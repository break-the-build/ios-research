/*
 * mac_fuzz_harness.c — libFuzzer/ASan in-process harness for macOS system
 * frameworks.
 *
 * Build one binary per framework/entry point with tools/harness/build.sh, then
 * run it under the `mac:<framework>` target (src/ios_research/targets/mac.py).
 * The Python target invokes `./<framework>_fuzzer <input-file>`, which runs the
 * single input through LLVMFuzzerTestOneInput and lets ASan/UBSan report any
 * real crash on stderr — no iOS device required.
 *
 * Authorized / own-machine research only. This harness only feeds bytes to a
 * decode entry point in a framework already installed on the machine; it does
 * not bypass permissions or access device sensors. See SECURITY.md.
 *
 * The entry point is selected at build time via -DHARNESS_TARGET_<NAME>:
 *   -DHARNESS_TARGET_IMAGEIO        ImageIO / CGImageSourceCreateWithData
 *   -DHARNESS_TARGET_AUDIOTOOLBOX   AudioToolbox / AudioFileOpenWithCallbacks
 *   -DHARNESS_TARGET_COREGRAPHICS   CoreGraphics / CGDataProviderCreateWithData
 *
 * Two build modes (selected by build.sh):
 *   default            -DHARNESS_STANDALONE + -fsanitize=address,undefined.
 *                      A built-in main() reads one or more input files and
 *                      drives them through LLVMFuzzerTestOneInput. This mode
 *                      works on the STOCK APPLE TOOLCHAIN (Apple clang ships
 *                      ASan/UBSan but NOT the libFuzzer runtime).
 *   --libfuzzer        -fsanitize=fuzzer,address,undefined (no HARNESS_STANDALONE).
 *                      libFuzzer supplies main(); requires an LLVM/clang that
 *                      ships libclang_rt.fuzzer_osx.a (e.g. `brew install llvm`).
 *
 * The standalone driver speaks a tiny stdout protocol so the Python target can
 * recover per-input outcome and attribute a crash within a batch:
 *   "RUN <i>\n"                 emitted (and flushed) before input i is run
 *   "DONE <i> decoded\n"        input i decoded to an object (ACCEPTED)
 *   "DONE <i> rejected\n"       the entry point rejected input i (REJECTED)
 * A crash aborts the process after its "RUN <i>" with no matching "DONE",
 * pinpointing the offending input; the ASan report goes to stderr as usual.
 *
 * We dlopen the framework and dlsym the entry point so the harness builds
 * without private framework headers and tolerates symbol availability across
 * OS builds.
 */

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal CoreFoundation typedefs so we avoid pulling framework headers. */
typedef const void *CFTypeRef;
typedef const struct __CFAllocator *CFAllocatorRef;
typedef const struct __CFData *CFDataRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef signed long CFIndex;

static void *cf_handle = NULL;
static void *fw_handle = NULL;

/* CoreFoundation function pointers, resolved once. */
static CFDataRef (*p_CFDataCreate)(CFAllocatorRef, const uint8_t *, CFIndex) = NULL;
static void (*p_CFRelease)(CFTypeRef) = NULL;

static int resolve_common(void) {
    if (cf_handle) return 1;
    cf_handle = dlopen(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!cf_handle) {
        fprintf(stderr, "harness: cannot dlopen CoreFoundation: %s\n", dlerror());
        return 0;
    }
    p_CFDataCreate = dlsym(cf_handle, "CFDataCreate");
    p_CFRelease = dlsym(cf_handle, "CFRelease");
    if (!p_CFDataCreate || !p_CFRelease) {
        fprintf(stderr, "harness: missing CoreFoundation symbols\n");
        return 0;
    }
    return 1;
}

#if defined(HARNESS_TARGET_IMAGEIO)

typedef CFTypeRef CGImageSourceRef;
typedef CFTypeRef CGImageRef;
static CGImageSourceRef (*p_CGImageSourceCreateWithData)(CFDataRef, CFDictionaryRef) = NULL;
static CGImageRef (*p_CGImageSourceCreateImageAtIndex)(CGImageSourceRef, size_t, CFDictionaryRef) = NULL;

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    fw_handle = dlopen(
        "/System/Library/Frameworks/ImageIO.framework/ImageIO",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen ImageIO: %s\n", dlerror()); return 0; }
    p_CGImageSourceCreateWithData = dlsym(fw_handle, "CGImageSourceCreateWithData");
    p_CGImageSourceCreateImageAtIndex = dlsym(fw_handle, "CGImageSourceCreateImageAtIndex");
    return p_CGImageSourceCreateWithData && p_CGImageSourceCreateImageAtIndex;
}

/* Returns 1 if the input decoded to an image, 0 if the framework rejected it. */
static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    CGImageSourceRef src = p_CGImageSourceCreateWithData(cfdata, NULL);
    if (!src) return 0;
    CGImageRef img = p_CGImageSourceCreateImageAtIndex(src, 0, NULL);
    int decoded = img != NULL;
    if (img) p_CFRelease(img);
    p_CFRelease(src);
    return decoded;
}

#elif defined(HARNESS_TARGET_COREGRAPHICS)

typedef CFTypeRef CGDataProviderRef;
static CGDataProviderRef (*p_CGDataProviderCreateWithCFData)(CFDataRef) = NULL;
static void (*p_CGDataProviderRelease)(CGDataProviderRef) = NULL;

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    fw_handle = dlopen(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen CoreGraphics: %s\n", dlerror()); return 0; }
    p_CGDataProviderCreateWithCFData = dlsym(fw_handle, "CGDataProviderCreateWithCFData");
    p_CGDataProviderRelease = dlsym(fw_handle, "CGDataProviderRelease");
    return p_CGDataProviderCreateWithCFData && p_CGDataProviderRelease;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    CGDataProviderRef prov = p_CGDataProviderCreateWithCFData(cfdata);
    if (!prov) return 0;
    p_CGDataProviderRelease(prov);
    return 1;
}

#elif defined(HARNESS_TARGET_AUDIOTOOLBOX)

/* AudioToolbox path: use AudioFileOpenWithCallbacks over an in-memory buffer.
 * Callback typedefs kept minimal; signatures match the public AudioToolbox API.
 */
typedef int32_t OSStatus;
typedef uint32_t UInt32;
typedef int64_t SInt64;
typedef CFTypeRef AudioFileID;

typedef OSStatus (*AudioFile_ReadProc)(void *, SInt64, UInt32, void *, UInt32 *);
typedef OSStatus (*AudioFile_WriteProc)(void *, SInt64, UInt32, const void *, UInt32 *);
typedef SInt64 (*AudioFile_GetSizeProc)(void *);
typedef OSStatus (*AudioFile_SetSizeProc)(void *, SInt64);

static OSStatus (*p_AudioFileOpenWithCallbacks)(
    void *, AudioFile_ReadProc, AudioFile_WriteProc,
    AudioFile_GetSizeProc, AudioFile_SetSizeProc, UInt32, AudioFileID *) = NULL;
static OSStatus (*p_AudioFileClose)(AudioFileID) = NULL;

typedef struct { const uint8_t *data; size_t size; } MemFile;

static OSStatus mem_read(void *ctx, SInt64 pos, UInt32 count,
                         void *buffer, UInt32 *actual) {
    MemFile *mf = (MemFile *)ctx;
    UInt32 n = 0;
    if ((size_t)pos < mf->size) {
        n = count;
        if ((size_t)pos + n > mf->size) n = (UInt32)(mf->size - (size_t)pos);
        for (UInt32 i = 0; i < n; i++) ((uint8_t *)buffer)[i] = mf->data[pos + i];
    }
    if (actual) *actual = n;
    return 0;
}
static SInt64 mem_size(void *ctx) { return (SInt64)((MemFile *)ctx)->size; }

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    fw_handle = dlopen(
        "/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen AudioToolbox: %s\n", dlerror()); return 0; }
    p_AudioFileOpenWithCallbacks = dlsym(fw_handle, "AudioFileOpenWithCallbacks");
    p_AudioFileClose = dlsym(fw_handle, "AudioFileClose");
    return p_AudioFileOpenWithCallbacks && p_AudioFileClose;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)cfdata;
    MemFile mf = { data, size };
    AudioFileID af = NULL;
    OSStatus st = p_AudioFileOpenWithCallbacks(&mf, mem_read, NULL,
                                               mem_size, NULL, 0, &af);
    if (st == 0 && af) { p_AudioFileClose(af); return 1; }
    return 0;
}

#elif defined(HARNESS_TARGET_SELFTEST)

/*
 * Self-test target: a tiny, intentionally-buggy in-process parser (NO framework
 * dlopen). It exists to VALIDATE the real-crash pipeline end-to-end — a real
 * ASan report flowing through parse -> dedup -> minimize -> reproduce — because
 * hardened system frameworks (ImageIO, ...) rarely crash in a short run.
 *
 * Safety: this only corrupts its own small heap buffer on a marker in the
 * input; it touches no framework, file, sensor, or external state. The three
 * markers below yield three distinct, reproducible ASan classifications; the
 * bug is keyed on a byte MARKER so ddmin can shrink a crashing input while
 * preserving the signature (the marker must survive minimization).
 *
 * It deliberately does NOT dlopen CoreFoundation, so it runs on any toolchain
 * (including the Command Line Tools clang) and needs no frameworks at all.
 */
static int resolve_target(void) { return 1; }

static int st_contains(const uint8_t *d, size_t n, const char *s) {
    size_t L = strlen(s);
    if (n < L) return 0;
    for (size_t i = 0; i + L <= n; i++) {
        if (memcmp(d + i, s, L) == 0) return 1;
    }
    return 0;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)cfdata;
    uint8_t *buf = (uint8_t *)malloc(16);
    if (!buf) return 0;
    memset(buf, 0, 16);
    if (st_contains(data, size, "OOB")) {
        volatile uint8_t x = buf[16 + (size & 0x3F)];  /* heap OOB read  */
        (void)x;
    } else if (st_contains(data, size, "WRT")) {
        buf[64] = 0x41;                                 /* heap OOB write */
    } else if (st_contains(data, size, "UAF")) {
        free(buf);
        volatile uint8_t y = buf[0];                    /* use-after-free */
        (void)y;
        buf = NULL;
    }
    if (buf) free(buf);
    return 1;
}

#else
#error "Define one of HARNESS_TARGET_IMAGEIO / _AUDIOTOOLBOX / _COREGRAPHICS / _SELFTEST"
#endif

static int g_ready = 0;
/* Decode status of the most recent LLVMFuzzerTestOneInput call:
 * 1 = the entry point produced an object, 0 = it rejected the input. */
int g_last_decoded = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    g_ready = resolve_target();
    if (!g_ready) {
        fprintf(stderr, "harness: failed to resolve target symbols\n");
        /* Non-zero exit here would be reported as an error by libFuzzer; make
         * the failure explicit so the Python target surfaces it as ABNORMAL. */
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    g_last_decoded = 0;
    if (!g_ready && !resolve_target()) return 0;
    /* CoreFoundation is optional (the self-test target needs no framework). */
    CFDataRef cfdata = p_CFDataCreate ? p_CFDataCreate(NULL, data, (CFIndex)size)
                                      : NULL;
    g_last_decoded = run_target(data, size, cfdata);
    if (cfdata && p_CFRelease) p_CFRelease(cfdata);
    return 0;
}

#ifdef HARNESS_STANDALONE
/*
 * Standalone driver: builds on the stock Apple toolchain (no libFuzzer runtime
 * required). Runs one or more input files through LLVMFuzzerTestOneInput and
 * emits the stdout protocol documented at the top of this file. Batching many
 * files into one process amortizes the dlopen + process-spawn cost.
 */
static int run_one_file(const char *path, int index) {
    printf("RUN %d\n", index);
    fflush(stdout);
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("DONE %d rejected\n", index);
        fflush(stdout);
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) n = 0;
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    size_t rd = buf ? fread(buf, 1, (size_t)n, f) : 0;
    fclose(f);
    LLVMFuzzerTestOneInput(buf, rd);  /* may abort here on a sanitizer finding */
    printf("DONE %d %s\n", index, g_last_decoded ? "decoded" : "rejected");
    fflush(stdout);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file> [<input-file> ...]\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        run_one_file(argv[i], i - 1);
    }
    return 0;
}
#endif /* HARNESS_STANDALONE */
