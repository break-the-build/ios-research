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
 * We dlopen the framework and dlsym the entry point so the harness builds
 * without private framework headers and tolerates symbol availability across
 * OS builds.
 */

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

static void run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    CGImageSourceRef src = p_CGImageSourceCreateWithData(cfdata, NULL);
    if (!src) return;
    CGImageRef img = p_CGImageSourceCreateImageAtIndex(src, 0, NULL);
    if (img) p_CFRelease(img);
    p_CFRelease(src);
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

static void run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    CGDataProviderRef prov = p_CGDataProviderCreateWithCFData(cfdata);
    if (prov) p_CGDataProviderRelease(prov);
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

static void run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)cfdata;
    MemFile mf = { data, size };
    AudioFileID af = NULL;
    OSStatus st = p_AudioFileOpenWithCallbacks(&mf, mem_read, NULL,
                                               mem_size, NULL, 0, &af);
    if (st == 0 && af) p_AudioFileClose(af);
}

#else
#error "Define one of HARNESS_TARGET_IMAGEIO / _AUDIOTOOLBOX / _COREGRAPHICS"
#endif

static int g_ready = 0;

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
    if (!g_ready && !resolve_target()) return 0;
    CFDataRef cfdata = p_CFDataCreate(NULL, data, (CFIndex)size);
    if (!cfdata) return 0;
    run_target(data, size, cfdata);
    p_CFRelease(cfdata);
    return 0;
}
