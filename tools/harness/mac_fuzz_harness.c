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
 *   -DHARNESS_TARGET_COREGRAPHICS   CoreGraphics / CGPDFDocumentCreateWithProvider
 *   -DHARNESS_TARGET_VIDEOTOOLBOX   VideoToolbox / VTDecompressionSessionCreate
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
#include <mach-o/dyld.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* SanitizerCoverage-compatible feature map for the standalone driver.  Guard
 * callbacks are installed by clang's trace-pc-guard instrumentation.  We only
 * record guards while LLVMFuzzerTestOneInput is executing, then write compact
 * numeric IDs to an explicitly supplied local file. */
#ifdef HARNESS_SANCOV
#define IOSR_MAX_SANCOV_GUARDS 65536u
static uint8_t g_sancov_seen[IOSR_MAX_SANCOV_GUARDS];
static uint32_t g_sancov_next_guard = 0;
static int g_sancov_active = 0;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *guard = start; guard < stop; guard++) *guard = ++g_sancov_next_guard;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t id = *guard;
    if (g_sancov_active && id > 0 && id < IOSR_MAX_SANCOV_GUARDS) {
        g_sancov_seen[id] = 1;
    }
}

static void sancov_reset(void) { memset(g_sancov_seen, 0, sizeof(g_sancov_seen)); }

static void sancov_write_map(void) {
    const char *path = getenv("IOS_RESEARCH_SANCOV_FILE");
    if (!path || !*path) return;
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "IOSR_SANCOV_V1\n");
    for (uint32_t i = 1; i < IOSR_MAX_SANCOV_GUARDS; i++) {
        if (g_sancov_seen[i]) fprintf(f, "%u\n", i);
    }
    fclose(f);
}
#endif

/* Minimal CoreFoundation typedefs so we avoid pulling framework headers. */
typedef const void *CFTypeRef;
typedef const struct __CFAllocator *CFAllocatorRef;
typedef const struct __CFData *CFDataRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef signed long CFIndex;

/* Small structs that Apple APIs take and return BY VALUE. Declaring such a
 * parameter as a pointer is an ABI bug, not a style choice: on arm64 a CGRect
 * (four doubles) travels in d0-d3 and a CFRange in two integer registers, so a
 * pointer shifts every later argument. Both bugs shipped here once and made the
 * ImageIO pixel decode and the CoreText frame layout silent no-ops
 * (tests/test_mac_harness_abi.py now guards every by-value parameter). */
typedef struct { double x, y, w, h; } IOSR_CGRect;
typedef struct { CFIndex loc, len; } IOSR_CFRange;

/* Optional per-input depth metric printed on the DONE line ("pixels=123"),
 * proving that the deep stage of an entry point actually ran. */
static const char *g_depth_name = NULL;
static long g_depth_value = 0;

/* Count non-zero bytes so a pixel metric proves something was really drawn
 * (ImageIO and CoreText; unused by the other targets). */
__attribute__((unused))
static long count_nonzero(const uint8_t *p, size_t n) {
    long c = 0;
    for (size_t i = 0; i < n; i++) c += p[i] != 0;
    return c;
}

/* Uninitialized-memory oracle (tools/mac_campaign/uninit.py). With
 * IOSR_DIGEST=1 the driver prints "DIGEST <i> <hex>", an FNV-1a hash of every
 * output pixel buffer. A framework that copies uninitialized heap into its
 * output gives different digests with and without MALLOC_FILL_SPACE (which
 * fills each new allocation with 0x55), and the same digest run to run.
 * IOSR_UNINIT_CANARY=1 is the positive control: output buffers are malloc'd,
 * not calloc'd, with one extra row the framework never writes, so every input
 * must show up as a hit. */
static uint64_t g_digest = 0;
static int g_digested = 0;

__attribute__((unused))
static void digest_fold(const uint8_t *p, size_t n) {
    uint64_t h = g_digested ? g_digest : 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ULL;
    g_digest = h;
    g_digested = 1;
}

__attribute__((unused))
static int uninit_canary(void) {
    const char *v = getenv("IOSR_UNINIT_CANARY");
    return v && strcmp(v, "1") == 0;
}

/* An output buffer of `rows` rows of `row_bytes`: zeroed, or (canary) left
 * uninitialized with one extra row. *alloc_bytes is what to digest. */
__attribute__((unused))
static uint8_t *output_buffer(size_t rows, size_t row_bytes, size_t *alloc_bytes) {
    if (uninit_canary()) {
        *alloc_bytes = (rows + 1) * row_bytes;
        return malloc(*alloc_bytes);
    }
    *alloc_bytes = rows * row_bytes;
    return calloc(rows, row_bytes);
}

static void *cf_handle = NULL;
static void *fw_handle = NULL;

/* CoreFoundation function pointers, resolved once. */
static CFDataRef (*p_CFDataCreate)(CFAllocatorRef, const uint8_t *, CFIndex) = NULL;
static CFDataRef (*p_CFDataCreateWithBytesNoCopy)(CFAllocatorRef, const uint8_t *, CFIndex,
                                                  CFAllocatorRef) = NULL;
static CFAllocatorRef p_kCFAllocatorNull = NULL;
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
    /* Canary only (optional): kCFAllocatorNull is an exported global holding
     * the allocator, so dlsym yields its address -- deref it. */
    p_CFDataCreateWithBytesNoCopy = dlsym(cf_handle, "CFDataCreateWithBytesNoCopy");
    const CFAllocatorRef *null_alloc = dlsym(cf_handle, "kCFAllocatorNull");
    p_kCFAllocatorNull = null_alloc ? *null_alloc : NULL;
    return 1;
}

/* ---- detection canary (IOSR_CANARY=1) --------------------------------------
 * A positive control for the whole detection chain: Guard Malloc, the crash
 * reporter, and the Python side's parsing and classification. Instead of the
 * input, the framework is handed a view of IOSR_CANARY_KEEP +
 * IOSR_CANARY_REACH bytes of which only IOSR_CANARY_KEEP (the input's first
 * bytes) are a live heap block; the rest is the guard page Guard Malloc keeps
 * beside it. The framework's OWN read into that page must fault and be
 * reported exactly like a real out-of-bounds read. Without Guard Malloc no
 * guard page borders the block, so the harness refuses to run the framework
 * (mode=unguarded) and the check fails: a dead oracle must never look like "no
 * bugs". ios_research.targets.canary requires the fault to land in the printed
 * range, inside the framework. */
#define IOSR_CANARY_KEEP 16       /* Guard Malloc's alignment: the block ends flush with its page */
#define IOSR_CANARY_REACH 4096    /* view bytes past the block, all within one guard page */

typedef struct {
    uint8_t *block;           /* the live allocation */
    const uint8_t *view;      /* what the framework is told it may read */
    size_t len;
    uintptr_t lo, hi;         /* the guarded bytes the view covers */
} IOSR_Canary;

static int canary_requested(void) {
    const char *v = getenv("IOSR_CANARY");
    return v && strcmp(v, "1") == 0;
}

/* Placement alone can't prove Guard Malloc is there: the system allocator also
 * hands out the odd small block at a page start (a macOS 15 CI runner did, and
 * the canary read it as mode=before). */
static int gmalloc_loaded(void) {
    for (uint32_t i = 0, n = _dyld_image_count(); i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "/libgmalloc")) return 1;
    }
    return 0;
}

/* Guard Malloc's placement tells which side the guard page is on: a block that
 * ends on a page boundary (default, MALLOC_STRICT_SIZE) has it after, one that
 * starts on a boundary (MALLOC_PROTECT_BEFORE) has it before. Returns the mode,
 * or NULL when Guard Malloc isn't loaded or no guard page borders the block. */
__attribute__((unused))
static const char *canary_open(IOSR_Canary *c, const uint8_t *data, size_t size) {
    if (!gmalloc_loaded()) return NULL;
    uintptr_t page = (uintptr_t)sysconf(_SC_PAGESIZE);
    c->block = calloc(1, IOSR_CANARY_KEEP);
    if (!c->block) return NULL;
    memcpy(c->block, data, size < IOSR_CANARY_KEEP ? size : IOSR_CANARY_KEEP);
    uintptr_t b = (uintptr_t)c->block;
    c->len = IOSR_CANARY_KEEP + IOSR_CANARY_REACH;
    if ((b + IOSR_CANARY_KEEP) % page == 0) {
        c->view = c->block;
        c->lo = b + IOSR_CANARY_KEEP;
        c->hi = c->lo + IOSR_CANARY_REACH;
        return "after";
    }
    if (b % page == 0) {
        c->view = (const uint8_t *)(b - IOSR_CANARY_KEEP);
        c->lo = b - IOSR_CANARY_KEEP;
        c->hi = b;
        return "before";
    }
    return NULL;
}

/* The canary view as CFData WITHOUT a copy: CFDataCreate would read the guard
 * page itself, in CoreFoundation on the harness's behalf, not in the framework. */
__attribute__((unused))
static CFDataRef canary_cfdata(const uint8_t *view, size_t len) {
    if (!p_CFDataCreateWithBytesNoCopy || !p_kCFAllocatorNull) return NULL;
    return p_CFDataCreateWithBytesNoCopy(NULL, view, (CFIndex)len, p_kCFAllocatorNull);
}

#if defined(HARNESS_TARGET_IMAGEIO)

/* Deep decode (#228): create EVERY frame of the source, then render each
 * into an offscreen bitmap — forcing full pixel decode (color management,
 * codec tile paths) rather than header-only opens. */
typedef CFTypeRef CGImageSourceRef;
typedef CFTypeRef CGImageRef;
typedef CFTypeRef CGContextRef;
typedef CFTypeRef CGColorSpaceRef;
static CGImageSourceRef (*p_CGImageSourceCreateWithData)(CFDataRef, CFDictionaryRef) = NULL;
static CGImageRef (*p_CGImageSourceCreateImageAtIndex)(CGImageSourceRef, size_t, CFDictionaryRef) = NULL;
static size_t (*p_CGImageSourceGetCount)(CGImageSourceRef) = NULL;
static size_t (*p_CGImageGetWidth)(CGImageRef) = NULL;
static size_t (*p_CGImageGetHeight)(CGImageRef) = NULL;
static CGContextRef (*p_CGBitmapContextCreate)(void *, size_t, size_t, size_t, size_t, CGColorSpaceRef, uint32_t) = NULL;
static CGColorSpaceRef (*p_CGColorSpaceCreateDeviceRGB)(void) = NULL;
static void (*p_CGColorSpaceRelease)(CGColorSpaceRef) = NULL;
static void (*p_CGContextDrawImage)(CGContextRef, IOSR_CGRect, CGImageRef) = NULL;
static void (*p_CGContextRelease)(CGContextRef) = NULL;

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    fw_handle = dlopen(
        "/System/Library/Frameworks/ImageIO.framework/ImageIO",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen ImageIO: %s\n", dlerror()); return 0; }
    void *cg = dlopen(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!cg) { fprintf(stderr, "harness: dlopen CoreGraphics: %s\n", dlerror()); return 0; }
    p_CGImageSourceCreateWithData = dlsym(fw_handle, "CGImageSourceCreateWithData");
    p_CGImageSourceCreateImageAtIndex = dlsym(fw_handle, "CGImageSourceCreateImageAtIndex");
    p_CGImageSourceGetCount = dlsym(fw_handle, "CGImageSourceGetCount");
    p_CGImageGetWidth = dlsym(cg, "CGImageGetWidth");
    p_CGImageGetHeight = dlsym(cg, "CGImageGetHeight");
    p_CGBitmapContextCreate = dlsym(cg, "CGBitmapContextCreate");
    p_CGColorSpaceCreateDeviceRGB = dlsym(cg, "CGColorSpaceCreateDeviceRGB");
    p_CGColorSpaceRelease = dlsym(cg, "CGColorSpaceRelease");
    p_CGContextDrawImage = dlsym(cg, "CGContextDrawImage");
    p_CGContextRelease = dlsym(cg, "CGContextRelease");
    return p_CGImageSourceCreateWithData && p_CGImageSourceCreateImageAtIndex
        && p_CGImageSourceGetCount && p_CGImageGetWidth && p_CGImageGetHeight
        && p_CGBitmapContextCreate && p_CGColorSpaceCreateDeviceRGB
        && p_CGColorSpaceRelease && p_CGContextDrawImage && p_CGContextRelease;
}

#define IOSR_IMGIO_MAX_DIM 512u  /* bound decode memory */

/* PNG chunk CRCs. ImageIO rejects a PNG whose IHDR CRC does not match
 * (measured: one flipped IHDR width bit -> rejected; the same file with its CRC
 * recomputed -> decoded), and blind mutation practically never repairs a CRC,
 * so every mutated header -- width, height, bit depth, color type, interlace --
 * was turned away at the door. Every complete chunk's CRC is recomputed before
 * decoding. IOSR_PNG_CRC_FIXUP=0 turns this off; IOSR_SAVE_INPUT=<path> writes
 * the bytes ImageIO actually received (the file to attach to a report). */
static const uint8_t kPNGSignature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};

static uint32_t iosr_crc32(const uint8_t *p, size_t n) {
    static uint32_t table[256];
    if (!table[1]) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

static uint32_t png_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Rewrite the CRC of every complete chunk; returns how many changed. A chunk
 * whose length runs past the end is left alone (and ends the walk). */
static int png_fix_crcs(uint8_t *buf, size_t size) {
    int changed = 0;
    size_t pos = sizeof kPNGSignature;
    while (pos + 12 <= size) {
        uint32_t len = png_be32(buf + pos);
        if (len > size - pos - 12) break;
        uint32_t crc = iosr_crc32(buf + pos + 4, (size_t)len + 4);   /* type + data */
        uint8_t *at = buf + pos + 8 + len;
        if (png_be32(at) != crc) {
            at[0] = (uint8_t)(crc >> 24); at[1] = (uint8_t)(crc >> 16);
            at[2] = (uint8_t)(crc >> 8);  at[3] = (uint8_t)crc;
            changed++;
        }
        pos += 12 + (size_t)len;
    }
    return changed;
}

/* A CRC-repaired copy of a PNG input, or NULL if it isn't a PNG, the fix-up is
 * off, or every CRC already matched. */
static uint8_t *png_repaired_copy(const uint8_t *data, size_t size) {
    const char *opt = getenv("IOSR_PNG_CRC_FIXUP");
    if ((opt && strcmp(opt, "0") == 0) || size < sizeof kPNGSignature
        || memcmp(data, kPNGSignature, sizeof kPNGSignature) != 0)
        return NULL;
    uint8_t *copy = malloc(size);
    if (!copy) return NULL;
    memcpy(copy, data, size);
    if (png_fix_crcs(copy, size)) return copy;
    free(copy);
    return NULL;
}

static void save_input(const uint8_t *p, size_t n) {
    const char *path = getenv("IOSR_SAVE_INPUT");
    if (!path || !*path) return;
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "harness: cannot write IOSR_SAVE_INPUT=%s\n", path); return; }
    fwrite(p, 1, n, f);
    fclose(f);
}

static int decode_all_frames(CFDataRef input);

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    g_depth_name = "pixels";
    CFDataRef input = cfdata;
    uint8_t *repaired = png_repaired_copy(data, size);
    if (repaired) {
        input = p_CFDataCreate(NULL, repaired, (CFIndex)size);
        if (!input) { free(repaired); repaired = NULL; input = cfdata; }
    }
    save_input(repaired ? repaired : data, size);
    int decoded = decode_all_frames(input);
    if (input != cfdata) p_CFRelease(input);
    free(repaired);
    return decoded;
}

static int decode_all_frames(CFDataRef input) {
    CGImageSourceRef src = p_CGImageSourceCreateWithData(input, NULL);
    if (!src) return 0;
    int decoded = 0;
    size_t frames = p_CGImageSourceGetCount(src);
    if (frames > 16) frames = 16;   /* bound multi-frame work */
    for (size_t i = 0; i < frames; i++) {
        CGImageRef img = p_CGImageSourceCreateImageAtIndex(src, i, NULL);
        if (!img) continue;
        size_t w = p_CGImageGetWidth(img), h = p_CGImageGetHeight(img);
        if (w > IOSR_IMGIO_MAX_DIM) w = IOSR_IMGIO_MAX_DIM;
        if (h > IOSR_IMGIO_MAX_DIM) h = IOSR_IMGIO_MAX_DIM;
        if (w && h) {
            CGColorSpaceRef cs = p_CGColorSpaceCreateDeviceRGB();
            size_t bytes = 0;
            uint8_t *pixels = output_buffer(h, w * 4, &bytes);
            if (cs && pixels) {
                CGContextRef ctx = p_CGBitmapContextCreate(
                    pixels, w, h, 8, w * 4, cs, 2 /* premul first */);
                if (ctx) {
                    IOSR_CGRect rect = {0, 0, (double)w, (double)h};
                    p_CGContextDrawImage(ctx, rect, img);   /* full pixel decode */
                    p_CGContextRelease(ctx);
                    g_depth_value += count_nonzero(pixels, w * h * 4);
                    digest_fold(pixels, bytes);
                    decoded = 1;
                }
            }
            free(pixels);
            if (cs) p_CGColorSpaceRelease(cs);
        }
        p_CFRelease(img);
    }
    p_CFRelease(src);
    return decoded;
}

/* Canary: straight to ImageIO (the PNG repair and IOSR_SAVE_INPUT would read
 * the guard page in harness code). */
#define IOSR_HAVE_CANARY 1
static int run_canary_view(const uint8_t *view, size_t len) {
    CFDataRef input = canary_cfdata(view, len);
    if (!input) return 0;
    int decoded = decode_all_frames(input);
    p_CFRelease(input);
    return decoded;
}

#elif defined(HARNESS_TARGET_COREGRAPHICS)

/* CoreGraphics path (#27, deepened #228/#234): drive a real PDF decode/render
 * pipeline instead of merely wrapping bytes. CGDataProviderCreateWithCFData
 * only wraps a buffer and never parses, so we open a CGPDFDocument over the
 * provider — the full PDF parser — then:
 *   1. render EVERY page (bounded) into an offscreen bitmap context, forcing
 *      full content-stream interpretation (text advances, color conversion,
 *      XObject recursion — the op_Tj family that produced FINDING-05);
 *   2. sweep each page's content stream with a CGPDFScanner whose operator
 *      table registers the standard operator set. The scanner tokenizes
 *      operands and dispatches per-operator even when rendering bails early,
 *      and our callback drains scalar operands (numbers/names) to exercise
 *      the operand-conversion paths directly.
 * Malformed inputs are rejected by the parser (meaningful REJECTED signal);
 * malformed ones that survive exercise real decode code under ASan/UBSan. */
typedef CFTypeRef CGDataProviderRef;
typedef CFTypeRef CGPDFDocumentRef;
typedef CFTypeRef CGPDFPageRef;
typedef CFTypeRef CGContextRef;
typedef CFTypeRef CGColorSpaceRef;
typedef CFTypeRef CGPDFOperatorTableRef;
typedef CFTypeRef CGPDFContentStreamRef;
typedef CFTypeRef CGPDFScannerRef;

static CGDataProviderRef (*p_CGDataProviderCreateWithCFData)(CFDataRef) = NULL;
static void (*p_CGDataProviderRelease)(CGDataProviderRef) = NULL;
static CGPDFDocumentRef (*p_CGPDFDocumentCreateWithProvider)(CGDataProviderRef) = NULL;
static void (*p_CGPDFDocumentRelease)(CGPDFDocumentRef) = NULL;
static size_t (*p_CGPDFDocumentGetNumberOfPages)(CGPDFDocumentRef) = NULL;
static CGPDFPageRef (*p_CGPDFDocumentGetPage)(CGPDFDocumentRef, size_t) = NULL;
static CGContextRef (*p_CGBitmapContextCreate)(void *, size_t, size_t,
                                               size_t, size_t, CGColorSpaceRef,
                                               uint32_t) = NULL;
static void (*p_CGContextRelease)(CGContextRef) = NULL;
static void (*p_CGContextDrawPDFPage)(CGContextRef, CGPDFPageRef) = NULL;
static CGColorSpaceRef (*p_CGColorSpaceCreateDeviceRGB)(void) = NULL;
static void (*p_CGColorSpaceRelease)(CGColorSpaceRef) = NULL;

/* PDF content-stream scanner (#234 operator coverage). */
static void (*p_CGPDFOperatorTableRelease)(CGPDFOperatorTableRef) = NULL;
static CGPDFOperatorTableRef (*p_CGPDFOperatorTableCreate)(void) = NULL;
static void (*p_CGPDFOperatorTableSetCallback)(CGPDFOperatorTableRef,
                                               const char *,
                                               void (*)(CGPDFScannerRef,
                                                        void *)) = NULL;
static CGPDFContentStreamRef (*p_CGPDFContentStreamCreateWithPage)(
    CGPDFPageRef) = NULL;
static void (*p_CGPDFContentStreamRelease)(CGPDFContentStreamRef) = NULL;
static CGPDFScannerRef (*p_CGPDFScannerCreate)(CGPDFContentStreamRef,
                                               CGPDFOperatorTableRef,
                                               void *) = NULL;
static unsigned char (*p_CGPDFScannerScan)(CGPDFScannerRef) = NULL;   /* bool */
static void (*p_CGPDFScannerRelease)(CGPDFScannerRef) = NULL;
/* Operand pops are optional: numbers/names carry no ownership burden. */
static unsigned char (*p_CGPDFScannerPopNumber)(CGPDFScannerRef, double *) = NULL;
static unsigned char (*p_CGPDFScannerPopName)(CGPDFScannerRef, const char **) = NULL;

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    fw_handle = dlopen(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen CoreGraphics: %s\n", dlerror()); return 0; }
    p_CGDataProviderCreateWithCFData = dlsym(fw_handle, "CGDataProviderCreateWithCFData");
    p_CGDataProviderRelease = dlsym(fw_handle, "CGDataProviderRelease");
    p_CGPDFDocumentCreateWithProvider = dlsym(fw_handle, "CGPDFDocumentCreateWithProvider");
    p_CGPDFDocumentRelease = dlsym(fw_handle, "CGPDFDocumentRelease");
    p_CGPDFDocumentGetNumberOfPages = dlsym(fw_handle, "CGPDFDocumentGetNumberOfPages");
    p_CGPDFDocumentGetPage = dlsym(fw_handle, "CGPDFDocumentGetPage");
    p_CGBitmapContextCreate = dlsym(fw_handle, "CGBitmapContextCreate");
    p_CGContextRelease = dlsym(fw_handle, "CGContextRelease");
    p_CGContextDrawPDFPage = dlsym(fw_handle, "CGContextDrawPDFPage");
    p_CGColorSpaceCreateDeviceRGB = dlsym(fw_handle, "CGColorSpaceCreateDeviceRGB");
    p_CGColorSpaceRelease = dlsym(fw_handle, "CGColorSpaceRelease");
    /* Scanner leg is optional — degrade to render-only when absent. */
    p_CGPDFOperatorTableCreate = dlsym(fw_handle, "CGPDFOperatorTableCreate");
    p_CGPDFOperatorTableSetCallback = dlsym(fw_handle, "CGPDFOperatorTableSetCallback");
    p_CGPDFOperatorTableRelease = dlsym(fw_handle, "CGPDFOperatorTableRelease");
    p_CGPDFContentStreamCreateWithPage = dlsym(fw_handle, "CGPDFContentStreamCreateWithPage");
    p_CGPDFContentStreamRelease = dlsym(fw_handle, "CGPDFContentStreamRelease");
    p_CGPDFScannerCreate = dlsym(fw_handle, "CGPDFScannerCreate");
    p_CGPDFScannerScan = dlsym(fw_handle, "CGPDFScannerScan");
    p_CGPDFScannerRelease = dlsym(fw_handle, "CGPDFScannerRelease");
    p_CGPDFScannerPopNumber = dlsym(fw_handle, "CGPDFScannerPopNumber");
    p_CGPDFScannerPopName = dlsym(fw_handle, "CGPDFScannerPopName");
    return p_CGDataProviderCreateWithCFData && p_CGDataProviderRelease
        && p_CGPDFDocumentCreateWithProvider && p_CGPDFDocumentRelease
        && p_CGPDFDocumentGetNumberOfPages && p_CGPDFDocumentGetPage
        && p_CGBitmapContextCreate && p_CGContextRelease
        && p_CGContextDrawPDFPage && p_CGColorSpaceCreateDeviceRGB
        && p_CGColorSpaceRelease;
}

#define IOSR_CG_BITMAP_ALPHA 2  /* kCGImageAlphaPremultipliedFirst */
#define IOSR_CG_MAX_PAGES 16u   /* bound per-input render work */
#define IOSR_CG_MAX_POPS 64u    /* scalar operands drained per callback */

/* Operator-hit counter (scanner callbacks fire on a parse thread of one). */
static volatile int g_pdf_op_hits = 0;

/* Drain scalar operands: exercises the numeric/name conversion paths for
 * every operator's operand stack. Bounded so pathological streams cannot
 * spin the callback. */
static void iosr_pdf_op_cb(CGPDFScannerRef scanner, void *info) {
    (void)info;
    g_pdf_op_hits++;
    if (!p_CGPDFScannerPopNumber && !p_CGPDFScannerPopName) return;
    double num;
    const char *name;
    for (uint32_t i = 0; i < IOSR_CG_MAX_POPS; i++) {
        int got_num = p_CGPDFScannerPopNumber
            && p_CGPDFScannerPopNumber(scanner, &num);
        int got_name = p_CGPDFScannerPopName
            && p_CGPDFScannerPopName(scanner, &name);
        if (!got_num && !got_name) break;
    }
}

static CGPDFOperatorTableRef g_pdf_op_table = NULL;

static void iosr_pdf_install_op_table(void) {
    static const char *const ops[] = {
        /* text */ "BT", "ET", "Td", "TD", "Tm", "T*", "TL", "Tc", "Tw",
        "Tz", "Ts", "Tf", "Tr", "Tj", "TJ", "'", "\"",
        /* graphics state + paths */ "q", "Q", "cm", "w", "W", "W*",
        "m", "l", "c", "v", "y", "h", "re", "n", "S", "s", "f", "f*", "F",
        "B", "B*", "b", "b*", "bA", "BA", "i", "gs", "M", "ri",
        /* color */ "cs", "CS", "sc", "scn", "SC", "SCN", "g", "G",
        "rg", "RG", "k", "K",
        /* xobject/image */ "Do", "BI", "ID", "EI",
        /* shading/annotations */ "sh", "MP", "DP", "BMC", "BDC", "EMC",
        /* compatibility */ "BX", "EX",
    };
    if (!p_CGPDFOperatorTableCreate || !p_CGPDFOperatorTableSetCallback)
        return;
    g_pdf_op_table = p_CGPDFOperatorTableCreate();
    if (!g_pdf_op_table) return;
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        p_CGPDFOperatorTableSetCallback(g_pdf_op_table, ops[i],
                                        iosr_pdf_op_cb);
    }
}

/* Scan one page's content stream through the operator table. Returns 1 when
 * any operator callback fired. */
static int iosr_pdf_sweep_page(CGPDFPageRef page) {
    if (!g_pdf_op_table || !p_CGPDFContentStreamCreateWithPage
        || !p_CGPDFScannerCreate || !p_CGPDFScannerScan
        || !p_CGPDFScannerRelease || !p_CGPDFContentStreamRelease)
        return 0;
    CGPDFContentStreamRef cs = p_CGPDFContentStreamCreateWithPage(page);
    if (!cs) return 0;
    int before = g_pdf_op_hits;
    CGPDFScannerRef sc = p_CGPDFScannerCreate(cs, g_pdf_op_table, NULL);
    if (sc) {
        p_CGPDFScannerScan(sc);   /* best-effort; malformed streams just stop */
        p_CGPDFScannerRelease(sc);
    }
    p_CGPDFContentStreamRelease(cs);
    return g_pdf_op_hits > before;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)data; (void)size;
    if (!g_pdf_op_table) iosr_pdf_install_op_table();
    CGDataProviderRef prov = p_CGDataProviderCreateWithCFData(cfdata);
    if (!prov) return 0;
    int decoded = 0;
    CGPDFDocumentRef doc = p_CGPDFDocumentCreateWithProvider(prov);
    if (doc) {
        size_t npages = p_CGPDFDocumentGetNumberOfPages(doc);
        size_t cap = npages < IOSR_CG_MAX_PAGES ? npages : IOSR_CG_MAX_PAGES;
        for (size_t pno = 1; pno <= cap; pno++) {
            CGPDFPageRef page = p_CGPDFDocumentGetPage(doc, pno);
            if (!page) continue;
            /* Small offscreen RGBA bitmap; row bytes = width * 4. */
            CGContextRef ctx = p_CGBitmapContextCreate(
                NULL, 64, 64, 8, 64 * 4,
                p_CGColorSpaceCreateDeviceRGB(), IOSR_CG_BITMAP_ALPHA);
            if (ctx) {
                p_CGContextDrawPDFPage(ctx, page);  /* forces full decode */
                p_CGContextRelease(ctx);
                decoded = 1;
            }
            if (iosr_pdf_sweep_page(page)) decoded = 1;
        }
        p_CGPDFDocumentRelease(doc);
    }
    p_CGDataProviderRelease(prov);
    return decoded;
}

#define IOSR_HAVE_CANARY 1
static int run_canary_view(const uint8_t *view, size_t len) {
    CFDataRef input = canary_cfdata(view, len);
    if (!input) return 0;
    int decoded = run_target(NULL, 0, input);   /* reads only the CFData */
    p_CFRelease(input);
    return decoded;
}

#elif defined(HARNESS_TARGET_AUDIOTOOLBOX)

/* Deep decode (#228): open -> query format -> read packets (drives the
 * demuxer AND codec packetization) -> AudioConverter to PCM16 (drives the
 * decoder pipeline), not merely open+close. */
typedef int32_t OSStatus;
typedef uint8_t UInt8;
typedef uint32_t UInt32;
typedef int64_t SInt64;
typedef uint32_t FourCharCode;
typedef CFTypeRef AudioFileID;

typedef OSStatus (*AudioFile_ReadProc)(void *, SInt64, UInt32, void *, UInt32 *);
typedef OSStatus (*AudioFile_WriteProc)(void *, SInt64, UInt32, const void *, UInt32 *);
typedef SInt64 (*AudioFile_GetSizeProc)(void *);
typedef OSStatus (*AudioFile_SetSizeProc)(void *, SInt64);

/* AudioStreamBasicDescription, naturally aligned like the SDK header. */
typedef struct {
    double mSampleRate;
    FourCharCode mFormatID;
    UInt32 mFormatFlags;
    UInt32 mBytesPerPacket;
    UInt32 mFramesPerPacket;
    UInt32 mBytesPerFrame;
    UInt32 mChannelsPerFrame;
    UInt32 mBitsPerChannel;
    UInt32 mReserved;
} IOSR_ASBD;

static OSStatus (*p_AudioFileOpenWithCallbacks)(
    void *, AudioFile_ReadProc, AudioFile_WriteProc,
    AudioFile_GetSizeProc, AudioFile_SetSizeProc, UInt32, AudioFileID *) = NULL;
static OSStatus (*p_AudioFileClose)(AudioFileID) = NULL;
static OSStatus (*p_AudioFileGetProperty)(AudioFileID, FourCharCode,
                                          UInt32 *, void *) = NULL;
/* CoreAudio base types use NATURAL alignment (CoreAudioBaseTypes.h has no
 * #pragma pack): AudioBufferList.mBuffers starts at offset 8. A 4-packed copy
 * put it at 4, which AudioToolbox rejects in
 * CrashIfClientProvidedBogusAudioBufferList (and broke the old PCM path). */
typedef struct { SInt64 mStartOffset; UInt32 mVariableFramesInPacket; UInt32 mDataByteSize; } IOSR_ASPD;
typedef struct { UInt32 mNumberChannels; UInt32 mDataByteSize; void *mData; } IOSR_AudioBuffer;
typedef struct { UInt32 mNumberBuffers; IOSR_AudioBuffer mBuffers[1]; } IOSR_ABL;

/* AudioConverterComplexInputDataProc */
typedef OSStatus (*IOSR_ACInputProc)(void *, UInt32 *, IOSR_ABL *, IOSR_ASPD **, void *);

/* AudioFileReadPacketData(file, inUseCache, ioNumBytes, outPacketDescriptions,
 * inStartingPacket, ioNumPackets, outBuffer). ioNumPackets is a POINTER: it was
 * once declared by value, which handed AudioToolbox the buffer size as an
 * address and made every valid file read as "rejected". */
static OSStatus (*p_AudioFileReadPacketData)(AudioFileID, int, UInt32 *, IOSR_ASPD *,
                                             SInt64, UInt32 *, void *) = NULL;
static OSStatus (*p_AudioConverterNew)(const IOSR_ASBD *, const IOSR_ASBD *, void **) = NULL;
static void (*p_AudioConverterDispose)(void *) = NULL;
static OSStatus (*p_AudioConverterSetProperty)(void *, UInt32, UInt32, const void *) = NULL;
/* FillComplexBuffer decodes compressed formats (AAC, ALAC, MP3, ...); the
 * previously used ConvertComplexBuffer is PCM-to-PCM only, so no codec ran. */
static OSStatus (*p_AudioConverterFillComplexBuffer)(void *, IOSR_ACInputProc, void *,
                                                     UInt32 *, IOSR_ABL *, IOSR_ASPD *) = NULL;

/* Canary only: the fuzz path feeds AudioToolbox through mem_read (harness code
 * copies the bytes), so the canary uses the stream parser, which reads the
 * caller's buffer itself. */
typedef CFTypeRef AudioFileStreamID;
typedef void (*IOSR_AFSPropertyProc)(void *, AudioFileStreamID, UInt32, UInt32 *);
typedef void (*IOSR_AFSPacketsProc)(void *, UInt32, UInt32, const void *, IOSR_ASPD *);
static OSStatus (*p_AudioFileStreamOpen)(void *, IOSR_AFSPropertyProc, IOSR_AFSPacketsProc,
                                         UInt32, AudioFileStreamID *) = NULL;
static OSStatus (*p_AudioFileStreamParseBytes)(AudioFileStreamID, UInt32, const void *,
                                               UInt32) = NULL;
static OSStatus (*p_AudioFileStreamClose)(AudioFileStreamID) = NULL;

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
    p_AudioFileGetProperty = dlsym(fw_handle, "AudioFileGetProperty");
    p_AudioFileReadPacketData = dlsym(fw_handle, "AudioFileReadPacketData");
    p_AudioConverterNew = dlsym(fw_handle, "AudioConverterNew");
    p_AudioConverterDispose = dlsym(fw_handle, "AudioConverterDispose");
    p_AudioConverterSetProperty = dlsym(fw_handle, "AudioConverterSetProperty");
    p_AudioConverterFillComplexBuffer = dlsym(fw_handle, "AudioConverterFillComplexBuffer");
    p_AudioFileStreamOpen = dlsym(fw_handle, "AudioFileStreamOpen");          /* canary */
    p_AudioFileStreamParseBytes = dlsym(fw_handle, "AudioFileStreamParseBytes");
    p_AudioFileStreamClose = dlsym(fw_handle, "AudioFileStreamClose");
    return p_AudioFileOpenWithCallbacks && p_AudioFileClose
        && p_AudioFileGetProperty && p_AudioFileReadPacketData
        && p_AudioConverterNew && p_AudioConverterDispose
        && p_AudioConverterSetProperty && p_AudioConverterFillComplexBuffer;
}

/* Property IDs exactly as in the SDK's AudioFile.h / AudioConverter.h. The
 * format ID was once 'asbd' -- not a property at all ('pty?' error) -- so the
 * harness never read a format and stopped after the container header. */
#define IOSR_AT_PROP_FORMAT 0x64666d74UL  /* 'dfmt' kAudioFilePropertyDataFormat */
#define IOSR_AT_PROP_COOKIE 0x6d676963UL  /* 'mgic' kAudioFilePropertyMagicCookieData */
#define IOSR_AC_PROP_COOKIE 0x646d6763UL  /* 'dmgc' kAudioConverterDecompressionMagicCookie */
#define IOSR_AT_MAX_PACKETS 64u
#define IOSR_AT_BUF_BYTES (64u * 1024u)
#define IOSR_AT_COOKIE_MAX 4096u
#define IOSR_AT_MAX_FILLS 64              /* bound decode work per input */

/* Feeds the packets read from the file to the converter exactly once. */
typedef struct {
    uint8_t *data;
    UInt32 bytes, packets, channels;
    IOSR_ASPD *descs;
    int consumed;
} PacketFeed;

static OSStatus feed_packets(void *conv, UInt32 *io_packets, IOSR_ABL *io_data,
                             IOSR_ASPD **out_descs, void *user) {
    (void)conv;
    PacketFeed *f = (PacketFeed *)user;
    io_data->mNumberBuffers = 1;
    if (f->consumed) {                 /* no more input: end of stream */
        *io_packets = 0;
        io_data->mBuffers[0].mDataByteSize = 0;
        io_data->mBuffers[0].mData = NULL;
        return 0;
    }
    f->consumed = 1;
    *io_packets = f->packets;
    io_data->mBuffers[0].mNumberChannels = f->channels;
    io_data->mBuffers[0].mDataByteSize = f->bytes;
    io_data->mBuffers[0].mData = f->data;
    if (out_descs) *out_descs = f->descs;   /* VBR codecs need per-packet sizes */
    return 0;
}

/* Decode the packets to 16-bit stereo PCM through the real codec pipeline. */
static void decode_packets(AudioFileID af, const IOSR_ASBD *src, uint8_t *pkts,
                           UInt32 nbytes, UInt32 npackets, IOSR_ASPD *descs) {
    IOSR_ASBD dst = *src;
    dst.mSampleRate = 44100.0;
    dst.mFormatID = 0x6c70636dUL;      /* 'lpcm' */
    dst.mFormatFlags = 0x0000000cUL;   /* signed | packed */
    dst.mBytesPerPacket = 4;
    dst.mFramesPerPacket = 1;
    dst.mBytesPerFrame = 4;
    dst.mChannelsPerFrame = 2;
    dst.mBitsPerChannel = 16;
    dst.mReserved = 0;
    void *conv = NULL;
    if (p_AudioConverterNew(src, &dst, &conv) != 0 || !conv) return;
    /* AAC/ALAC/... decoders are configured by the file's magic cookie, itself
     * parsed by the decoder (e.g. an MPEG-4 ESDS) -- attack surface too. */
    static uint8_t cookie[IOSR_AT_COOKIE_MAX];
    UInt32 csz = sizeof(cookie);
    if (p_AudioFileGetProperty(af, IOSR_AT_PROP_COOKIE, &csz, cookie) == 0 && csz > 0)
        p_AudioConverterSetProperty(conv, IOSR_AC_PROP_COOKIE, csz, cookie);
    PacketFeed feed = { pkts, nbytes, npackets, src->mChannelsPerFrame, descs, 0 };
    static uint8_t pcm[IOSR_AT_BUF_BYTES];
    for (int i = 0; i < IOSR_AT_MAX_FILLS; i++) {
        IOSR_ABL out;
        out.mNumberBuffers = 1;
        out.mBuffers[0].mNumberChannels = 2;
        out.mBuffers[0].mDataByteSize = IOSR_AT_BUF_BYTES;
        out.mBuffers[0].mData = pcm;
        UInt32 frames = IOSR_AT_BUF_BYTES / dst.mBytesPerFrame;
        OSStatus st = p_AudioConverterFillComplexBuffer(conv, feed_packets, &feed,
                                                        &frames, &out, NULL);
        g_depth_value += (long)frames;
        if (st != 0 || frames == 0) break;
    }
    p_AudioConverterDispose(conv);
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)cfdata;
    g_depth_name = "frames";
    MemFile mf = { data, size };
    AudioFileID af = NULL;
    OSStatus st = p_AudioFileOpenWithCallbacks(&mf, mem_read, NULL,
                                               mem_size, NULL, 0, &af);
    if (st != 0 || !af) return 0;

    int exercised = 0;
    IOSR_ASBD src_fmt;
    UInt32 sz = sizeof(src_fmt);
    if (p_AudioFileGetProperty(af, IOSR_AT_PROP_FORMAT, &sz, &src_fmt) == 0) {
        /* Read packets through the demuxer (with descriptions for VBR). */
        static uint8_t pktbuf[IOSR_AT_BUF_BYTES];
        static IOSR_ASPD descs[IOSR_AT_MAX_PACKETS];
        UInt32 nbytes = IOSR_AT_BUF_BYTES, npackets = IOSR_AT_MAX_PACKETS;
        p_AudioFileReadPacketData(af, 0 /* !cache */, &nbytes, descs, 0, &npackets, pktbuf);
        if (npackets > 0 && npackets <= IOSR_AT_MAX_PACKETS && nbytes <= IOSR_AT_BUF_BYTES) {
            exercised = 1;     /* a short read at end-of-file still yields packets */
            decode_packets(af, &src_fmt, pktbuf, nbytes, npackets, descs);
        }
    }
    p_AudioFileClose(af);
    return exercised;
}

static void afs_property(void *user, AudioFileStreamID s, UInt32 id, UInt32 *flags) {
    (void)user; (void)s; (void)id; (void)flags;
}
static void afs_packets(void *user, UInt32 nbytes, UInt32 npackets, const void *d,
                        IOSR_ASPD *descs) {
    (void)user; (void)nbytes; (void)npackets; (void)d; (void)descs;
}

#define IOSR_HAVE_CANARY 1
static int run_canary_view(const uint8_t *view, size_t len) {
    if (!p_AudioFileStreamOpen || !p_AudioFileStreamParseBytes || !p_AudioFileStreamClose)
        return 0;
    AudioFileStreamID s = NULL;
    if (p_AudioFileStreamOpen(NULL, afs_property, afs_packets, 0, &s) != 0 || !s) return 0;
    OSStatus st = p_AudioFileStreamParseBytes(s, (UInt32)len, view, 0);
    p_AudioFileStreamClose(s);
    return st == 0;
}

#elif defined(HARNESS_TARGET_VIDEOTOOLBOX)

/* VideoToolbox decompression-session path (#234): drive the real video decode
 * pipeline — CMVideoFormatDescription construction from embedded parameter
 * sets (SPS/PPS/VPS parsing) -> VTDecompressionSessionCreate -> DecodeFrame
 * (decoder selection + NAL repacketization) -> async drain — not merely a
 * container parse. Container handling is deliberately codec-frame-first: the
 * fuzzer controls raw parameter sets and access-unit NAL boundaries directly
 * instead of routing through an MP4 demuxer (ByteParser is its own follow-up
 * target).
 *
 * Input layout (all integers big-endian):
 *   byte 0        flags; bit0 selects the codec (0 = H.264, 1 = HEVC)
 *   records...    repeated: u32 length L, then min(L, remaining) payload bytes
 *                 H.264 needs >= 3 records: [SPS, PPS, frame]
 *                 HEVC  needs >= 4 records: [VPS, SPS, PPS, frame]
 *   The frame record is itself a sequence of u32-length-prefixed sub-NALs,
 *   re-emitted as one AVCC/HVCC-style buffer with canonical 4-byte prefixes
 *   (malformed sub-lengths are clamped, keeping boundary math in fuzz space).
 * Every iteration fully tears down the session (drain -> invalidate -> release)
 * so libFuzzer runs cannot leak decoder sessions or wedge the media daemon. */
typedef int32_t OSStatus;

typedef CFTypeRef CMBlockBufferRef;
typedef CFTypeRef CMSampleBufferRef;
typedef CFTypeRef CMFormatDescriptionRef;
typedef CFTypeRef VTDecompressionSessionRef;
typedef CFTypeRef CVImageBufferRef;

/* CMTime / CMSampleTimingInfo layouts (public ABI; no headers available). */
typedef struct {
    int64_t value;
    uint32_t timescale;
    uint32_t flags;
    int64_t epoch;
} IOSR_CMTIME;

typedef struct {
    IOSR_CMTIME duration;
    IOSR_CMTIME presentationTimeStamp;
    IOSR_CMTIME decodeTimeStamp;
} IOSR_CMSAMPLE_TIMING_INFO;

#define IOSR_CM_TIME_VALID 1u

/* The callback fires on a session thread during the drain below; a plain
 * counter increment is sufficient (best-effort liveness signal only). */
static volatile int g_vt_frames_decoded = 0;

static void iosr_vt_output_cb(void *refCon, void *sourceFrameRefCon,
                              OSStatus status, uint32_t infoFlags,
                              CVImageBufferRef imageBuffer, IOSR_CMTIME pts,
                              IOSR_CMTIME dur) {
    (void)refCon; (void)sourceFrameRefCon; (void)infoFlags; (void)pts; (void)dur;
    if (status == 0 && imageBuffer) g_vt_frames_decoded++;
}

typedef struct {
    void (*decompressionOutputCallback)(void *, void *, OSStatus, uint32_t,
                                        CVImageBufferRef, IOSR_CMTIME,
                                        IOSR_CMTIME);
    void *decompressionOutputRefCon;
} IOSR_VT_CALLBACK_RECORD;

/* parameterSetCount is size_t: a uint32_t leaves the upper half of the
 * register unspecified on arm64, so the callee could read a garbage count. */
static OSStatus (*p_CMVideoFormatDescriptionCreateFromH264ParameterSets)(
    CFAllocatorRef, size_t, const uint8_t * const *, const size_t *,
    int, CMFormatDescriptionRef *) = NULL;
static OSStatus (*p_CMVideoFormatDescriptionCreateFromHEVCParameterSets)(
    CFAllocatorRef, size_t, const uint8_t * const *, const size_t *,
    int, CFDictionaryRef, CMFormatDescriptionRef *) = NULL;
static OSStatus (*p_CMBlockBufferCreateWithMemoryBlock)(
    CFAllocatorRef, void *, size_t, CFAllocatorRef, void *, size_t, size_t,
    uint32_t, CMBlockBufferRef *) = NULL;
/* CMSampleBufferCreateReady: (allocator, dataBuffer, formatDescription,
 * numSamples, numSampleTimingEntries, sampleTimingArray,
 * numSampleSizeEntries, sampleSizeArray, sampleBufferOut) — 9 args; the
 * size-entries count is easy to omit and then the framework reads its
 * out-pointer from garbage (observed as a wild WRITE in
 * figSampleBufferCreateCallbackOrHandler). */
static OSStatus (*p_CMSampleBufferCreateReady)(
    CFAllocatorRef, CMBlockBufferRef, CMFormatDescriptionRef, long, long,
    const IOSR_CMSAMPLE_TIMING_INFO *, long, const size_t *,
    CMSampleBufferRef *) = NULL;
static OSStatus (*p_VTDecompressionSessionCreate)(
    CFAllocatorRef, CMFormatDescriptionRef, CFTypeRef, CFDictionaryRef,
    const IOSR_VT_CALLBACK_RECORD *, VTDecompressionSessionRef *) = NULL;
/* VTDecompressionSessionDecodeFrame: (session, sampleBuffer, decodeFlags,
 * sourceFrameRefCon, infoFlagsOut) — 5 args. */
static OSStatus (*p_VTDecompressionSessionDecodeFrame)(
    VTDecompressionSessionRef, CMSampleBufferRef, uint32_t, void *,
    uint32_t *) = NULL;
static OSStatus (*p_VTDecompressionSessionWaitForAsynchronousFrames)(
    VTDecompressionSessionRef) = NULL;
static void (*p_VTDecompressionSessionInvalidate)(VTDecompressionSessionRef) = NULL;

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    void *cm = dlopen(
        "/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!cm) { fprintf(stderr, "harness: dlopen CoreMedia: %s\n", dlerror()); return 0; }
    fw_handle = dlopen(
        "/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen VideoToolbox: %s\n", dlerror()); return 0; }
    p_CMVideoFormatDescriptionCreateFromH264ParameterSets =
        dlsym(cm, "CMVideoFormatDescriptionCreateFromH264ParameterSets");
    p_CMVideoFormatDescriptionCreateFromHEVCParameterSets =
        dlsym(cm, "CMVideoFormatDescriptionCreateFromHEVCParameterSets");
    p_CMBlockBufferCreateWithMemoryBlock =
        dlsym(cm, "CMBlockBufferCreateWithMemoryBlock");
    p_CMSampleBufferCreateReady = dlsym(cm, "CMSampleBufferCreateReady");
    p_VTDecompressionSessionCreate = dlsym(fw_handle, "VTDecompressionSessionCreate");
    p_VTDecompressionSessionDecodeFrame =
        dlsym(fw_handle, "VTDecompressionSessionDecodeFrame");
    p_VTDecompressionSessionWaitForAsynchronousFrames =
        dlsym(fw_handle, "VTDecompressionSessionWaitForAsynchronousFrames");
    p_VTDecompressionSessionInvalidate =
        dlsym(fw_handle, "VTDecompressionSessionInvalidate");
    return p_CMVideoFormatDescriptionCreateFromH264ParameterSets
        && p_CMVideoFormatDescriptionCreateFromHEVCParameterSets
        && p_CMBlockBufferCreateWithMemoryBlock && p_CMSampleBufferCreateReady
        && p_VTDecompressionSessionCreate && p_VTDecompressionSessionDecodeFrame
        && p_VTDecompressionSessionWaitForAsynchronousFrames
        && p_VTDecompressionSessionInvalidate;
}

#define IOSR_VT_MAX_RECORDS 16u
#define IOSR_VT_MAX_RECORD_BYTES (256u * 1024u)
#define IOSR_VT_MAX_SUBNALS 64u
#define IOSR_VT_MAX_FRAME (256u * 1024u)

static uint32_t vt_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Read one u32-length-prefixed record at *pos; malformed lengths are clamped
 * to the bytes actually present (truncation stays inside the parse). */
static int vt_next_record(const uint8_t *data, size_t size, size_t *pos,
                          const uint8_t **out, uint32_t *outlen) {
    if (*pos > size || size - *pos < 4) return 0;
    uint32_t len = vt_be32(data + *pos);
    *pos += 4;
    uint32_t avail = (uint32_t)(size - *pos);
    uint32_t take = len > avail ? avail : len;
    if (take > IOSR_VT_MAX_RECORD_BYTES) take = IOSR_VT_MAX_RECORD_BYTES;
    *out = data + *pos;
    *outlen = take;
    *pos += take;
    return 1;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)cfdata;
    if (!size) return 0;
    uint32_t hevc = data[0] & 1u;
    size_t pos = 1;
    const uint8_t *rec[IOSR_VT_MAX_RECORDS];
    uint32_t reclen[IOSR_VT_MAX_RECORDS];
    uint32_t nrec = 0;
    while (nrec < IOSR_VT_MAX_RECORDS && pos < size) {
        if (!vt_next_record(data, size, &pos, &rec[nrec], &reclen[nrec])) break;
        nrec++;
    }
    uint32_t nparams = hevc ? 3u : 2u;   /* H264: SPS+PPS; HEVC: VPS+SPS+PPS */
    if (nrec < nparams + 1u) return 0;

    /* Rebuild the frame record as one AVCC/HVCC buffer with canonical 4-byte
     * NAL length prefixes. Static buffer: too large for the ASan stack. */
    static uint8_t framebuf[IOSR_VT_MAX_FRAME];
    const uint8_t *fr = rec[nparams];
    uint32_t frlen = reclen[nparams];
    size_t fpos = 0, ftot = 0;
    uint32_t subnals = 0;
    while (fpos + 4 <= frlen && subnals < IOSR_VT_MAX_SUBNALS) {
        uint32_t nl = vt_be32(fr + fpos);
        fpos += 4;
        if (nl > frlen - fpos) nl = frlen - fpos;
        if (ftot + 4 + (size_t)nl > IOSR_VT_MAX_FRAME) break;
        framebuf[ftot++] = (uint8_t)(nl >> 24);
        framebuf[ftot++] = (uint8_t)(nl >> 16);
        framebuf[ftot++] = (uint8_t)(nl >> 8);
        framebuf[ftot++] = (uint8_t)nl;
        if (nl) memcpy(framebuf + ftot, fr + fpos, nl);
        ftot += nl;
        fpos += nl;
        subnals++;
    }
    if (!subnals || !ftot) return 0;

    /* Format description from parameter sets: exercises the SPS/PPS/VPS
     * parsers on every input, even when session creation later fails. */
    const uint8_t *psp[3];
    size_t pss[3];
    for (uint32_t i = 0; i < nparams; i++) { psp[i] = rec[i]; pss[i] = reclen[i]; }
    CMFormatDescriptionRef desc = NULL;
    OSStatus st = hevc
        ? p_CMVideoFormatDescriptionCreateFromHEVCParameterSets(
              NULL, nparams, psp, pss, 4, NULL, &desc)
        : p_CMVideoFormatDescriptionCreateFromH264ParameterSets(
              NULL, nparams, psp, pss, 4, &desc);
    if (st != 0 || !desc) return 0;

    /* Session owns decoding; install our output callback and drain before
     * teardown so asynchronous frames cannot outlive the input buffers. */
    IOSR_VT_CALLBACK_RECORD cbrec = { iosr_vt_output_cb, NULL };
    VTDecompressionSessionRef sess = NULL;
    st = p_VTDecompressionSessionCreate(NULL, desc, NULL, NULL, &cbrec, &sess);
    if (st != 0 || !sess) { p_CFRelease(desc); return 0; }

    uint8_t *copy = (uint8_t *)malloc(ftot);
    CMBlockBufferRef bb = NULL;
    CMSampleBufferRef sb = NULL;
    IOSR_CMSAMPLE_TIMING_INFO timing;
    memset(&timing, 0, sizeof(timing));
    timing.duration.value = 1;
    timing.duration.timescale = 600;
    timing.duration.flags = IOSR_CM_TIME_VALID;
    timing.presentationTimeStamp.timescale = 600;
    timing.presentationTimeStamp.flags = IOSR_CM_TIME_VALID;
    timing.decodeTimeStamp = timing.presentationTimeStamp;
    size_t fsize = ftot;
    if (copy) memcpy(copy, framebuf, ftot);
    /* customBlockSource==NULL: the block buffer OWNS `copy` and frees it at
     * CFRelease — we must never free() it ourselves (double-free aborts in
     * libmalloc's xzone introspection, observed on macOS 26.5). */
    OSStatus bb_err = copy
        ? p_CMBlockBufferCreateWithMemoryBlock(NULL, copy, ftot, NULL, NULL,
                                               0, ftot, 0, &bb)
        : -1;
    if (bb_err != 0 || !bb
             || p_CMSampleBufferCreateReady(NULL, bb, desc, 1, 1, &timing,
                                            1, &fsize, &sb) != 0 || !sb) {
        if (sb) p_CFRelease(sb);
        if (bb) p_CFRelease(bb);   /* frees owned `copy` */
        else free(copy);           /* never handed off */
        p_VTDecompressionSessionInvalidate(sess);
        p_CFRelease(sess);
        p_CFRelease(desc);
        return 0;
    }

    g_vt_frames_decoded = 0;
    st = p_VTDecompressionSessionDecodeFrame(sess, sb, 0 /* sync */, NULL,
                                             NULL);
    p_VTDecompressionSessionWaitForAsynchronousFrames(sess);
    int exercised = (st == 0) || g_vt_frames_decoded > 0;
    p_VTDecompressionSessionInvalidate(sess);

    p_CFRelease(sb);
    p_CFRelease(bb);   /* frees owned `copy` */
    p_CFRelease(sess);
    p_CFRelease(desc);
    return exercised;
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

#elif defined(HARNESS_TARGET_CORETEXT)

/* CoreText path: parse untrusted font data. CTFontManagerCreateFontDescriptorsFromData
 * forces full sfnt table parsing (head/maxp/cmap/...); we then map characters to
 * glyphs and extract an outline path, shape text through the layout engine, and
 * RASTERIZE: a sample of glyphs plus a line of the font's own characters are
 * drawn into a bitmap, at the default instance and at each variation extreme.
 * Outlines alone never reach bitmap strikes (sbix/bdat), color glyphs
 * (COLR/CPAL, SVG) or variable-font instancing. The depth metric is the number
 * of inked bytes. Fonts are a classic untrusted-input surface shared by iOS/macOS. */
typedef CFTypeRef CTFontDescriptorRef;
typedef CFTypeRef CTFontRef;
typedef CFTypeRef CFArrayRef;
typedef CFTypeRef CGPathRef;
typedef CFTypeRef CGMutablePathRef;
typedef CFTypeRef CTFramesetterRef;
typedef CFTypeRef CTFrameRef;
/* CGAffineTransform fields are CGFloat (double on arm64) — a float struct
 * would be read past by the framework (48-byte ABI, 24-byte object). */
typedef struct { double a, b, c, d, tx, ty; } IOSR_CGAffineTransform;

static CFArrayRef (*p_CTFontManagerCreateFontDescriptorsFromData)(CFDataRef) = NULL;
static CTFontRef (*p_CTFontCreateWithFontDescriptor)(CTFontDescriptorRef,
                                                     double, void *) = NULL;
static unsigned char (*p_CTFontGetGlyphsForCharacters)(CTFontRef, const uint16_t *,
                                                       uint16_t *, CFIndex) = NULL;  /* bool */
static CGPathRef (*p_CTFontCreatePathForGlyph)(CTFontRef, uint16_t,
                                               const IOSR_CGAffineTransform *) = NULL;
static CFIndex (*p_CFArrayGetCount)(CFArrayRef) = NULL;
static CFTypeRef (*p_CFArrayGetValueAtIndex)(CFArrayRef, CFIndex) = NULL;
static void (*p_CGPathRelease)(CGPathRef) = NULL;
typedef CFTypeRef CFMutableDictionaryRef;
typedef CFTypeRef CFAttributedStringRef;
typedef CFTypeRef CTLineRef;
typedef const struct __CFString *CFStringRef;
static CFAttributedStringRef (*p_CFAttributedStringCreate)(void *, CFStringRef, CFDictionaryRef) = NULL;
static CTLineRef (*p_CTLineCreateWithAttributedString)(CFTypeRef) = NULL;
static CTFramesetterRef (*p_CTFramesetterCreateWithAttributedString)(
    CFAttributedStringRef) = NULL;
/* CTFramesetterCreateFrame takes FOUR args (framesetter, stringRange, path,
 * frameAttributes), and stringRange is a CFRange BY VALUE. As a pointer it
 * shifted path into the range and NULL into path: the frame was never laid out. */
static CTFrameRef (*p_CTFramesetterCreateFrame)(CTFramesetterRef,
                                                IOSR_CFRange,
                                                CGPathRef, void *) = NULL;
static CGMutablePathRef (*p_CGPathCreateMutable)(void) = NULL;
static void (*p_CGPathAddRect)(CGMutablePathRef, const IOSR_CGAffineTransform *,
                               IOSR_CGRect) = NULL;
/* CFDictionaryCreateMutable takes FOUR args (allocator, capacity,
 * keyCallbacks, valueCallbacks); use the real kCFType callback structs
 * resolved by dlsym instead of letting the framework read them from garbage
 * (observed as an objc BUS inside TAttributes::ApplyFont during shaping). */
static CFMutableDictionaryRef (*p_CFDictionaryCreateMutable)(
    void *, long, const void *, const void *) = NULL;
static void (*p_CFDictionarySetValue)(CFMutableDictionaryRef, const void *, const void *) = NULL;static CFStringRef (*p_CFStringCreateWithCString)(void *, const char *, unsigned int) = NULL;
static CFStringRef p_kCTFontAttributeName = NULL;
static const void *p_kCFTypeDictionaryKeyCallBacks = NULL;
static const void *p_kCFTypeDictionaryValueCallBacks = NULL;

/* Rasterization. CGPoint is two CGFloats (doubles); CTFontDrawGlyphs takes an
 * ARRAY of them (a pointer is right there), CGContextSetTextPosition takes x
 * and y by value in d0/d1. Boolean-returning calls are declared unsigned char:
 * only the low byte of w0 is defined. */
typedef CFTypeRef CGContextRef;
typedef CFTypeRef CGColorSpaceRef;
typedef CFTypeRef CFNumberRef;
typedef struct { double x, y; } IOSR_CGPoint;
static CFIndex (*p_CTFontGetGlyphCount)(CTFontRef) = NULL;
static void (*p_CTFontDrawGlyphs)(CTFontRef, const uint16_t *, const IOSR_CGPoint *,
                                  size_t, CGContextRef) = NULL;
static void (*p_CTLineDraw)(CTLineRef, CGContextRef) = NULL;
static void (*p_CGContextSetTextPosition)(CGContextRef, double, double) = NULL;
/* bool parameters: one byte, like the bool results above. */
static void (*p_CGContextSetShouldAntialias)(CGContextRef, unsigned char) = NULL;
static void (*p_CGContextSetShouldSmoothFonts)(CGContextRef, unsigned char) = NULL;
static CGContextRef (*p_CGBitmapContextCreate)(void *, size_t, size_t, size_t, size_t,
                                               CGColorSpaceRef, uint32_t) = NULL;
static CGColorSpaceRef (*p_CGColorSpaceCreateDeviceRGB)(void) = NULL;
static void (*p_CGColorSpaceRelease)(CGColorSpaceRef) = NULL;
static void (*p_CGContextRelease)(CGContextRef) = NULL;
static CFStringRef (*p_CFStringCreateWithCharacters)(void *, const uint16_t *, CFIndex) = NULL;
/* Variable-font instancing. */
static CFArrayRef (*p_CTFontCopyVariationAxes)(CTFontRef) = NULL;
static const void *(*p_CFDictionaryGetValue)(CFDictionaryRef, const void *) = NULL;
static unsigned char (*p_CFNumberGetValue)(CFNumberRef, CFIndex, void *) = NULL;
static CTFontDescriptorRef (*p_CTFontDescriptorCreateCopyWithVariation)(
    CTFontDescriptorRef, CFNumberRef, double) = NULL;
static CFStringRef p_kCTFontVariationAxisIdentifierKey = NULL;
static CFStringRef p_kCTFontVariationAxisMinimumValueKey = NULL;
static CFStringRef p_kCTFontVariationAxisMaximumValueKey = NULL;

/* Shape an attributed line through the layout engine - drives feature-driven
 * glyph substitution (morx/GSUB) and cluster mapping, not merely outline
 * extraction (#228 deep decode) - and, given a canvas, draw it. Runs while
 * `font` is alive: the NULL-callback dictionary does not retain its value, and
 * CFAttributedStringCreate copies (retains) attributes into its own storage,
 * released below. */
static int shape_line(CTFontRef font, CFStringRef text, CGContextRef canvas) {
    if (!p_CFAttributedStringCreate || !p_CTLineCreateWithAttributedString
        || !p_CFDictionaryCreateMutable || !p_CFDictionarySetValue
        || !p_kCTFontAttributeName
        || !p_kCFTypeDictionaryKeyCallBacks
        || !p_kCFTypeDictionaryValueCallBacks || !text)
        return 0;
    int shaped = 0;
    CFMutableDictionaryRef dict = p_CFDictionaryCreateMutable(
        NULL, 1, p_kCFTypeDictionaryKeyCallBacks,
        p_kCFTypeDictionaryValueCallBacks);
    if (dict) {
        p_CFDictionarySetValue(dict, p_kCTFontAttributeName,
                               (const void *)font);
        CFAttributedStringRef as = p_CFAttributedStringCreate(NULL, text, dict);
        if (as) {
            CTLineRef line = p_CTLineCreateWithAttributedString(as);
            if (line) {
                if (canvas) {
                    p_CGContextSetTextPosition(canvas, 4.0, 4.0);
                    p_CTLineDraw(line, canvas);
                }
                p_CFRelease(line);
                shaped = 1;
            }
            /* Full typesetting (#228 §2): framesetter lays the string into a
             * frame path — line-breaking, alignment, per-line glyph runs over
             * the parsed font, not merely descriptor parse. */
            if (p_CTFramesetterCreateWithAttributedString
                && p_CTFramesetterCreateFrame && p_CGPathCreateMutable
                && p_CGPathAddRect && p_CGPathRelease) {
                CTFramesetterRef fs =
                    p_CTFramesetterCreateWithAttributedString(as);
                if (fs) {
                    CGMutablePathRef path = p_CGPathCreateMutable();
                    if (path) {
                        IOSR_CGRect bounds = {0, 0, 200, 200};
                        p_CGPathAddRect(path, NULL, bounds);
                        IOSR_CFRange all = {0, 0};   /* whole string */
                        CTFrameRef frame =
                            p_CTFramesetterCreateFrame(fs, all, path, NULL);
                        if (frame) {
                            p_CFRelease(frame);
                            shaped = 1;
                        }
                        p_CGPathRelease(path);
                    }
                    p_CFRelease(fs);
                }
            }
            p_CFRelease(as);
        }
        p_CFRelease(dict);
    }
    return shaped;
}

#define IOSR_CT_CANVAS 256u        /* px square; glyphs sit in 32 px cells */
#define IOSR_CT_CELL 32u
#define IOSR_CT_GRID (IOSR_CT_CANVAS / IOSR_CT_CELL)
#define IOSR_CT_MAX_GLYPHS 64u     /* bound per-instance raster work */
#define IOSR_CT_DRAW_SIZE 24.0     /* pt: large enough to pick real bitmap strikes */
#define IOSR_CT_MAX_AXES 16
#define IOSR_CT_MAX_TEXT 48
#define IOSR_CT_PER_SCRIPT 8
#define IOSR_CF_NUMBER_DOUBLE 13   /* kCFNumberDoubleType */

typedef struct { uint8_t *px; CGContextRef ctx; size_t bytes; } IOSR_Canvas;

static int canvas_open(IOSR_Canvas *c) {
    c->ctx = NULL;
    c->px = output_buffer(IOSR_CT_CANVAS, (size_t)IOSR_CT_CANVAS * 4, &c->bytes);
    CGColorSpaceRef cs = p_CGColorSpaceCreateDeviceRGB();
    if (c->px && cs)
        c->ctx = p_CGBitmapContextCreate(c->px, IOSR_CT_CANVAS, IOSR_CT_CANVAS, 8,
                                         IOSR_CT_CANVAS * 4, cs, 2 /* premul first */);
    if (cs) p_CGColorSpaceRelease(cs);
    if (!c->ctx) { free(c->px); c->px = NULL; }
    return c->ctx != NULL;
}

/* Release the canvas; returns how many bytes were inked. */
static long canvas_close(IOSR_Canvas *c) {
    if (!c->ctx) return 0;
    p_CGContextRelease(c->ctx);
    long ink = count_nonzero(c->px, (size_t)IOSR_CT_CANVAS * IOSR_CT_CANVAS * 4);
    digest_fold(c->px, c->bytes);
    free(c->px);
    c->px = NULL;
    c->ctx = NULL;
    return ink;
}

/* Draw a deterministic sample of glyph IDs -- the first 32 and 32 more spread
 * across the rest -- whether or not cmap maps them, so every glyph format the
 * font carries is rasterized: glyf/CFF/CFF2 outlines, sbix and bdat bitmap
 * strikes, COLR/CPAL and SVG color glyphs. */
static void draw_glyph_grid(CTFontRef font, CGContextRef ctx) {
    CFIndex count = p_CTFontGetGlyphCount(font);
    if (count <= 0) return;
    if (count > 0xFFFF) count = 0xFFFF;               /* glyph IDs are 16-bit */
    uint16_t glyphs[IOSR_CT_MAX_GLYPHS];
    IOSR_CGPoint pos[IOSR_CT_MAX_GLYPHS];
    size_t n = 0, half = IOSR_CT_MAX_GLYPHS / 2;
    for (; n < half && (CFIndex)n < count; n++) glyphs[n] = (uint16_t)n;
    if (count > (CFIndex)IOSR_CT_MAX_GLYPHS) {
        for (size_t k = 0; k < half; k++)
            glyphs[n++] = (uint16_t)(half + k * (size_t)(count - (CFIndex)half) / half);
    } else {
        for (; (CFIndex)n < count; n++) glyphs[n] = (uint16_t)n;
    }
    for (size_t i = 0; i < n; i++) {
        pos[i].x = (double)((i % IOSR_CT_GRID) * IOSR_CT_CELL + 4);
        pos[i].y = (double)((i / IOSR_CT_GRID) * IOSR_CT_CELL + 6);
    }
    p_CTFontDrawGlyphs(font, glyphs, pos, n, ctx);
}

/* Up to 8 characters the font itself maps from each of several scripts whose
 * shaping is stateful (Arabic joining, Indic reordering, Hebrew bidi, Hangul,
 * Thai), plus Latin, symbols and presentation forms -- so layout runs the
 * font's OWN morx/GSUB/GPOS rules instead of falling back to another font. */
static const uint16_t kScriptRanges[][2] = {
    {0x0041, 0x007A}, {0x00C0, 0x017F}, {0x0391, 0x03C9}, {0x0410, 0x044F},
    {0x05D0, 0x05EA}, {0x0621, 0x064A}, {0x064B, 0x0652}, {0x0915, 0x0939},
    {0x093E, 0x094D}, {0x0E01, 0x0E3A}, {0x1100, 0x11FF}, {0x2190, 0x21FF},
    {0x2600, 0x27BF}, {0x3041, 0x30FF}, {0xAC00, 0xACFF}, {0xFB00, 0xFB4F},
};

static CFStringRef font_own_text(CTFontRef font) {
    uint16_t text[IOSR_CT_MAX_TEXT];
    CFIndex n = 0;
    size_t nranges = sizeof kScriptRanges / sizeof kScriptRanges[0];
    for (size_t r = 0; r < nranges && n < IOSR_CT_MAX_TEXT; r++) {
        uint16_t chars[256], glyphs[256];
        CFIndex cnt = 0, taken = 0;
        for (uint32_t ch = kScriptRanges[r][0]; ch <= kScriptRanges[r][1] && cnt < 256; ch++)
            chars[cnt++] = (uint16_t)ch;
        memset(glyphs, 0, sizeof glyphs);
        p_CTFontGetGlyphsForCharacters(font, chars, glyphs, cnt);   /* 0 = unmapped */
        for (CFIndex i = 0; i < cnt && taken < IOSR_CT_PER_SCRIPT && n < IOSR_CT_MAX_TEXT; i++)
            if (glyphs[i]) { text[n++] = chars[i]; taken++; }
    }
    return n ? p_CFStringCreateWithCharacters(NULL, text, n) : NULL;
}

/* A copy of `desc` with every variation axis (up to 16) set to the value under
 * `key` (the axis minimum or maximum), or NULL for a font without axes. */
static CTFontDescriptorRef instance_at(CTFontDescriptorRef desc, CFArrayRef axes,
                                       CFStringRef key) {
    CTFontDescriptorRef cur = NULL;
    CFIndex n = p_CFArrayGetCount(axes);
    if (n > IOSR_CT_MAX_AXES) n = IOSR_CT_MAX_AXES;
    for (CFIndex i = 0; i < n; i++) {
        CFDictionaryRef axis = (CFDictionaryRef)p_CFArrayGetValueAtIndex(axes, i);
        CFNumberRef id = axis ? p_CFDictionaryGetValue(axis, p_kCTFontVariationAxisIdentifierKey) : NULL;
        CFNumberRef v = axis ? p_CFDictionaryGetValue(axis, key) : NULL;
        double value = 0;
        if (!id || !v || !p_CFNumberGetValue(v, IOSR_CF_NUMBER_DOUBLE, &value)) continue;
        CTFontDescriptorRef next =
            p_CTFontDescriptorCreateCopyWithVariation(cur ? cur : desc, id, value);
        if (!next) continue;
        if (cur) p_CFRelease(cur);
        cur = next;
    }
    return cur;
}

/* Draw the glyph grid at the minimum and at the maximum of every axis:
 * instancing runs the gvar / CFF2 blend / HVAR / MVAR / avar delta math that
 * the default instance skips. Returns inked bytes. */
static long draw_variation_extremes(CTFontDescriptorRef desc, CTFontRef font) {
    if (!p_CTFontCopyVariationAxes || !p_CTFontDescriptorCreateCopyWithVariation
        || !p_CFDictionaryGetValue || !p_CFNumberGetValue
        || !p_kCTFontVariationAxisIdentifierKey || !p_kCTFontVariationAxisMinimumValueKey
        || !p_kCTFontVariationAxisMaximumValueKey)
        return 0;
    CFArrayRef axes = p_CTFontCopyVariationAxes(font);
    if (!axes) return 0;
    long ink = 0;
    CFStringRef keys[2] = {p_kCTFontVariationAxisMinimumValueKey,
                           p_kCTFontVariationAxisMaximumValueKey};
    for (int k = 0; k < 2; k++) {
        CTFontDescriptorRef inst = instance_at(desc, axes, keys[k]);
        if (!inst) continue;
        CTFontRef f = p_CTFontCreateWithFontDescriptor(inst, IOSR_CT_DRAW_SIZE, NULL);
        IOSR_Canvas c;
        if (f && canvas_open(&c)) {
            draw_glyph_grid(f, c.ctx);
            ink += canvas_close(&c);
        }
        if (f) p_CFRelease(f);
        p_CFRelease(inst);
    }
    p_CFRelease(axes);
    return ink;
}

/* The glyph grid again with antialiasing and font smoothing off. Only aliased
 * rendering runs the TrueType bytecode interpreter (fpgm, prep, glyph
 * programs): measured on Arial, 30 of 90 hinting edits changed the aliased
 * output and none changed the antialiased one. CVE-2023-41990 was in that
 * interpreter. */
static long draw_aliased(CTFontRef font) {
    if (!p_CGContextSetShouldAntialias || !p_CGContextSetShouldSmoothFonts) return 0;
    IOSR_Canvas c;
    if (!canvas_open(&c)) return 0;
    p_CGContextSetShouldAntialias(c.ctx, 0);
    p_CGContextSetShouldSmoothFonts(c.ctx, 0);
    draw_glyph_grid(font, c.ctx);
    return canvas_close(&c);
}

/* Rasterize the font: glyph grid plus a shaped line of its own characters at the
 * default instance, the grid again aliased (hinting), then the variation
 * extremes. Returns inked bytes. */
static long rasterize(CTFontDescriptorRef desc) {
    if (!p_CTFontGetGlyphCount || !p_CTFontDrawGlyphs || !p_CTLineDraw
        || !p_CGContextSetTextPosition || !p_CGBitmapContextCreate
        || !p_CGColorSpaceCreateDeviceRGB || !p_CGColorSpaceRelease
        || !p_CGContextRelease || !p_CFStringCreateWithCharacters)
        return 0;
    CTFontRef font = p_CTFontCreateWithFontDescriptor(desc, IOSR_CT_DRAW_SIZE, NULL);
    if (!font) return 0;
    long ink = 0;
    IOSR_Canvas c;
    if (canvas_open(&c)) {
        draw_glyph_grid(font, c.ctx);
        CFStringRef text = font_own_text(font);
        if (text) {
            shape_line(font, text, c.ctx);
            p_CFRelease(text);
        }
        ink += canvas_close(&c);
    }
    ink += draw_aliased(font);
    ink += draw_variation_extremes(desc, font);
    p_CFRelease(font);
    return ink;
}

static int resolve_target(void) {
    if (!resolve_common()) return 0;
    fw_handle = dlopen(
        "/System/Library/Frameworks/CoreText.framework/CoreText",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!fw_handle) { fprintf(stderr, "harness: dlopen CoreText: %s\n", dlerror()); return 0; }
    void *cg = dlopen(
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        RTLD_LAZY | RTLD_GLOBAL);
    if (!cg) { fprintf(stderr, "harness: dlopen CoreGraphics: %s\n", dlerror()); return 0; }
    p_CTFontManagerCreateFontDescriptorsFromData =
        dlsym(fw_handle, "CTFontManagerCreateFontDescriptorsFromData");
    p_CTFontCreateWithFontDescriptor =
        dlsym(fw_handle, "CTFontCreateWithFontDescriptor");
    p_CTFontGetGlyphsForCharacters =
        dlsym(fw_handle, "CTFontGetGlyphsForCharacters");
    p_CTFontCreatePathForGlyph = dlsym(fw_handle, "CTFontCreatePathForGlyph");
    p_CFArrayGetCount = dlsym(cf_handle, "CFArrayGetCount");
    p_CFArrayGetValueAtIndex = dlsym(cf_handle, "CFArrayGetValueAtIndex");
    p_CGPathRelease = dlsym(cg, "CGPathRelease");
    p_CGPathCreateMutable = dlsym(cg, "CGPathCreateMutable");
    p_CGPathAddRect = dlsym(cg, "CGPathAddRect");
    p_CFAttributedStringCreate = dlsym(cf_handle, "CFAttributedStringCreate");
    p_CTLineCreateWithAttributedString = dlsym(fw_handle, "CTLineCreateWithAttributedString");
    p_CTFramesetterCreateWithAttributedString = dlsym(
        fw_handle, "CTFramesetterCreateWithAttributedString");
    p_CTFramesetterCreateFrame = dlsym(fw_handle, "CTFramesetterCreateFrame");
    p_CTFontGetGlyphCount = dlsym(fw_handle, "CTFontGetGlyphCount");
    p_CTFontDrawGlyphs = dlsym(fw_handle, "CTFontDrawGlyphs");
    p_CTLineDraw = dlsym(fw_handle, "CTLineDraw");
    p_CGContextSetTextPosition = dlsym(cg, "CGContextSetTextPosition");
    p_CGContextSetShouldAntialias = dlsym(cg, "CGContextSetShouldAntialias");
    p_CGContextSetShouldSmoothFonts = dlsym(cg, "CGContextSetShouldSmoothFonts");
    p_CGBitmapContextCreate = dlsym(cg, "CGBitmapContextCreate");
    p_CGColorSpaceCreateDeviceRGB = dlsym(cg, "CGColorSpaceCreateDeviceRGB");
    p_CGColorSpaceRelease = dlsym(cg, "CGColorSpaceRelease");
    p_CGContextRelease = dlsym(cg, "CGContextRelease");
    p_CFStringCreateWithCharacters = dlsym(cf_handle, "CFStringCreateWithCharacters");
    p_CTFontCopyVariationAxes = dlsym(fw_handle, "CTFontCopyVariationAxes");
    p_CFDictionaryGetValue = dlsym(cf_handle, "CFDictionaryGetValue");
    p_CFNumberGetValue = dlsym(cf_handle, "CFNumberGetValue");
    p_CTFontDescriptorCreateCopyWithVariation =
        dlsym(fw_handle, "CTFontDescriptorCreateCopyWithVariation");
    /* Like kCTFontAttributeName below: exported globals holding CFStringRefs. */
    CFStringRef *axis_id = dlsym(fw_handle, "kCTFontVariationAxisIdentifierKey");
    CFStringRef *axis_min = dlsym(fw_handle, "kCTFontVariationAxisMinimumValueKey");
    CFStringRef *axis_max = dlsym(fw_handle, "kCTFontVariationAxisMaximumValueKey");
    p_kCTFontVariationAxisIdentifierKey = axis_id ? *axis_id : NULL;
    p_kCTFontVariationAxisMinimumValueKey = axis_min ? *axis_min : NULL;
    p_kCTFontVariationAxisMaximumValueKey = axis_max ? *axis_max : NULL;
    p_CFDictionaryCreateMutable = dlsym(cf_handle, "CFDictionaryCreateMutable");
    p_CFDictionarySetValue = dlsym(cf_handle, "CFDictionarySetValue");
    p_CFStringCreateWithCString = dlsym(cf_handle, "CFStringCreateWithCString");
    p_kCFTypeDictionaryKeyCallBacks =
        dlsym(cf_handle, "kCFTypeDictionaryKeyCallBacks");
    p_kCFTypeDictionaryValueCallBacks =
        dlsym(cf_handle, "kCFTypeDictionaryValueCallBacks");
    p_kCTFontAttributeName = (CFStringRef)dlsym(fw_handle, "kCTFontAttributeName");
    /* kCTFontAttributeName is an exported GLOBAL holding a CFStringRef;
     * dlsym yields its address, so deref to get the actual string. Passing
     * the address itself as the dictionary key hands CoreText a non-object
     * (objc BUS inside __setObject:forKey: class realization). */
    if (p_kCTFontAttributeName)
        p_kCTFontAttributeName = *(CFStringRef *)p_kCTFontAttributeName;
    return p_CTFontManagerCreateFontDescriptorsFromData
        && p_CTFontCreateWithFontDescriptor && p_CTFontGetGlyphsForCharacters
        && p_CTFontCreatePathForGlyph && p_CFArrayGetCount
        && p_CFArrayGetValueAtIndex && p_CGPathRelease;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)data; (void)size;
    g_depth_name = "pixels";
    CFArrayRef descs = p_CTFontManagerCreateFontDescriptorsFromData(cfdata);   /* +1 */
    if (!descs) return 0;
    int decoded = 0;
    if (p_CFArrayGetCount(descs) > 0) {
        CTFontDescriptorRef desc =
            (CTFontDescriptorRef)p_CFArrayGetValueAtIndex(descs, 0);
        if (desc) {
            CTFontRef font = p_CTFontCreateWithFontDescriptor(desc, 12.0, NULL);
            if (font) {
                uint16_t chars[4] = {'A', 'g', 'Q', 'y'};
                uint16_t glyphs[4] = {0, 0, 0, 0};
                if (p_CTFontGetGlyphsForCharacters(font, chars, glyphs, 4)) {
                    for (int i = 0; i < 4; i++) {
                        if (!glyphs[i]) continue;
                        IOSR_CGAffineTransform xf = {1, 0, 0, 1, 0, 0};
                        CGPathRef path =
                            p_CTFontCreatePathForGlyph(font, glyphs[i], &xf);
                        if (path) { p_CGPathRelease(path); decoded = 1; }
                    }
                }
                /* Deep decode (#228): shape an attributed line through the
                 * layout engine (see shape_line above). */
                CFStringRef text = p_CFStringCreateWithCString
                    ? p_CFStringCreateWithCString(NULL, "AgQyffiW10",
                                                  0x00000600 /* kCFStringEncodingUTF8 */)
                    : NULL;
                if (shape_line(font, text, NULL)) decoded = 1;
                if (text) p_CFRelease(text);
                p_CFRelease(font);
            }
            g_depth_value += rasterize(desc);
        }
    }
    p_CFRelease(descs);
    return decoded;
}

#define IOSR_HAVE_CANARY 1
static int run_canary_view(const uint8_t *view, size_t len) {
    CFDataRef input = canary_cfdata(view, len);
    if (!input) return 0;
    int decoded = run_target(NULL, 0, input);   /* reads only the CFData */
    p_CFRelease(input);
    return decoded;
}

#else
#error "Define one of HARNESS_TARGET_IMAGEIO / _AUDIOTOOLBOX / _COREGRAPHICS / _CORETEXT / _VIDEOTOOLBOX / _SELFTEST"
#endif

static int g_ready = 0;
/* Decode status of the most recent LLVMFuzzerTestOneInput call:
 * 1 = the entry point produced an object, 0 = it rejected the input. */
int g_last_decoded = 0;

/* Detection canary (see canary_open): print the guarded range, then let the
 * framework read into it. */
static int run_canary(const uint8_t *data, size_t size) {
#ifdef IOSR_HAVE_CANARY
    IOSR_Canary c = {0};
    const char *mode = canary_open(&c, data, size);
    fprintf(stderr, "IOSR-CANARY mode=%s lo=0x%016lx hi=0x%016lx\n",
            mode ? mode : "unguarded", (unsigned long)c.lo, (unsigned long)c.hi);
    int decoded = mode ? run_canary_view(c.view, c.len) : 0;
    free(c.block);
    return decoded;
#else
    (void)data; (void)size;
    fprintf(stderr, "IOSR-CANARY mode=unsupported lo=0x0 hi=0x0\n");
    return 0;
#endif
}

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
    g_depth_name = NULL;
    g_depth_value = 0;
    g_digest = 0;
    g_digested = 0;
    if (!g_ready && !resolve_target()) return 0;
    if (canary_requested()) {
        g_last_decoded = run_canary(data, size);
        return 0;
    }
    /* CoreFoundation is optional (the self-test target needs no framework). */
    CFDataRef cfdata = p_CFDataCreate ? p_CFDataCreate(NULL, data, (CFIndex)size)
                                      : NULL;
    #ifdef HARNESS_SANCOV
    g_sancov_active = 1;
    #endif
    g_last_decoded = run_target(data, size, cfdata);
    #ifdef HARNESS_SANCOV
    g_sancov_active = 0;
    #endif
    if (cfdata && p_CFRelease) p_CFRelease(cfdata);
    return 0;
}

#ifdef HARNESS_STANDALONE
#include "harness_runtime.h"
/*
 * Standalone driver: builds on the stock Apple toolchain (no libFuzzer runtime
 * required). Runs one or more input files through LLVMFuzzerTestOneInput and
 * emits the stdout protocol documented at the top of this file. Batching many
 * files into one process amortizes the dlopen + process-spawn cost.
 */
/*
 * Persistent entry point for binary-instrumentation fuzzers (Jackalope /
 * TinyInst), which hook a named function and loop it in place:
 *   -target_module <framework>_fuzzer -target_method _iosr_fuzz_file
 *   -nargs 1 -persist -loop -- ./<framework>_fuzzer @@
 * Exported and never inlined so the instrumenter can find it. Returns 1 if the
 * input was read and run, 0 if the file could not be read.
 */
__attribute__((noinline, visibility("default")))
int iosr_fuzz_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        g_last_decoded = 0;
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) n = 0;
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    size_t rd = buf ? fread(buf, 1, (size_t)n, f) : 0;
    fclose(f);
    LLVMFuzzerTestOneInput(buf, rd);  /* may abort here on a finding */
    free(buf);
    return 1;
}

static int run_one_file(const char *path, int index) {
    printf("RUN %d\n", index);
    fflush(stdout);
    #ifdef HARNESS_SANCOV
    sancov_reset();
    #endif
    if (!iosr_fuzz_file(path)) {
        printf("DONE %d rejected\n", index);
        fflush(stdout);
        return 0;
    }
    #ifdef HARNESS_SANCOV
    sancov_write_map();
    #endif
    if (g_depth_name)
        printf("DONE %d %s %s=%ld\n", index, g_last_decoded ? "decoded" : "rejected",
               g_depth_name, g_depth_value);
    else
        printf("DONE %d %s\n", index, g_last_decoded ? "decoded" : "rejected");
    const char *digest = getenv("IOSR_DIGEST");
    if (digest && strcmp(digest, "1") == 0 && g_digested)
        printf("DIGEST %d %016llx\n", index, (unsigned long long)g_digest);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    iosr_arm_guard_malloc(argv);          /* may re-exec under libgmalloc */
    iosr_install_crash_reporter();
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
