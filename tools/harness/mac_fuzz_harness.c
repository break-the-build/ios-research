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
static void (*p_CGContextDrawImage)(CGContextRef, void *, CGImageRef) = NULL;
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

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    CGImageSourceRef src = p_CGImageSourceCreateWithData(cfdata, NULL);
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
            if (cs) {
                CGContextRef ctx = p_CGBitmapContextCreate(
                    NULL, w, h, 8, w * 4, cs, 2 /* premul first */);
                if (ctx) {
                    double rect[4] = {0};   /* CGRect: origin + size as doubles */
                    double *r = (double *)rect;
                    r[2] = (double)w; r[3] = (double)h;
                    p_CGContextDrawImage(ctx, rect, img);
                    p_CGContextRelease(ctx);
                    decoded = 1;
                }
                p_CGColorSpaceRelease(cs);
            }
        }
        p_CFRelease(img);
    }
    p_CFRelease(src);
    return decoded;
}

#elif defined(HARNESS_TARGET_COREGRAPHICS)

/* CoreGraphics path (#27): drive a real PDF decode/render pipeline instead of
 * merely wrapping bytes. CGDataProviderCreateWithCFData only wraps a buffer and
 * never parses (every input was "accepted", no decoder logic ran), so we now
 * open a CGPDFDocument over the provider — the full PDF parser — then force a
 * decode by rendering page 1 into an offscreen bitmap context. Malformed inputs
 * are rejected by the parser (meaningful REJECTED signal); malformed ones that
 * survive parsing exercise real decode code under ASan/UBSan. */
typedef CFTypeRef CGDataProviderRef;
typedef CFTypeRef CGPDFDocumentRef;
typedef CFTypeRef CGPDFPageRef;
typedef CFTypeRef CGContextRef;
typedef CFTypeRef CGColorSpaceRef;

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
    return p_CGDataProviderCreateWithCFData && p_CGDataProviderRelease
        && p_CGPDFDocumentCreateWithProvider && p_CGPDFDocumentRelease
        && p_CGPDFDocumentGetNumberOfPages && p_CGPDFDocumentGetPage
        && p_CGBitmapContextCreate && p_CGContextRelease
        && p_CGContextDrawPDFPage && p_CGColorSpaceCreateDeviceRGB
        && p_CGColorSpaceRelease;
}

#define IOSR_CG_BITMAP_ALPHA 2  /* kCGImageAlphaPremultipliedFirst */

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    CGDataProviderRef prov = p_CGDataProviderCreateWithCFData(cfdata);
    if (!prov) return 0;
    int decoded = 0;
    CGPDFDocumentRef doc = p_CGPDFDocumentCreateWithProvider(prov);
    if (doc) {
        if (p_CGPDFDocumentGetNumberOfPages(doc) > 0) {
            CGPDFPageRef page = p_CGPDFDocumentGetPage(doc, 1);
            if (page) {
                /* Small offscreen RGBA bitmap; row bytes = width * 4. */
                CGContextRef ctx = p_CGBitmapContextCreate(
                    NULL, 64, 64, 8, 64 * 4,
                    p_CGColorSpaceCreateDeviceRGB(), IOSR_CG_BITMAP_ALPHA);
                if (ctx) {
                    p_CGContextDrawPDFPage(ctx, page);  /* forces full decode */
                    p_CGContextRelease(ctx);
                    decoded = 1;
                }
            }
        }
        p_CGPDFDocumentRelease(doc);
    }
    p_CGDataProviderRelease(prov);
    return decoded;
}

#elif defined(HARNESS_TARGET_AUDIOTOOLBOX)

/* Deep decode (#228): open -> query format -> read packets (drives the
 * demuxer AND codec packetization) -> AudioConverter to PCM16 (drives the
 * decoder pipeline), not merely open+close. */
typedef int32_t OSStatus;
typedef uint32_t UInt32;
typedef int64_t SInt64;
typedef uint32_t FourCharCode;
typedef CFTypeRef AudioFileID;

typedef OSStatus (*AudioFile_ReadProc)(void *, SInt64, UInt32, void *, UInt32 *);
typedef OSStatus (*AudioFile_WriteProc)(void *, SInt64, UInt32, const void *, UInt32 *);
typedef SInt64 (*AudioFile_GetSizeProc)(void *);
typedef OSStatus (*AudioFile_SetSizeProc)(void *, SInt64);

#pragma pack(push, 4)
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
#pragma pack(pop)

static OSStatus (*p_AudioFileOpenWithCallbacks)(
    void *, AudioFile_ReadProc, AudioFile_WriteProc,
    AudioFile_GetSizeProc, AudioFile_SetSizeProc, UInt32, AudioFileID *) = NULL;
static OSStatus (*p_AudioFileClose)(AudioFileID) = NULL;
static OSStatus (*p_AudioFileGetProperty)(AudioFileID, FourCharCode,
                                          UInt32 *, void *) = NULL;
static OSStatus (*p_AudioFileReadPacketData)(AudioFileID, int,
                                             UInt32 *, void *, SInt64, UInt32, void *) = NULL;
static OSStatus (*p_AudioConverterNew)(const IOSR_ASBD *, const IOSR_ASBD *, void **) = NULL;
static void (*p_AudioConverterDispose)(void *) = NULL;
static OSStatus (*p_AudioConverterConvertComplexBuffer)(void *, UInt32,
                                                        void *, void *) = NULL;

/* AudioConverterConvertComplexBuffer parameter structs (packed layouts). */
#pragma pack(push, 4)
typedef struct { UInt32 mNumberBuffers; struct { UInt32 mNumberChannels; UInt32 mDataByteSize; void *mData; } mBuffers[1]; } IOSR_ACB1;
typedef struct { UInt32 mNumberBuffers; struct { UInt32 mNumberChannels; UInt32 mDataByteSize; void *mData; } mBuffers[1]; } IOSR_ACB2;
#pragma pack(pop)

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
    p_AudioConverterConvertComplexBuffer = dlsym(fw_handle, "AudioConverterConvertComplexBuffer");
    return p_AudioFileOpenWithCallbacks && p_AudioFileClose
        && p_AudioFileGetProperty && p_AudioFileReadPacketData
        && p_AudioConverterNew && p_AudioConverterDispose
        && p_AudioConverterConvertComplexBuffer;
}

#define IOSR_AT_PROP_FORMAT 0x61736264UL  /* 'asbd' kAudioFilePropertyDataFormat */
#define IOSR_AT_MAX_PACKETS 64u
#define IOSR_AT_BUF_BYTES (64u * 1024u)

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)cfdata;
    MemFile mf = { data, size };
    AudioFileID af = NULL;
    OSStatus st = p_AudioFileOpenWithCallbacks(&mf, mem_read, NULL,
                                               mem_size, NULL, 0, &af);
    if (st != 0 || !af) return 0;

    int exercised = 0;
    IOSR_ASBD src_fmt;
    UInt32 sz = sizeof(src_fmt);
    if (p_AudioFileGetProperty(af, IOSR_AT_PROP_FORMAT, &sz, &src_fmt) == 0) {
        /* Read packets through the demuxer. */
        static UInt8 pktbuf[IOSR_AT_BUF_BYTES];
        static IOSR_ASBD dst_fmt;
        static UInt8 convbuf[IOSR_AT_BUF_BYTES];
        UInt32 npackets = IOSR_AT_MAX_PACKETS;
        void *pktdescs = NULL;
        if (p_AudioFileReadPacketData(af, 0 /* !cache */, &npackets,
                                      pktdescs, 0, IOSR_AT_BUF_BYTES,
                                      pktbuf) == 0 && npackets > 0) {
            exercised = 1;
            /* Convert to 16-bit stereo PCM through the codec pipeline. */
            dst_fmt = src_fmt;
            dst_fmt.mSampleRate = 44100.0;
            dst_fmt.mFormatID = 0x6c70636dUL;      /* 'lpcm' */
            dst_fmt.mFormatFlags = 0x0000000cUL;   /* signed | packed */
            dst_fmt.mBytesPerPacket = 4;
            dst_fmt.mFramesPerPacket = 1;
            dst_fmt.mBytesPerFrame = 4;
            dst_fmt.mChannelsPerFrame = 2;
            dst_fmt.mBitsPerChannel = 16;
            dst_fmt.mReserved = 0;
            void *conv = NULL;
            if (p_AudioConverterNew(&src_fmt, &dst_fmt, &conv) == 0 && conv) {
                IOSR_ACB1 in; in.mNumberBuffers = 1;
                in.mBuffers[0].mNumberChannels = src_fmt.mChannelsPerFrame;
                in.mBuffers[0].mDataByteSize = IOSR_AT_BUF_BYTES;
                in.mBuffers[0].mData = pktbuf;
                IOSR_ACB2 out; out.mNumberBuffers = 1;
                out.mBuffers[0].mNumberChannels = 2;
                out.mBuffers[0].mDataByteSize = IOSR_AT_BUF_BYTES;
                out.mBuffers[0].mData = convbuf;
                /* Best effort: conversion may legitimately fail on garbage. */
                p_AudioConverterConvertComplexBuffer(conv, npackets, &in, &out);
                p_AudioConverterDispose(conv);
            }
        }
    }
    p_AudioFileClose(af);
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
 * glyphs and extract an outline path, exercising glyf/CFF shape decoding under
 * ASan/UBSan. Fonts are a classic untrusted-input surface shared by iOS/macOS. */
typedef CFTypeRef CTFontDescriptorRef;
typedef CFTypeRef CTFontRef;
typedef CFTypeRef CFArrayRef;
typedef CFTypeRef CGPathRef;
typedef struct { float a, b, c, d, tx, ty; } IOSR_CGAffineTransform;

static CFArrayRef (*p_CTFontManagerCreateFontDescriptorsFromData)(CFDataRef) = NULL;
static CTFontRef (*p_CTFontCreateWithFontDescriptor)(CTFontDescriptorRef,
                                                     double, void *) = NULL;
static int (*p_CTFontGetGlyphsForCharacters)(CTFontRef, const uint16_t *,
                                             uint16_t *, CFIndex) = NULL;
static CGPathRef (*p_CTFontCreatePathForGlyph)(CTFontRef, uint16_t,
                                               const IOSR_CGAffineTransform *) = NULL;
static CFIndex (*p_CFArrayGetCount)(CFArrayRef) = NULL;
static CFTypeRef (*p_CFArrayGetValueAtIndex)(CFArrayRef, CFIndex) = NULL;
static void (*p_CGPathRelease)(CGPathRef) = NULL;
typedef CFTypeRef CFMutableDictionaryRef;
typedef CFTypeRef CFAttributedStringRef;
typedef CFTypeRef CTLineRef;
static CFAttributedStringRef (*p_CFAttributedStringCreate)(void *, CFStringRef, CFDictionaryRef) = NULL;
static CTLineRef (*p_CTLineCreateWithAttributedString)(CFTypeRef) = NULL;
static CFMutableDictionaryRef (*p_CFDictionaryCreateMutable)(void *, long) = NULL;
static void (*p_CFDictionarySetValue)(CFMutableDictionaryRef, const void *, const void *) = NULL;
static CFStringRef (*p_CFStringCreateWithCString)(void *, const char *, unsigned int) = NULL;

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
    p_CFAttributedStringCreate = dlsym(cf_handle, "CFAttributedStringCreate");
    p_CTLineCreateWithAttributedString = dlsym(fw_handle, "CTLineCreateWithAttributedString");
    p_CFDictionaryCreateMutable = dlsym(cf_handle, "CFDictionaryCreateMutable");
    p_CFDictionarySetValue = dlsym(cf_handle, "CFDictionarySetValue");
    p_CFStringCreateWithCString = dlsym(cf_handle, "CFStringCreateWithCString");
    return p_CTFontManagerCreateFontDescriptorsFromData
        && p_CTFontCreateWithFontDescriptor && p_CTFontGetGlyphsForCharacters
        && p_CTFontCreatePathForGlyph && p_CFArrayGetCount
        && p_CFArrayGetValueAtIndex && p_CGPathRelease;
}

static int run_target(const uint8_t *data, size_t size, CFDataRef cfdata) {
    (void)data; (void)size;
    CFArrayRef descs = p_CTFontManagerCreateFontDescriptorsFromData(cfdata);
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
                p_CFRelease(font);
            }
        }
    }
    /* Deep decode (#228): shape an attributed line through the layout
     * engine - drives feature-driven glyph substitution (morx/GSUB) and
     * cluster mapping, not merely outline extraction. */
    if (p_CFAttributedStringCreate && p_CTLineCreateWithAttributedString
        && p_CFDictionaryCreateMutable && p_CFDictionarySetValue
        && p_CFStringCreateWithCString) {
        CFStringRef text = p_CFStringCreateWithCString(
            NULL, "AgQyffiW10", 0x00000600 /* kCFStringEncodingUTF8 */);
        if (text) {
            CFMutableDictionaryRef dict =
                p_CFDictionaryCreateMutable(NULL, 1);
            if (dict) {
                /* kCTFontAttributeName carries the CTFont as the value. */
                p_CFDictionarySetValue(dict, (const void *)1,
                                       (const void *)font);
                CFAttributedStringRef as = p_CFAttributedStringCreate(
                    NULL, text, dict);
                if (as) {
                    CTLineRef line = p_CTLineCreateWithAttributedString(as);
                    if (line) { p_CFRelease(line); decoded = 1; }
                    p_CFRelease(as);
                }
                p_CFRelease(dict);
            }
            p_CFRelease(text);
        }
    }
    p_CFRelease(descs);
    return decoded;
}

#else
#error "Define one of HARNESS_TARGET_IMAGEIO / _AUDIOTOOLBOX / _COREGRAPHICS / _CORETEXT / _SELFTEST"
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
    #ifdef HARNESS_SANCOV
    sancov_reset();
    #endif
    LLVMFuzzerTestOneInput(buf, rd);  /* may abort here on a sanitizer finding */
    #ifdef HARNESS_SANCOV
    sancov_write_map();
    #endif
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
