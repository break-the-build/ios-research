/*
 * gen_videoseeds.c — generate videotoolbox harness seed files (#234).
 *
 * Dev tool, NOT part of the sanitizer harness: links the framework headers
 * directly. It encodes a few frames of a tiny gradient clip with Apple's own
 * VideoToolbox encoders (H.264 and HEVC), pulls the parameter sets out of the
 * resulting CMFormatDescription ("avcC"/"hvcC" sample-description atoms), and
 * writes seed files in the container format mac_fuzz_harness.c's
 * HARNESS_TARGET_VIDEOTOOLBOX expects:
 *
 *   byte 0        flags (bit0: codec, 0 = H.264 / 1 = HEVC)
 *   records       u32 BE length + bytes   (H264: SPS,PPS,frame; HEVC: VPS,SPS,PPS,frame)
 *   frame record  repeated u32 BE length-prefixed NALs (harness re-emits AVCC/HVCC)
 *
 * Usage: gen_videoseeds <out-h264> <out-hevc>
 * Build:  xcrun clang tools/harness/gen_videoseeds.c -o /tmp/gen_videoseeds \
 *           -framework CoreFoundation -framework CoreMedia -framework CoreVideo \
 *           -framework VideoToolbox
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <VideoToolbox/VideoToolbox.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIDTH 96
#define HEIGHT 96

static CMSampleBufferRef g_first_sample = NULL;

static void compression_cb(void *refCon, void *srcFrameRefCon, OSStatus status,
                           VTEncodeInfoFlags infoFlags,
                           CMSampleBufferRef sampleBuffer) {
    (void)refCon; (void)srcFrameRefCon; (void)infoFlags;
    if (status != 0 || !sampleBuffer || !CMSampleBufferDataIsReady(sampleBuffer))
        return;
    if (!g_first_sample && CMSampleBufferGetNumSamples(sampleBuffer) == 1) {
        /* Keep only the first (IDR/keyframe) access unit. */
        CFRetain(sampleBuffer);
        g_first_sample = sampleBuffer;
    }
}

static void put_u32(FILE *f, uint32_t v) {
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16),
                    (uint8_t)(v >> 8), (uint8_t)v};
    fwrite(b, 1, 4, f);
}

static void put_record(FILE *f, const uint8_t *data, size_t len) {
    put_u32(f, (uint32_t)len);
    if (len) fwrite(data, 1, len, f);
}

static void put_u32_mem(uint8_t *buf, size_t *at, uint32_t v) {
    buf[(*at)++] = (uint8_t)(v >> 24);
    buf[(*at)++] = (uint8_t)(v >> 16);
    buf[(*at)++] = (uint8_t)(v >> 8);
    buf[(*at)++] = (uint8_t)v;
}

/* Extract parameter sets from the sample-description extension atom and the
 * encoded access unit, then write one seed file. Returns 0 on success. */
static int write_seed(const char *path, int hevc,
                      CMFormatDescriptionRef desc,
                      const uint8_t *au, size_t au_len) {
    CFDictionaryRef exts = (CFDictionaryRef)CMFormatDescriptionGetExtension(
        desc, kCMFormatDescriptionExtension_SampleDescriptionExtensionAtoms);
    if (!exts) { fprintf(stderr, "no extension atoms\n"); return 1; }
    CFDataRef cfg = CFDictionaryGetValue(
        exts, hevc ? CFSTR("hvcC") : CFSTR("avcC"));
    if (!cfg || CFDataGetLength(cfg) < 23) {
        fprintf(stderr, "missing %s atom\n", hevc ? "hvcC" : "avcC");
        return 1;
    }
    const uint8_t *c = CFDataGetBytePtr(cfg);
    size_t cn = (size_t)CFDataGetLength(cfg);

    uint8_t vps[512], sps[512], pps[512];
    size_t vps_len = 0, sps_len = 0, pps_len = 0;
    size_t nal_size = 4;

    if (!hevc) {
        if (cn < 8) return 1;
        nal_size = (size_t)((c[4] & 0x03) + 1);
        size_t off = 5;
        int num_sps = c[off++] & 0x1F;
        for (int i = 0; i < num_sps && off + 2 <= cn; i++) {
            size_t l = ((size_t)c[off] << 8) | c[off + 1];
            off += 2;
            if (off + l > cn) return 1;
            if (!sps_len && l <= sizeof(sps)) { memcpy(sps, c + off, l); sps_len = l; }
            off += l;
        }
        if (off >= cn) return 1;
        int num_pps = c[off++];
        for (int i = 0; i < num_pps && off + 2 <= cn; i++) {
            size_t l = ((size_t)c[off] << 8) | c[off + 1];
            off += 2;
            if (off + l > cn) return 1;
            if (!pps_len && l <= sizeof(pps)) { memcpy(pps, c + off, l); pps_len = l; }
            off += l;
        }
    } else {
        if (cn < 23) return 1;
        nal_size = (size_t)((c[21] & 0x03) + 1);
        size_t off = 22;
        int num_arrays = c[off++];
        for (int a = 0; a < num_arrays && off + 3 <= cn; a++) {
            uint8_t type = c[off] & 0x3F;
            off += 1;
            size_t num_nalus = ((size_t)c[off] << 8) | c[off + 1];
            off += 2;
            for (size_t n = 0; n < num_nalus && off + 2 <= cn; n++) {
                size_t l = ((size_t)c[off] << 8) | c[off + 1];
                off += 2;
                if (off + l > cn) return 1;
                if (l <= sizeof(vps)) {
                    if (type == 32 && !vps_len) { memcpy(vps, c + off, l); vps_len = l; }
                    else if (type == 33 && !sps_len) { memcpy(sps, c + off, l); sps_len = l; }
                    else if (type == 34 && !pps_len) { memcpy(pps, c + off, l); pps_len = l; }
                }
                off += l;
            }
        }
    }
    if (!sps_len || !pps_len || (hevc && !vps_len)) {
        fprintf(stderr, "could not extract parameter sets (%s)\n",
                hevc ? "VPS/SPS/PPS" : "SPS/PPS");
        return 1;
    }

    /* Re-chunk the access unit into canonical 4-byte-length-prefixed NALs. */
    FILE *out = fopen(path, "wb");
    if (!out) { perror("fopen"); return 1; }
    fputc(hevc ? 1 : 0, out);
    uint8_t frame[256 * 1024];
    size_t ftot = 0;
    size_t off = 0;
    int guard = 0;
    while (off + nal_size <= au_len && guard++ < 64) {
        size_t nl = 0;
        for (size_t b = 0; b < nal_size; b++)
            nl = (nl << 8) | au[off + b];
        off += nal_size;
        if (nl > au_len - off) break;
        if (ftot + 4 + nl > sizeof(frame)) break;
        put_u32_mem(frame, &ftot, (uint32_t)nl);
        memcpy(frame + ftot, au + off, nl);
        ftot += nl;
        off += nl;
    }
    if (!ftot) { fprintf(stderr, "empty access unit\n"); fclose(out); return 1; }

    if (hevc) put_record(out, vps, vps_len);
    put_record(out, sps, sps_len);
    put_record(out, pps, pps_len);
    put_record(out, frame, ftot);
    fclose(out);
    printf("wrote %s (%zu B, %s, nal_len=%zu)\n", path,
           (size_t)(ftot + sps_len + pps_len + vps_len),
           hevc ? "HEVC" : "H.264", nal_size);
    return 0;
}

static OSStatus make_frame_pixel_buffer(int64_t idx, CVPixelBufferRef *out) {
    CVPixelBufferRef pb = NULL;
    OSStatus st = CVPixelBufferCreate(
        NULL, WIDTH, HEIGHT, kCVPixelFormatType_420YpCbCr8Planar, NULL, &pb);
    if (st != 0) return st;
    CVPixelBufferLockBaseAddress(pb, 0);
    for (int plane = 0; plane < 3; plane++) {
        uint8_t *base = CVPixelBufferGetBaseAddressOfPlane(pb, plane);
        size_t stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
        size_t ph = CVPixelBufferGetHeightOfPlane(pb, plane);
        size_t pw = CVPixelBufferGetWidthOfPlane(pb, plane);
        if (!base) continue;
        for (size_t y = 0; y < ph; y++) {
            memset(base + y * stride,
                   (uint8_t)((idx * 37) + plane * 60 + y),
                   pw ? pw : stride);
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    *out = pb;
    return 0;
}

static int encode_one(CMVideoCodecType codec, const char *out_path) {
    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(
        NULL, WIDTH, HEIGHT, codec, NULL, NULL, NULL, compression_cb, NULL,
        &sess);
    if (st != 0 || !sess) {
        fprintf(stderr, "codec 0x%x: VTCompressionSessionCreate %d (HEVC may "
                        "be unsupported on this machine)\n", codec, st);
        return 1;
    }
    CFStringRef profile_key = kVTCompressionPropertyKey_ProfileLevel;
    if (profile_key) {
        CFStringRef level = codec == kCMVideoCodecType_HEVC
            ? CFSTR("Main_AutoLevel") : CFSTR("Baseline_Auto_Level");
        VTSessionSetProperty(sess, profile_key, level);
    }

    CMFormatDescriptionRef desc = NULL;
    uint8_t au[256 * 1024];
    size_t au_len = 0;
    for (int64_t i = 0; i < 2; i++) {
        CVPixelBufferRef pb = NULL;
        if (make_frame_pixel_buffer(i, &pb) != 0) continue;
        CMTime pts = CMTimeMake(i, 30);
        CMTime dur = CMTimeMake(1, 30);
        CFNumberRef force = CFNumberCreate(NULL, kCFNumberIntType,
                                           &(int){1});
        const void *keys[1] = { kVTEncodeFrameOptionKey_ForceKeyFrame };
        const void *vals[1] = { force };
        CFDictionaryRef props = CFDictionaryCreate(
            NULL, keys, vals, 1, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFRelease(force);
        st = VTCompressionSessionEncodeFrame(sess, pb, pts, dur, props, NULL,
                                             NULL);
        CFRelease(props);
        CVPixelBufferRelease(pb);
        if (st != 0) fprintf(stderr, "EncodeFrame(%lld): %d\n", (long long)i, st);
    }
    VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid);
    if (g_first_sample) {
        CMBlockBufferRef bb = CMSampleBufferGetDataBuffer(g_first_sample);
        size_t len = (size_t)CMBlockBufferGetDataLength(bb);
        if (bb && len && len <= sizeof(au)) {
            if (CMBlockBufferCopyDataBytes(bb, 0, len, au) == 0) au_len = len;
        }
        desc = (CMFormatDescriptionRef)CMSampleBufferGetFormatDescription(
            g_first_sample);
        if (desc) CFRetain(desc);
        CFRelease(g_first_sample);
        g_first_sample = NULL;
    }
    VTCompressionSessionInvalidate(sess);
    CFRelease(sess);

    int rc = 1;
    if (desc && au_len) rc = write_seed(out_path, codec == kCMVideoCodecType_HEVC,
                                        desc, au, au_len);
    if (desc) CFRelease(desc);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <out-h264-seed> <out-hevc-seed>\n", argv[0]);
        return 2;
    }
    int rc = encode_one(kCMVideoCodecType_H264, argv[1]);
    rc |= encode_one(kCMVideoCodecType_HEVC, argv[2]);
    return rc;
}
