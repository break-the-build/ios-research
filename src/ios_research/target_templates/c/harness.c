/*
 * Custom ios-research target harness ({name}) — C, byte input.
 *
 * Deliberately triggerable ASan findings keyed on byte markers (modeled on
 * tools/harness/mac_fuzz_harness.c HARNESS_TARGET_SELFTEST) so
 * `ios-research target validate` can prove real crash parsing end to end:
 *   input contains "OOB" -> heap-buffer-overflow READ
 *   input contains "WRT" -> heap-buffer-overflow WRITE
 *   input contains "UAF" -> heap-use-after-free READ
 * Anything else is parsed cleanly. Authorized/own-machine research only.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains(const uint8_t *d, size_t n, const char *s) {
    size_t len = strlen(s);
    if (n < len) return 0;
    for (size_t i = 0; i + len <= n; i++) {
        if (memcmp(d + i, s, len) == 0) return 1;
    }
    return 0;
}

static int parse_record(const uint8_t *data, size_t size) {
    uint8_t *buf = (uint8_t *)malloc(16);
    if (!buf) return 0;
    memset(buf, 0, 16);
    if (contains(data, size, "OOB")) {
        volatile uint8_t x = buf[16 + (size & 0x3F)];  /* heap OOB read  */
        (void)x;
    } else if (contains(data, size, "WRT")) {
        buf[64] = 0x41;                                /* heap OOB write */
    } else if (contains(data, size, "UAF")) {
        free(buf);
        volatile uint8_t y = buf[0];                   /* use-after-free */
        (void)y;
        buf = NULL;
    }
    if (buf) free(buf);
    return 1;
}

/* libFuzzer-compatible entry point (used when built with -fsanitize=fuzzer;
 * see docs/TARGET-SDK.md for the two build modes). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return parse_record(data, size) ? 0 : 0;
}

#ifndef HARNESS_SDK_NO_MAIN
/* Standalone driver: Apple clang ships no libFuzzer runtime, so the default
 * build links this main instead. Runs each argv file through the entry point;
 * ASan reports go to stderr and exit non-zero (exitcode=99). */
int main(int argc, char **argv) {
    static uint8_t blob[1 << 20];
    for (int i = 1; i < argc; i++) {
        FILE *fh = fopen(argv[i], "rb");
        if (!fh) { perror(argv[i]); return 2; }
        size_t n = fread(blob, 1, sizeof(blob), fh);
        fclose(fh);
        (void)LLVMFuzzerTestOneInput(blob, n);
    }
    return 0;
}
#endif /* HARNESS_SDK_NO_MAIN */
