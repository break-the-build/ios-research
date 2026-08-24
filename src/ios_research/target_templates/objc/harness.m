/*
 * Custom ios-research target harness ({name}) — Objective-C, byte input.
 *
 * Platform fallback: plain Objective-C (no Foundation dependency) with an
 * argv-based driver because Apple clang ships no libFuzzer runtime. Same
 * OOB/WRT/UAF marker scheme as the C template. Authorized research only.
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

/* Standalone driver (Apple clang ships no libFuzzer runtime). */
int main(int argc, char **argv) {
    static uint8_t blob[1 << 20];
    for (int i = 1; i < argc; i++) {
        FILE *fh = fopen(argv[i], "rb");
        if (!fh) { perror(argv[i]); return 2; }
        size_t n = fread(blob, 1, sizeof(blob), fh);
        fclose(fh);
        (void)parse_record(blob, n);
    }
    return 0;
}
