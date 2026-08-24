/*
 * Custom ios-research target harness ({name}) — C++, byte input.
 *
 * Same marker scheme as the C template (OOB/WRT/UAF -> distinct ASan
 * classifications) so `target validate` can prove real crash parsing.
 * Authorized/own-machine research only.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>

static bool contains(const uint8_t *d, size_t n, const char *s) {
    size_t len = std::strlen(s);
    if (n < len) return false;
    for (size_t i = 0; i + len <= n; i++) {
        if (std::memcmp(d + i, s, len) == 0) return true;
    }
    return false;
}

static int parse_record(const uint8_t *data, size_t size) {
    auto *buf = static_cast<uint8_t *>(std::malloc(16));
    if (!buf) return 0;
    std::memset(buf, 0, 16);
    if (contains(data, size, "OOB")) {
        volatile uint8_t x = buf[16 + (size & 0x3F)];  /* heap OOB read  */
        static_cast<void>(x);
    } else if (contains(data, size, "WRT")) {
        buf[64] = 0x41;                                /* heap OOB write */
    } else if (contains(data, size, "UAF")) {
        std::free(buf);
        volatile uint8_t y = buf[0];                   /* use-after-free */
        static_cast<void>(y);
        buf = nullptr;
    }
    if (buf) std::free(buf);
    return 1;
}

/* libFuzzer-compatible entry point (see docs/TARGET-SDK.md). */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return parse_record(data, size) ? 0 : 0;
}

#ifndef HARNESS_SDK_NO_MAIN
/* Standalone driver (Apple clang ships no libFuzzer runtime). */
int main(int argc, char **argv) {
    static uint8_t blob[1 << 20];
    for (int i = 1; i < argc; i++) {
        std::FILE *fh = std::fopen(argv[i], "rb");
        if (!fh) { std::perror(argv[i]); return 2; }
        size_t n = std::fread(blob, 1, sizeof(blob), fh);
        std::fclose(fh);
        (void)LLVMFuzzerTestOneInput(blob, n);
    }
    return 0;
}
#endif /* HARNESS_SDK_NO_MAIN */
