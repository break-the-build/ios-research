/*
 * P4-LIVENESS: IOTimeSyncDomain type-0x00 user-client dispatch liveness probe.
 *
 * Scope (operator-approved, defensive):
 *   - APIs: IOServiceMatching / IOServiceGetMatchingService (discovery only),
 *     IOServiceOpen, IOConnectCallScalarMethod, IOServiceClose, IOObjectRelease.
 *   - Scalar method calls ALWAYS carry NULL input vector / NULL output vector,
 *     zero counts. No structure or scalar argument data is ever populated.
 *   - Exactly ONE scalar-method call per process launch ('call' mode), selector
 *     taken from argv and checked against a hardcoded allowlist:
 *         { 0xFEED, 18, 41, 52 }
 *   - 'baseline' mode performs opens/closes only: ZERO method calls.
 *   - Connect budget across all launches of this experiment: <= 8 cycles.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NUB_CLASS "IOTimeSyncDomain"
#define OPEN_TYPE_LIVE  0x00u   /* empirically opens */
#define OPEN_TYPE_GATED 0x18u   /* empirically refused */

static const uint32_t kAllowed[] = { 0xFEEDu, 18u, 41u, 52u };

static int sel_allowed(uint32_t sel)
{
    for (size_t i = 0; i < sizeof(kAllowed) / sizeof(kAllowed[0]); ++i)
        if (kAllowed[i] == sel)
            return 1;
    return 0;
}

static const char *krname(kern_return_t kr)
{
    switch (kr) {
    case KERN_SUCCESS: return "KERN_SUCCESS";
    case 0xe00002c1:   return "kIOReturnNotPrivileged";
    case 0xe00002c2:   return "kIOReturnBadArgument";
    case 0xe00002c7:   return "kIOReturnUnsupported";
    case 0xe00002e2:   return "kIOReturnNotPermitted";
    default:           return "(see mach_error_string)";
    }
}

static void stamp(void)
{
    char buf[32];
    time_t now = time(NULL);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", localtime(&now));
    printf("[%s]", buf);
}

/* Discovery + open. Returns connect port or IO_OBJECT_NULL; releases service. */
static io_connect_t dom_open(uint32_t type, kern_return_t *out_kr)
{
    CFMutableDictionaryRef matching = IOServiceMatching(NUB_CLASS);
    if (!matching) {
        fprintf(stderr, "IOServiceMatching failed\n");
        *out_kr = (kern_return_t)-2;
        return IO_OBJECT_NULL;
    }

    /* NOTE: consumes the +1 reference on `matching` on success or failure. */
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!svc || svc == MACH_PORT_NULL) {
        printf("  %-16s no matching service in registry\n", NUB_CLASS);
        *out_kr = (kern_return_t)-1;
        return IO_OBJECT_NULL;
    }
    printf("  %-16s svc=%#x", NUB_CLASS, svc);

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
    IOObjectRelease(svc);
    *out_kr = kr;
    printf("  IOServiceOpen(type=0x%02x) kr=%#x (%s | %s)\n", type, kr,
           krname(kr), mach_error_string(kr));

    if (!(kr == KERN_SUCCESS && conn != IO_OBJECT_NULL))
        conn = IO_OBJECT_NULL;
    return conn;
}

static void dom_close(io_connect_t conn)
{
    if (conn == IO_OBJECT_NULL)
        return;
    kern_return_t kr = IOServiceClose(conn);
    printf("  IOServiceClose kr=%#x (%s)\n", kr, mach_error_string(kr));
}

int main(int argc, char **argv)
{
    stamp();
    printf(" == P4-LIVENESS uid=%d euid=%d pid=%d argv0=%s\n",
           getuid(), geteuid(), getpid(), argv[0]);

    if (argc >= 2 && strcmp(argv[1], "baseline") == 0) {
        /* Cycle A: control open at type 0x00 (no method calls). */
        stamp(); printf(" CYCLE-A open@0x00 control (no calls)\n");
        kern_return_t kr = KERN_SUCCESS;
        io_connect_t c = dom_open(OPEN_TYPE_LIVE, &kr);
        dom_close(c);

        /* Cycle B: refusal re-check at type 0x18 (no method calls). */
        stamp(); printf(" CYCLE-B open@0x18 refusal check (no calls)\n");
        kern_return_t kr18 = KERN_SUCCESS;
        io_connect_t c18 = dom_open(OPEN_TYPE_GATED, &kr18);
        dom_close(c18); /* hygiene: close even on unexpected success */

        stamp();
        printf(" RESULT baseline open0x00=%#x open0x18=%#x method_calls=0\n",
               kr, kr18);
        return 0;
    }

    if (argc >= 3 && strcmp(argv[1], "call") == 0) {
        char *end = NULL;
        unsigned long sel_ul = strtoul(argv[2], &end, 0);
        if (!end || *end != '\0' || !sel_allowed((uint32_t)sel_ul)) {
            fprintf(stderr,
                    "REFUSED: selector '%s' not in allowlist {0xFEED,18,41,52}\n",
                    argv[2]);
            return 2;
        }
        uint32_t sel = (uint32_t)sel_ul;

        /* Single cycle: open -> ONE empty scalar call -> close. */
        stamp();
        printf(" CYCLE-C open@0x00 then scalar sel=%u (0x%02x) NULL/0 in, "
               "NULL/0 out\n", sel, sel);
        kern_return_t kro = KERN_SUCCESS;
        io_connect_t c = dom_open(OPEN_TYPE_LIVE, &kro);
        if (c == IO_OBJECT_NULL) {
            stamp();
            printf(" RESULT sel=%u(0x%02x) NO-CONNECT open_kr=%#x\n",
                   sel, sel, kro);
            return 1;
        }

        kern_return_t kr = IOConnectCallScalarMethod(c, sel, NULL, 0, NULL, NULL);
        stamp();
        printf(" IOConnectCallScalarMethod(sel=%u/0x%02x) kr=%#x (%s | %s)\n",
               sel, sel, kr, krname(kr), mach_error_string(kr));

        dom_close(c);
        stamp();
        printf(" RESULT sel=%u(0x%02x) kr=%#x name=%s\n", sel, sel, kr,
               krname(kr));
        return 0;
    }

    fprintf(stderr, "usage:\n  %s baseline\n  %s call <sel>   "
                    "(sel in {0xFEED,18,41,52})\n", argv[0], argv[0]);
    return 2;
}
