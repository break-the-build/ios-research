/* P4-LIVENESS probe: IOTimeSyncClockManager externalMethod liveness.
 * One connect cycle per launch: IOServiceOpen(type=0x18) ->
 * IOConnectCallScalarMethod(sel, NULL in/out) -> IOServiceClose.
 * No buffers, no data passed. Defensive scope per campaign-0825 P4.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef kIOMainPortDefault
#define kIOMainPortDefault kIOMasterPortDefault
#endif

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <selector>\n", argv[0]);
        return 2;
    }
    uint64_t sel = strtoull(argv[1], NULL, 0);

    printf("== P4-LIVENESS probe_cm uid=%d euid=%d pid=%d sel=0x%llx ==\n",
           getuid(), geteuid(), getpid(), sel);

    CFDictionaryRef matching = IOServiceMatching("IOTimeSyncClockManager");
    if (!matching) {
        fprintf(stderr, "{\"error\":\"IOServiceMatching failed\"}\n");
        return 1;
    }
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!svc) {
        fprintf(stderr, "{\"error\":\"no matching service\"}\n");
        return 1;
    }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t okr = IOServiceOpen(svc, mach_task_self(), 0x18, &conn);
    printf("IOServiceOpen type=0x18 kr=0x%x (%s)\n", okr, mach_error_string(okr));

    if (okr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
        kern_return_t ckr = IOConnectCallScalarMethod(
            conn, (uint32_t)sel, NULL, 0, NULL, NULL);
        printf("IOConnectCallScalarMethod sel=0x%llx in=NULL/0 out=NULL kr=0x%x (%s)\n",
               sel, ckr, mach_error_string(ckr));

        kern_return_t kkr = IOServiceClose(conn);
        printf("IOServiceClose kr=0x%x (%s)\n", kkr, mach_error_string(kkr));
    } else {
        printf("(open failed; no connect call issued)\n");
    }

    IOObjectRelease(svc);
    printf("== done ==\n");
    return 0;
}
