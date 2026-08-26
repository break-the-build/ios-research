/*
 * P3-OPENPROBE: unprivileged reachability probe for gPTP-family IOKit nubs.
 *
 * Scope (operator-approved, defensive):
 *   - ONLY IOServiceGetMatchingService / IOServiceOpen / IOObjectGetClass /
 *     IOServiceClose / IOObjectRelease.
 *   - NO IOConnectCallMethod / externalMethod. No buffers sent to kernel.
 *   - Open -> identify class -> immediate close.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <unistd.h>

static void probe(const char *class_name, uint32_t type)
{
    CFMutableDictionaryRef matching = IOServiceMatching(class_name);
    if (!matching) {
        printf("%-24s type=0x%02x  ERROR: IOServiceMatching returned NULL\n",
               class_name, type);
        return;
    }

    /* NOTE: consumes the +1 reference on `matching` on success or failure. */
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!svc || svc == MACH_PORT_NULL) {
        printf("%-24s type=0x%02x  RESULT: no matching service in registry\n",
               class_name, type);
        return;
    }

    char svcbuf[128] = {0};
    kern_return_t krs = IOObjectGetClass(svc, svcbuf);
    printf("%-24s type=0x%02x  svc=%#x svc-class=%s\n", class_name, type, svc,
           (krs == KERN_SUCCESS) ? svcbuf : "<getclass-failed>");

    io_connect_t connect = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &connect);

    printf("%-24s type=0x%02x  IOServiceOpen kr=%#x (%s)", class_name, type,
           kr, mach_error_string(kr));

    if (kr == KERN_SUCCESS && connect != IO_OBJECT_NULL) {
        char buf[128] = {0};
        kern_return_t krc = IOObjectGetClass(connect, buf);
        if (krc == KERN_SUCCESS) {
            printf("  UC-class=\"%s\"", buf);
        } else {
            printf("  IOObjectGetClass kr=%#x (%s)", krc, mach_error_string(krc));
        }
        kern_return_t krclose = IOServiceClose(connect);
        printf("  IOServiceClose kr=%#x", krclose);
        connect = IO_OBJECT_NULL;
    } else if (kr != KERN_SUCCESS && connect != IO_OBJECT_NULL) {
        /* defensive hygiene: never leak a port even on unexpected combos */
        IOServiceClose(connect);
        connect = IO_OBJECT_NULL;
    }

    printf("\n");
    IOObjectRelease(svc);
}

int main(void)
{
    printf("== P3-OPENPROBE uid=%d euid=%d pid=%d ==\n", getuid(), geteuid(), getpid());

    probe("IOTimeSyncDomain",       0x18);  /* step 1 */
    probe("IOTimeSyncgPTPManager",  0x18);  /* step 2 */
    probe("IOTimeSyncClockManager", 0x18);  /* step 3 */
    probe("IOTimeSyncDomain",       0x00);  /* step 4: negative control */

    printf("== done ==\n");
    return 0;
}
