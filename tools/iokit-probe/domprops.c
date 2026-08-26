#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
static void dump(CFDictionaryRef d, int depth);
static void dumpval(CFTypeRef v, int depth) {
    if (CFGetTypeID(v) == CFDictionaryGetTypeID()) { printf("\n"); dump((CFDictionaryRef)v, depth+1); }
    else if (CFGetTypeID(v) == CFArrayGetTypeID()) {
        CFIndex n = CFArrayGetCount(v);
        if (n > 8) { printf(" [array n=%lld]", (long long)n); return; }
        printf(" [ ");
        for (CFIndex i=0;i<n;i++) { dumpval(CFArrayGetValueAtIndex(v,i), depth); printf(" "); }
        printf("]");
    } else {
        CFStringRef s = CFStringCreateWithFormat(NULL,NULL,CFSTR("%@"),v);
        char buf[256]; if (CFStringGetCString(s,buf,256,kCFStringEncodingUTF8)) printf(" %s", buf);
        else printf(" <binary %lu>", (unsigned long)CFDataGetLength(v)?0:0);
        CFRelease(s);
    }
}
static void dump(CFDictionaryRef d, int depth) {
    CFIndex n = CFDictionaryGetCount(d);
    const void **keys = malloc(n*sizeof(void*)), **vals = malloc(n*sizeof(void*));
    CFDictionaryGetKeysAndValues(d, keys, vals);
    for (CFIndex i=0;i<n;i++) {
        for (int j=0;j<depth;j++) printf("  ");
        char kb[128]; CFStringRef k = (CFStringRef)keys[i];
        if (!CFStringGetCString(k,kb,128,kCFStringEncodingUTF8)) snprintf(kb,128,"<key>");
        printf("%s =", kb); dumpval(vals[i], depth); printf("\n");
    }
    free(keys); free(vals);
}
int main(void) {
    io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOTimeSyncDomain"));
    if (!s) { printf("no match\n"); return 1; }
    printf("entry: 0x%x\n", s);
    CFDictionaryRef p=NULL;
    if (KERN_IS_ERROR(KERN_SUCCESS)) {}
    kern_return_t kr = IORegistryEntryCreateCFProperties(s, (CFMutableDictionaryRef*)&p, kCFAllocatorDefault, 0);
    if (kr != KERN_SUCCESS || !p) { printf("props failed 0x%x\n", kr); return 2; }
    dump(p, 0);
    CFRelease(p);
    IOObjectRelease(s);
    return 0;
}
