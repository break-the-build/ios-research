// Device confirmation probe (FINDING-04 pipeline, issue #217).
//
// Launch behavior:
//   1. If Documents/input.bin exists in the app container, open it.
//   2. Otherwise self-test with the bundled benign.aiff + hang.mp3.
//
// The file's magic bytes select the framework API exercised, mirroring the
// mac campaign targets: ImageIO (images), CoreGraphics (PDF), CoreText
// (fonts), AudioToolbox (audio). Verdicts are NSLog'd as "PROBE ..." lines
// so `devicectl ... --console` capture can parse them; the process exits
// after DONE, or spins forever inside the framework if it hangs.
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
@import CoreBluetooth;

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

static NSString *classify_family(NSData *d) {
    const uint8_t *b = (const uint8_t *)d.bytes;
    NSUInteger n = d.length;
    if (n >= 8 && memcmp(b, "IOSRBT", 6) == 0) return @"bluetooth";
    if (n >= 8 && b[0] == 0x89 && memcmp(b + 1, "PNG", 3) == 0) return @"imageio";
    if (n >= 6 && (memcmp(b, "GIF87a", 6) == 0 || memcmp(b, "GIF89a", 6) == 0))
        return @"imageio";
    if (n >= 12 && memcmp(b, "\xff\xd8\xff", 3) == 0) return @"imageio";   // JPEG
    if (n >= 12 && memcmp(b + 4, "ftyp", 4) == 0) return @"imageio";       // HEIC/AVIF
    if (n >= 5 && memcmp(b, "%PDF-", 5) == 0) return @"coregraphics";
    if (n >= 4 && (memcmp(b, "\x00\x01\x00\x00", 4) == 0
                   || memcmp(b, "OTTO", 4) == 0
                   || memcmp(b, "true", 4) == 0
                   || memcmp(b, "ttcf", 4) == 0)) return @"coretext";
    if (n >= 4 && (memcmp(b, "RIFF", 4) == 0 || memcmp(b, "FORM", 4) == 0
                   || memcmp(b, "caff", 4) == 0)) return @"audio";
    if (n >= 3 && memcmp(b, "ID3", 3) == 0) return @"audio";
    if (n >= 2 && b[0] == 0xff && (b[1] & 0xE0) == 0xE0) return @"audio";  // MPEG sync
    return @"unknown";
}

static void open_imageio(NSData *d) {
    CGImageSourceRef src = CGImageSourceCreateWithData((__bridge CFDataRef)d, NULL);
    if (!src) { NSLog(@"PROBE OPEN_FAIL imageio (no source)"); return; }
    size_t count = CGImageSourceGetCount(src);
    for (size_t i = 0; i < count; i++) {
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, i, NULL);
        if (img) CFRelease(img);
    }
    CFRelease(src);
    NSLog(@"PROBE OPEN_OK imageio frames=%zu", count);
}

static void open_coregraphics(NSData *d) {
    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"probe.pdf"];
    [d writeToFile:tmp atomically:YES];
    CGPDFDocumentRef pdf = CGPDFDocumentCreateWithURL(
        (__bridge CFURLRef)[NSURL fileURLWithPath:tmp]);
    if (!pdf) { NSLog(@"PROBE OPEN_FAIL coregraphics (no doc)"); return; }
    size_t pages = CGPDFDocumentGetNumberOfPages(pdf);
    for (size_t i = 1; i <= pages; i++) {
        CGPDFPageRef p = CGPDFDocumentGetPage(pdf, i);
        if (p) CGPDFPageGetBoxRect(p, kCGPDFMediaBox);
    }
    CGPDFDocumentRelease(pdf);
    NSLog(@"PROBE OPEN_OK coregraphics pages=%zu", pages);
}

static void open_coretext(NSData *d) {
    CFArrayRef descs = CTFontManagerCreateFontDescriptorsFromData(
        (__bridge CFDataRef)d);
    if (!descs) { NSLog(@"PROBE OPEN_FAIL coretext (no descriptors)"); return; }
    NSLog(@"PROBE OPEN_OK coretext descriptors=%ld", (long)CFArrayGetCount(descs));
    CFRelease(descs);
}

static void open_audio(NSData *d, NSURL *url) {
    AudioFileID af = NULL;
    OSStatus st = AudioFileOpenURL((__bridge CFURLRef)url,
                                   kAudioFileReadPermission, 0, &af);
    if (st == 0 && af) { AudioFileClose(af);
        NSLog(@"PROBE OPEN_OK audio"); return; }
    NSLog(@"PROBE OPEN_FAIL audio status=%d", st);
}

// On-device Bluetooth-stack probe: scan as central, connect ONLY to the
// research peer's local-name prefix (never to third-party devices), then walk
// its advertised GATT tree — services -> characteristics -> descriptors —
// reading every value. All bytes come from the controlled peer; the phone
// parses them through CoreBluetooth/bluetoothd. Input layout after "IOSRBT":
// [scan window s u32 BE][pad u16]. A safety timer exits cleanly so a silent
// peer can never wedge the app past the bridge's verdict timeout.
@interface BLEProbe : NSObject <CBCentralManagerDelegate, CBPeripheralDelegate>
@property (strong) CBCentralManager *cm;
@property (strong) NSMutableArray<CBPeripheral *> *pending;
@property NSInteger reads;
@property NSInteger descs;
@property NSTimeInterval window;
@end

static dispatch_semaphore_t g_bt_done;

@implementation BLEProbe

- (void)startWithWindow:(NSTimeInterval)window {
    self.pending = [NSMutableArray array];
    self.window = window;
    [self createManager];
    // Self-heal: bluetoothd occasionally wedges state delivery for a bundle
    // after many rapid session attach/detach cycles (state stays .unknown
    // forever). Tear the manager down and build a fresh session once.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                  (int64_t)(8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (self.cm.state == CBManagerStateUnknown) {
            NSLog(@"PROBE bluetooth state stuck unknown; recreating session");
            [self.cm setDelegate:nil];
            self.cm = nil;
            [self createManager];
        }
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                  (int64_t)(window * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSLog(@"PROBE OPEN_OK bluetooth reads=%ld descs=%ld (window expired)",
              (long)self.reads, (long)self.descs);
        if (g_bt_done) dispatch_semaphore_signal(g_bt_done);
    });
}

- (void)createManager {
    dispatch_sync(dispatch_get_main_queue(), ^{
        self.cm = [[CBCentralManager alloc]
                   initWithDelegate:self queue:nil];
        // CBManagerState: 0=unknown 1=resetting 2=unsupported 3=unauthorized
        //                 4=poweredOff 5=poweredOn
        NSLog(@"PROBE bluetooth cm-state=%ld", (long)self.cm.state);
    });
}

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    NSLog(@"PROBE bluetooth state-callback=%ld", (long)central.state);
    if (central.state != CBManagerStatePoweredOn) {
        NSLog(@"PROBE OPEN_FAIL bluetooth state=%ld", (long)central.state);
        return;
    }
    // Scan for everything; connection is name-filtered in didDiscover.
    [central scanForPeripheralsWithServices:nil options:nil];
    NSLog(@"PROBE bluetooth scan-started");
}

- (void)centralManager:(CBCentralManager *)central
 didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary *)advertisementData
                  RSSI:(NSNumber *)RSSI {
    NSString *name = peripheral.name
        ?: advertisementData[CBAdvertisementDataLocalNameKey] ?: @"";
    // Log every discovery unfiltered — RF-neighborhood visibility is half
    // the debugging battle.
    NSLog(@"PROBE adv-hit %@ rssi=%@ adv=%@", name, RSSI,
          advertisementData[CBAdvertisementDataManufacturerDataKey]);
    if (![name hasPrefix:@"IOSR-BT"] || [self.pending containsObject:peripheral])
        return;
    NSLog(@"PROBE peer-match %@", name);
    [self.pending addObject:peripheral];
    peripheral.delegate = self;
    [central connectPeripheral:peripheral options:nil];
}

- (void)centralManager:(CBCentralManager *)central
 didConnectPeripheral:(CBPeripheral *)peripheral {
    NSLog(@"PROBE connected %@", peripheral.name);
    [peripheral discoverServices:nil];
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverServices:(NSError *)error {
    for (CBService *s in peripheral.services) {
        NSLog(@"PROBE service %@", s.UUID.UUIDString);
        [peripheral discoverCharacteristics:nil forService:s];
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverCharacteristicsForService:(CBService *)service
             error:(NSError *)error {
    for (CBCharacteristic *c in service.characteristics) {
        [peripheral readValueForCharacteristic:c];
        if (c.value.length > 0)
            NSLog(@"PROBE char %@ len=%lu",
                  c.UUID.UUIDString, (unsigned long)c.value.length);
        [peripheral discoverDescriptorsForCharacteristic:c];
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
    self.reads++;
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverDescriptorsForCharacteristic:(CBCharacteristic *)characteristic
                             error:(NSError *)error {
    for (CBDescriptor *d in characteristic.descriptors) {
        [peripheral readValueForDescriptor:d];
        self.descs++;
    }
}

- (void)peripheral:(CBPeripheral *)peripheral
didUpdateValueForDescriptor:(CBDescriptor *)descriptor
             error:(NSError *)error {
    NSLog(@"PROBE desc %@ val=%@",
          descriptor.UUID.UUIDString, descriptor.value);
}

@end

static void open_bluetooth(NSData *d) {
    const uint8_t *b = (const uint8_t *)d.bytes;
    NSTimeInterval window = 20.0;
    if (d.length >= 10) {
        uint32_t w = ((uint32_t)b[6] << 24) | ((uint32_t)b[7] << 16)
                   | ((uint32_t)b[8] << 8) | b[9];
        if (w > 0 && w <= 120) window = w;
    }
    NSLog(@"PROBE bluetooth scan-window=%.0fs", window);
    g_bt_done = dispatch_semaphore_create(0);
    // CBCentralManager holds its delegate WEAKLY — the probe must be kept
    // alive for the whole scan window or every callback lands on a zombie.
    static BLEProbe *g_bt_probe;
    g_bt_probe = [BLEProbe new];
    [g_bt_probe startWithWindow:window];
    // Block until the scan window expires — the outer probe() block exits
    // the process on return, which would otherwise kill the async scan
    // before a single central-manager callback fires.
    dispatch_semaphore_wait(g_bt_done,
        dispatch_time(DISPATCH_TIME_NOW,
                      (int64_t)((window + 10) * NSEC_PER_SEC)));
}

static void probe(NSURL *url, NSString *label) {
    NSLog(@"PROBE about-to-open %@", label);
    NSData *d = [NSData dataWithContentsOfURL:url];
    if (!d) { NSLog(@"PROBE ERROR unreadable %@", label); return; }
    NSString *family = classify_family(d);
    NSLog(@"PROBE family=%@ bytes=%lu", family, (unsigned long)d.length);
    if ([family isEqualToString:@"imageio"]) open_imageio(d);
    else if ([family isEqualToString:@"coregraphics"]) open_coregraphics(d);
    else if ([family isEqualToString:@"coretext"]) open_coretext(d);
    else if ([family isEqualToString:@"audio"]) open_audio(d, url);
    else if ([family isEqualToString:@"bluetooth"]) open_bluetooth(d);
    else { open_imageio(d); open_audio(d, url); }
}

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [UIViewController new];
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSURL *docs = [[NSFileManager defaultManager]
            URLForDirectory:NSDocumentDirectory inDomain:NSUserDomainMask
            appropriateForURL:nil create:NO error:nil];
        NSURL *input = [docs URLByAppendingPathComponent:@"input.bin"];
        if ([NSFileManager.defaultManager fileExistsAtPath:input.path]) {
            probe(input, @"input.bin");
        } else {
            probe([NSBundle.mainBundle URLForResource:@"benign"
                                        withExtension:@"aiff"], @"benign.aiff");
            probe([NSBundle.mainBundle URLForResource:@"hang"
                                        withExtension:@"mp3"], @"hang.mp3");
        }
        NSLog(@"PROBE DONE no-hang");
        exit(0);
    });
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
                                 NSStringFromClass([AppDelegate class]));
    }
}
