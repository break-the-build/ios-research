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

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

static NSString *classify_family(NSData *d) {
    const uint8_t *b = (const uint8_t *)d.bytes;
    NSUInteger n = d.length;
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
