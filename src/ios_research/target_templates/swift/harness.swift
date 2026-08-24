/*
 * Custom ios-research target harness ({name}) — Swift, byte input.
 *
 * Platform fallback driver: Apple's toolchain ships no libFuzzer runtime, so
 * this template uses a simple argv-based `run_one_input` main instead of a
 * libFuzzer entry point (docs/TARGET-SDK.md). Same OOB/WRT/UAF marker scheme
 * as the C template; build with -sanitize=address (the declared sanitizer
 * profile) so the findings are caught and reported. Authorized research only.
 */
import Foundation

func contains(_ data: [UInt8], _ marker: [UInt8]) -> Bool {
    guard marker.count <= data.count else { return false }
    return data.contains(marker)
}

func parseRecord(_ data: [UInt8]) -> Int32 {
    guard let raw = malloc(16) else { return 1 }
    memset(raw, 0, 16)
    let buf = raw.assumingMemoryBound(to: UInt8.self)
    let oob = Array("OOB".utf8), wrt = Array("WRT".utf8), uaf = Array("UAF".utf8)
    if contains(data, oob) {
        let v = buf[16 + (data.count & 0x3F)]      // heap OOB read (ASan)
        _ = v
    } else if contains(data, wrt) {
        buf[64] = 0x41                             // heap OOB write (ASan)
    } else if contains(data, uaf) {
        free(raw)
        let v = buf[0]                             // use-after-free (ASan)
        _ = v
        return 0
    }
    free(raw)
    return 0
}

func runOneInput(_ path: String) -> Int32 {
    guard let data = FileManager.default.contents(atPath: path) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        return 2
    }
    return parseRecord([UInt8](data))
}

// Driver: `harness <file>` — one input per process, like the libFuzzer mode.
let args = CommandLine.arguments
if args.count < 2 {
    FileHandle.standardError.write(Data("usage: harness <input-file>\n".utf8))
    exit(2)
}
exit(runOneInput(args[1]))
