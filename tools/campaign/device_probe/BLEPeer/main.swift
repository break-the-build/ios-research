// BLEPeer — controlled CoreBluetooth peripheral for on-device Bluetooth-stack
// testing (authorized research on your own devices; see SECURITY.md).
//
// The Mac acts as the *attacker-controlled peer*: it advertises mutated
// manufacturer-specific data (Apple company ID 0x004C + fuzzed continuity-
// style sub-elements) and serves a GATT service whose characteristics and
// descriptors carry fuzzed payload bytes. The probe app on the iPhone scans,
// connects, and reads everything — exercising the phone's advertisement /
// ATT / GATT parsing paths with our bytes.
//
// Usage:
//   swift main.swift --duration 600 --interval 5 --corpus DIR --seed N
//
// Logs "PEER ..." lines to stdout (case counter + current adv payload hex).
// Bounded by --duration; exits 0.

import Foundation
import CoreBluetooth

// NOTE: do NOT use Apple's company ID (0x004C) — iOS filters Apple-CID
// advertisements out of third-party app scan delivery (system daemons still
// parse them). Use a registered test CID so the probe app can see the peer.
let APPLE_CID = Data([0xFF, 0xFF])          // little-endian 0xFFFF (test)
let LOCAL_NAME = "IOSR-BT"
let SERVICE_UUID = CBUUID(string: "3A4E0001-11C3-4F2A-9E37-52B7C0DEF001")
let CHAR_BASE = "3A4E0002-11C3-4F2A-9E37-52B7C0DEF0"
let DESC_UUID = CBUUID(string: "3A4E00FF-11C3-4F2A-9E37-52B7C0DEF001")

struct Config {
    var duration: TimeInterval = 300
    var interval: TimeInterval = 5.0
    var corpus: String? = nil
    var seed: UInt64 = 1
    var chars: Int = 6
}

// Deterministic xorshift so runs are reproducible from --seed.
struct Rng {
    var s: UInt64
    mutating func next() -> UInt64 {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s
    }
    mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
    mutating func data(_ n: Int) -> Data {
        var out = Data(capacity: n)
        for _ in 0..<n { out.append(byte()) }
        return out
    }
}

func loadCorpus(_ dir: String) -> [Data] {
    let fm = FileManager.default
    guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { return [] }
    return entries.sorted().compactMap { name in
        let p = (dir as NSString).appendingPathComponent(name)
        guard let d = fm.contents(atPath: p), d.count > 0, d.count <= 512 else { return nil }
        return d
    }
}

// Build one fuzzed advertisement manufacturer-data blob: Apple CID +
// continuity-style header (type/len) + mutated sub-bytes.
func makeAdvPayload(_ rng: inout Rng, _ base: Data?) -> Data {
    var d = APPLE_CID
    if let b = base, b.count >= 2 {
        // keep type/len shape, mutate the state bytes
        d.append(b.prefix(min(b.count, 12)))
        for i in 2..<d.count where rng.next() % 4 == 0 {
            d[i] = rng.byte()
        }
    } else {
        d.append(rng.byte())                       // type
        d.append(UInt8(2 + Int(rng.next() % 10)))  // len
        d.append(rng.data(Int(2 + rng.next() % 10)))
    }
    if d.count > 27 { d = d.prefix(27) }
    return d
}

final class Peer: NSObject, CBPeripheralManagerDelegate {
    let cfg: Config
    var pm: CBPeripheralManager!
    var rng: Rng
    var corpus: [Data]
    var caseNo = 0
    var service: CBMutableService!
    var currentBlob = Data()

    init(cfg: Config) {
        self.cfg = cfg
        self.rng = Rng(s: cfg.seed == 0 ? 0x9E3779B97F4A7C15 : cfg.seed)
        self.corpus = cfg.corpus.flatMap { loadCorpus($0) } ?? []
        super.init()
    }

    func log(_ s: String) {
        print("PEER \(Int(Date().timeIntervalSince1970)) case=\(caseNo) \(s)")
        fflush(stdout)
    }

    func start() {
        pm = CBPeripheralManager(delegate: self, queue: nil)
        RunLoop.main.run(until: Date().addingTimeInterval(cfg.duration))
        log("done cases=\(caseNo)")
        exit(0)
    }

    func nextBlob() -> Data {
        if !corpus.isEmpty {
            currentBlob = corpus[Int(rng.next() % UInt64(corpus.count))]
            // still mutate a few bytes per round
            var m = currentBlob
            for _ in 0..<3 {
                let i = Int(rng.next() % UInt64(max(m.count, 1)))
                if i < m.count { m[i] = rng.byte() }
            }
            return m
        }
        currentBlob = rng.data(32 + Int(rng.next() % 224))
        return currentBlob
    }

    func rebuildService() {
        if let old = service { pm.remove(old) }
        let chrs: [CBMutableCharacteristic] = (0..<cfg.chars).map { i in
            let start = min(i * 16, max(currentBlob.count - 1, 0))
            let len = min(16, currentBlob.count - start)
            let slice = currentBlob.isEmpty
                ? Data([0])
                : currentBlob.subdata(in: start..<(start + max(len, 1)))
            return CBMutableCharacteristic(
                type: CBUUID(string: "\(CHAR_BASE)\(String(format: "%02X", i))"),
                properties: [.read],
                value: slice.isEmpty ? Data([rng.byte()]) : slice,
                permissions: [.readable])
        }
        service = CBMutableService(type: SERVICE_UUID, primary: true)
        service.characteristics = chrs.map { c in
            let ch = CBMutableCharacteristic(
                type: c.uuid, properties: [.read],
                value: c.value, permissions: [.readable])
            ch.descriptors = [CBMutableDescriptor(
                type: DESC_UUID,
                value: rng.data(Int(4 + rng.next() % 28)))]
            return ch
        }
        pm.add(service!)
    }

    func advertiseRound() {
        caseNo += 1
        currentBlob = nextBlob()
        rebuildService()
        let adv = makeAdvPayload(&rng, corpus.first)
        let advData: [String: Any] = [
            CBAdvertisementDataLocalNameKey: LOCAL_NAME,
            CBAdvertisementDataManufacturerDataKey: adv,
            CBAdvertisementDataServiceUUIDsKey: [SERVICE_UUID],
        ]
        pm.stopAdvertising()
        pm.startAdvertising(advData)
        log("adv=\(adv.map { String(format: "%02x", $0) }.joined()) gattlen=\(currentBlob.count) chars=\(cfg.chars)")
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            log("powered-on")
            advertiseRound()
            Timer.scheduledTimer(withTimeInterval: cfg.interval, repeats: true) { [weak self] _ in
                guard let self else { return }
                self.advertiseRound()
            }
        case .poweredOff, .unauthorized, .unsupported:
            log("fatal state=\(peripheral.state.rawValue) (is Bluetooth on?)")
            exit(3)
        default:
            break
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error { log("adv-error \(error.localizedDescription)") }
    }
}

final class ScanTest: NSObject, CBCentralManagerDelegate {
    var cm: CBCentralManager!
    func run() {
        cm = CBCentralManager(delegate: self, queue: nil)
        RunLoop.main.run(until: Date().addingTimeInterval(12))
        print("PEER scan-test done")
        exit(0)
    }
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        print("PEER scan-test state=\(central.state.rawValue)")
        guard central.state == .poweredOn else { return }
        central.scanForPeripherals(withServices: nil, options: nil)
    }
    func centralManager(_ central: CBCentralManager,
                        didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any],
                        rssi RSSI: NSNumber) {
        let name = peripheral.name
            ?? (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? ""
        print("PEER scan-test hit name=\(name) rssi=\(RSSI)")
    }
}

final class Churn: NSObject, CBPeripheralManagerDelegate {
    var pm: CBPeripheralManager!
    var cycles = 0
    var churnMs: Int = 200
    var gattRebuild = false
    var service: CBMutableService? = nil
    var rng = Rng(s: 0x9E3779B97F4A7C15)
    var t0 = Date()
    var fatalAt: Date? = nil
    var recoveredAt: Date? = nil

    func log(_ s: String) {
        print("CHURN +\(Int(Date().timeIntervalSince(t0)))s cycles=\(cycles) \(s)")
        fflush(stdout)
    }

    func start() {
        let a = Array(CommandLine.arguments.dropFirst())
        if let i = a.firstIndex(of: "--churn-ms"), i + 1 < a.count {
            churnMs = Int(a[i + 1]) ?? 200
        }
        if a.contains("--gatt-rebuild") { gattRebuild = true }
        pm = CBPeripheralManager(delegate: self, queue: nil)
        RunLoop.main.run(until: Date().addingTimeInterval(900))
        log("end")
        exit(0)
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        log("state=\(peripheral.state.rawValue)")
        switch peripheral.state {
        case .poweredOn:
            if fatalAt != nil && recoveredAt == nil {
                recoveredAt = Date()
                log("RECOVERED after \(Int(recoveredAt!.timeIntervalSince(fatalAt!)))s")
            }
            if fatalAt == nil {
                Timer.scheduledTimer(withTimeInterval: Double(churnMs) / 1000.0,
                                     repeats: true) { [weak self] _ in
                    guard let self, self.fatalAt == nil else { return }
                    self.cycles += 1
                    self.pm.stopAdvertising()
                    if self.gattRebuild {
                        if let old = self.service { self.pm.remove(old) }
                        let chrs: [CBMutableCharacteristic] = (0..<4).map { i in
                            CBMutableCharacteristic(
                                type: CBUUID(string: "\(CHAR_BASE)\(String(format: "%02X", i))"),
                                properties: [.read],
                                value: self.rng.data(16 + Int(self.rng.next() % 48)),
                                permissions: [.readable])
                        }
                        let svc = CBMutableService(type: SERVICE_UUID, primary: true)
                        svc.characteristics = chrs.map { c in
                            let ch = CBMutableCharacteristic(
                                type: c.uuid, properties: [.read],
                                value: c.value, permissions: [.readable])
                            ch.descriptors = [CBMutableDescriptor(
                                type: DESC_UUID, value: self.rng.data(16))]
                            return ch
                        }
                        self.pm.add(svc)
                        self.service = svc
                    }
                    self.pm.startAdvertising([
                        CBAdvertisementDataLocalNameKey: LOCAL_NAME,
                        CBAdvertisementDataManufacturerDataKey:
                            Data([0xFF, 0xFF, UInt8(self.cycles & 0xFF)])])
                    if self.cycles % 50 == 0 { self.log("churning gatt=\(self.gattRebuild)") }
                }
            }
        case .poweredOff:
            // System sleep reports poweredOff to sessions (pmset-correlated);
            // only fatal if it happens while a caffeinated run holds the
            // machine awake — otherwise pause and resume on poweredOn.
            log("poweredOff (system sleep?) — pausing churn")
            if fatalAt == nil { fatalAt = Date() }
        default:
            log("state-change \(peripheral.state.rawValue)")
        }
    }
}

let args = Array(CommandLine.arguments.dropFirst())
if args.contains("--scan-test") {
    let st = ScanTest()
    st.run()
}
if args.contains("--churn-test") {
    Churn().start()
}
var cfg = Config()
var i = 0
while i < args.count {
    switch args[i] {
    case "--duration": i += 1; cfg.duration = TimeInterval(args[i]) ?? 300
    case "--interval": i += 1; cfg.interval = TimeInterval(args[i]) ?? 5
    case "--corpus":   i += 1; cfg.corpus = args[i]
    case "--seed":     i += 1; cfg.seed = UInt64(args[i]) ?? 1
    case "--chars":    i += 1; cfg.chars = Int(args[i]) ?? 6
    default: break
    }
    i += 1
}
Peer(cfg: cfg).start()
