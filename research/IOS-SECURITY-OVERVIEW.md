# iOS Security Overview (research notes)

**Purpose:** shared reference for target selection and attack-surface mapping in
`ios-research`. Describes the platform's architecture, security mechanisms,
protocols, and capability model as of the iOS 26 generation (2025–2026), with an
emphasis on where *untrusted input enters the system*.

**Scope/safety note.** This document is defensive research context for the
authorized-research framework. It describes published architecture and public
bounty categories; it contains no exploit techniques, payloads, or bypass
guidance. See [SECURITY.md](../SECURITY.md).

Primary sources: Apple Platform Security guide, security.apple.com bounty
pages, Apple security-release notes, and public conference literature. Facts
are stated at the confidence level supported by those sources.

---

## 1. Hardware layer

| Component | Role | Research relevance |
|---|---|---|
| Application Processor (AP) | Runs XNU + userspace; A/M-series SoC | Primary exploitation endpoint ("application processor" outcome) |
| Secure Enclave (SEP) | Isolated RISC-based coprocessor w/ its own SEPOS, boot chain, crypto engine; holds UID/GID fused keys, biometric templates, passcode verification | Trust anchor for data protection; software-reach surface is narrow (mailbox/IPC protocol) |
| Baseband/modem | Separate CPU+RTOS for cellular (LTE/5G, IMS/SIP, SMS/RCS decode) | Historically separate bounty scope; out of framework reach |
| Wi-Fi/BT combo radio | Firmware + kernel driver (IO80211Family) + userspace daemons (`wifid`, `bluetoothd`) | "Wireless proximity" bounty entry point |
| UWB (U1/N1) | Secure ranging coprocessor (Nearby Interaction) | Proximity surface |
| NFC controller | Reader/emulation modes, background tag read | Proximity surface |
| ANE / GPU / ISP | Accelerators with their own firmware/drivers | IOKit user-client surface from apps |

## 2. Kernel (XNU) and enforcement layers

XNU = Mach (IPC, VM, scheduling) + BSD (POSIX, network stack) + IOKit
(C++ driver model; DriverKit moves drivers to userspace on modern OSs).
Kernel attack surface from a sandboxed process: syscalls, Mach ports to
kernel-owned objects, `vm_map` copy paths, IOKit/DriverKit user clients,
shared memory (`IOSurface`), filesystem/APFS ioctls, socket option parsing.

Key hardening layers (evolution timeline):

| Era | Mechanism | Notes |
|---|---|---|
| 2016–2017 | KTRR/KPP era ends | Kernel text protection superseded below |
| A12 / iOS 12 (2018) | PAC (arm64e), PPL introduced | Pointer Authentication on return addresses/function pointers; Page Protection Layer makes kernel page tables & read-only data immutable from EL1 |
| ~A15 (2021) | SPTM/TXM | Secure Page Table Monitor + Trusted Execution Monitor take over PPL/hypervisor roles; also BTI-era branch protections |
| iOS 14 (2020) | Parser separation begins at scale | BlastDoor service for inbound iMessage parsing; media parsing split to `mediaparserd`; WebKit multi-process model matures |
| iOS 17 (2023) | `__AUTH`/`__AUTH_CONST` segments | Authenticated pointer/data sections in binaries; x18-style platform register discipline |
| Sept 2025 (iPhone 17/A19 class) | **MIE — Memory Integrity Enforcement** | Always-on Enhanced MTE (ARM memory tagging) applied across most OS *and third-party* processes, plus dedicated tag-cache hardware; Apple positions it against the full exploit chain, not individual bugs |
| iOS 26.x (2025–26) | Background Security Improvements (BSI) | Standalone, automatically-applied security patches decoupled from full OTA trains |

Implication for researchers: post-MIE devices invalidate many legacy
exploitation assumptions; discovery vs confirmation device strategy must track
the mitigation matrix (see ATTACK-SURFACE-MAP §5 and issue: MIE provenance probe).

## 3. Boot chain and code signing

1. **Boot ROM** (immutable) verifies the next stage against fused keys.
2. **iBoot/SPTM-stage loaders** verify kernel + trust caches.
3. **Trust cache**: hashes of allowed kernel/system binaries; AMFI
   (Apple Mobile File Integrity) enforces code signing, entitlement validity,
   and library validation at runtime.
4. **CoreTrust** verifies signing chains in a hardware-anchored path.
5. Third-party apps: provisioning profile + team signature; Developer Mode
   gates locally-built code; macOS additionally uses notarization/quarantine
   (Gatekeeper — macOS-only bounty category).
6. All executable memory is W^X; JIT requires entitlements (disabled under
   Lockdown Mode); dyld shared cache reduces exposed unique code.

## 4. Userspace architecture and trust boundaries

- **launchd** starts system daemons; each has a per-service **Seatbelt
  sandbox profile** compiled into the kernel-enforced MAC policy.
- **SpringBoard** is the UI shell; lock-screen/notification/widget rendering
  is a physical-access surface.
- **Parser-separation pattern** (post-2014 "sandblaster"-class lessons):
  untrusted formats are decoded in dedicated least-privilege services before
  results cross into privileged consumers:
  - iMessage → **BlastDoor**-class sandboxed decoder
  - audio/video/image containers → **`mediaparserd`**, ImageIO worker paths
  - web content → WebContent/WebKit child processes (browser category)
- **IPC fabric**: Mach ports + XPC everywhere; every daemon exposing an XPC or
  Mach service is a potential local-privesc endpoint (app-sandbox-escape tier).
- **Data protection**: per-file keys wrapped by class keys
  (Complete / CompleteUnlessOpen / CompleteUntilFirstUserAuthentication /
  AfterFirstUnlock); Keychain items carry their own classes; SEP mediates
  key use (biometric gating via Secure Enclave crypto server).
- **Privacy controls**: TCC-style consent (camera/mic/location/photos),
  local-network permission, pasteboard change notifications, privacy
  manifests; on macOS TCC databases are Target-Flag instrumented
  (`integrity_flag`, `tccutil flag check`).

## 5. Networking and protocols (untrusted-input channels)

**IP transport:** CFNetwork / Network.framework; HTTP/2 + HTTP/3(QUIC);
TLS 1.3; App Transport Security defaults. System resolver =
`mDNSResponder` (DNS, mDNS, Bonjour advertisement — historically fuzzed
surface). Private Relay adds Oblivious DoH + relay protocol handling.

**Messaging (zero-click tier):**
- SMS/MMS decode in CommCenter-class daemons.
- **RCS** (since iOS 18): carrier/GSMA interop stack — new parser code
  exposed to messages from arbitrary numbers.
- **iMessage**: APNs-delivered payloads decrypted then parsed by separated
  services; **PQ3** post-quantum ratchet (new protocol implementation,
  2024+) adds fresh state-machine parsing.

**Proximity/radio (proximity tier):**
- Bluetooth: LE advertisements, ATT/GATT, SMP pairing, BR/EDR AVDTP/A2DP/
  HFP RFCOMM; Continuity beacons (Handoff/Instant Hotspot/Find My).
- Wi-Fi: management/action frames, AWDL (time-sync + TLV used by AirDrop/
  AirPlay), WPA3 SAE, 802.1X EAP, Passpoint, **Wi-Fi Aware** (iOS 26 —
  brand-new discovery/data-path stack).
- AirDrop: BLE discovery → AWDL link → HTTPS transfer with identity certs.
- AirPlay receiver: mDNS + RTSP/HTTP session parsing on-device.
- NFC background tag/NDEF reads; UWB ranging exchanges.

**One-click channels:** Safari/WebKit (layout, JS, media, PDF), universal
links/custom URL scheme routing (LaunchServices/SpringBoard), QR-code-launched
links and App Clip invocations, downloads, share-sheet extension inputs.

**Physical (locked-device tier):**
- USB: usbmuxd multiplexing, lockdownd plist service negotiation, backup
  format, crash-log retrieval, AFC; MFi/iAP2 accessory authentication
  challenge parsing; USB-PD/alt-mode negotiation.
- Lock screen rendering of notifications/widgets/live activities/wallet;
  incoming-call (CallKit) UI; Siri while locked (voice-triggered parsing).

**Cloud/services (separate rewards table):** iCloud account data access
($1M tier), CloudKit sync, Keychain sync, Find My encrypted beacon network,
APNs, **Private Cloud Compute** (attested inference protocol with its own
$100K–$1M reward tiers).

## 6. Capabilities and entitlements

- Entitlements are signed assertions; **restricted/platform entitlements**
  (`com.apple.private.*`, IOKit user-client access, network-extension,
  hotspot, NFC, DriverKit families) require Apple platform signatures —
  obtaining one illegitimately is itself a severity amplifier.
- Sandbox profiles + entitlement checks together define the app-side trust
  boundary; escapes are categorized by end-state (kernel control vs access
  to sensitive user data).
- TCC services enumerate protectable user data; on macOS the TCC Target Flag
  demonstrates database modification objectively.

## 7. Lockdown Mode (differential baseline)

Disables JIT, most complex web features, strips most message attachment types
(images excepted, filters stripped), blocks FaceTime calls from non-contacts,
wired connections while locked, configuration profiles, invitation previews,
shared albums. Bounty pays **2× for protections-bypassing issues** (150% combined
with beta). Differential value: any input that crashes a hardened path but not
its normal-mode twin isolates Lockdown-specific code (see issue #60 pipeline).

## 8. Framework mapping (what ios-research can/cannot do)

| Platform layer | Framework fit today |
|---|---|
| Userspace file-format parsers | ✅ mock targets; ✅ real macOS in-process libFuzzer/ASan harnesses (`mac:*`) |
| On-device behavior confirmation | ✅ black-box `.ips` harvest (`ios-device:*`) — confirmation only |
| Radio/baseband/SEP internals | ❌ out of scope (safety boundary); host-side parse-path subsets only (#63) |
| Kernel boundary | ⚠️ host-side syscall/Mach/IOKit harness concepts (#68) on authorized machines |
| WebKit/JSC semantics | ✅ planned external-generator profile (#46) |

## 9. Open questions / watchlist (2026)

1. MIE-era exploitability evidence: what does a defensible report look like on
   tagged-memory hardware? (drives issue: MIE provenance probe)
2. Wi-Fi Aware + RCS + PQ3: three new stacks shipped within ~24 months; n-day
   density likely high (relates #69 IPSW diffing pipeline).
3. BSI patch cadence shortens build-provenance windows for matrix repro (#37).
4. PCC attestation protocol maturity — services-tier rewards without device work.

---

*Related documents: [ATTACK-SURFACE-MAP.md](ATTACK-SURFACE-MAP.md),
[APPLE-BOUNTY-READINESS.md](../docs/APPLE-BOUNTY-READINESS.md),
[RESEARCH-LOG.md](RESEARCH-LOG.md).*
