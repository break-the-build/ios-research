# iOS Attack Surface Map (authorized-research view)

**Purpose:** inventory of iOS attack surfaces relevant to the Apple Security
Bounty, evaluated for risk and mapped onto what `ios-research` can exercise
today. Companion to [IOS-SECURITY-OVERVIEW.md](IOS-SECURITY-OVERVIEW.md).
This is a research-planning artifact — it catalogs *entry points* and
*outcomes*; it contains no exploit material (see [SECURITY.md](../SECURITY.md)).

---

## 1. Method

Each surface is scored on four axes (1–5 unless noted):

| Axis | Meaning |
|---|---|
| **R** reachability | 5 zero-click/remote · 4 one-click · 3 proximity · 2 physical/locked · 1 local-app only |
| **S** outcome severity | 5 kernel/app-processor control · 4 sandbox escape w/ data access · 3 code-exec in hardened sandbox · 2 sensitive-data exposure · 1 DoS-only |
| **N** novelty | 5 fresh stack (<24 mo) · 3 moderately researched · 1 heavily hunted (WebKit-class) |
| **F** framework fit (0–3) | what our pipeline can exercise today: mock / mac-in-process / on-device confirm |

**EV-proxy = R × S × N × F** (max 300). It ranks research direction, not
reward probability; bounty reward tiers are listed separately.

## 2. Bounty category → outcome mapping

From security.apple.com/bounty/categories (2026):

| Category (entry point) | End state | Max reward | Target Flag required |
|---|---|---|---|
| Network, no user interaction | Kernel control | $2,000,000 | ✅ Commpage |
| Network, no user interaction | User-space control | $350,000 | ✅ Commpage |
| Network, after interaction | Kernel control | $1,000,000 | ✅ |
| Wireless proximity (Apple radios) | Application processor | $1,000,000 | ✅ |
| Physical access, locked device | Sensitive data access | $500,000 | — |
| App sandbox escape | Kernel | $500,000 | ✅ |
| App sandbox escape | Sensitive data | $100,000 | — |
| Browser (Safari) | Kernel | $1,000,000 | ✅ |
| Browser | WebContent sandbox escape | $300,000 | ✅ |
| Browser | WebContent code execution | $10,000 | — |
| Services: iCloud account data | Unauthorized access | $1,000,000 | — |
| PCC | Unsigned code exec in image / request data | $1,000,000 / $250,000 | — |
| macOS only | Gatekeeper bypass / TCC capture / sandbox escape | $100K / $10K / $5K | TCC flag |
| Bonuses | Beta +50% · Lockdown Mode +100% · both +150% | — | — |

Demonstration mechanics that reports must satisfy (drives evidence tooling):
**Commpage Target Flags** (`_COMM_PAGE_ASB_TARGET_VALUE/+0x320`,
`_COMM_PAGE_ASB_TARGET_ADDRESS/+0x328`, `…KERN_VALUE/+0x330`,
`…KERN_ADDRESS/+0x338`) prove register-control / arbitrary-RW / PC-control via
crash-log register & fault-address inspection; full 64-bit register control
earns the max, 32–64-bit partial. **TCC flag**: `tccutil flag check`
detects non-zero `integrity_flag`.

## 3. Surface inventory

### Tier Z — network, zero-click (highest tier)

| ID | Surface | Components/formats | Precedent bug classes | Reward tier | R | S | N | F | EV |
|----|---------|--------------------|-----------------------|-------------|---|---|---|---|----|
| Z1 | iMessage/SMS/MMS/RCS decode | BlastDoor-class decoder, CommCenter; text, attachments, CPIM/RCS payloads | memory corruption in parsers, protocol state machines | $350K–$2M | 5 | 5 | 3–4 (RCS new) | 1–2 | 75–100 |
| Z2 | Link-preview/metadata fetchers | LinkPresentation, URL metadata fetch (fires without click) | parser + network fetch races | $350K+ | 5 | 4 | 3 | 1 | 60 |
| Z3 | Mail MIME/attachment pipeline | MIME tree walkers, calendar/vCard invite parsers | classic memory corruption | $350K+ | 5 | 4 | 3 | 1 | 60 |
| Z4 | Push payload handling (APNs) | notification payload decode before display | JSON/plist parser edge cases | $350K+ | 5 | 4 | 3 | 1 | 60 |
| Z5 | Voicemail/shared-album auto-fetch media | mediaparserd/ImageIO on auto-downloaded content | ImageIO/media container bugs | $350K+ | 5 | 4 | 2 | 3 | 120 |
| Z6 | FaceTime pre-answer signaling | CallKit/SIP-like session setup before accept | signaling parse/state bugs | $350K+ | 5 | 4 | 4 | 1 | 80 |
| Z7 | IP-stack input path | mDNSResponder records, DHCPv6/RA options, ICMPv6 info | resolver/parser memory bugs | up to kernel tier | 5 | 5 | 3 | 2 | 150 |
| Z8 | Wi-Fi Aware stack (iOS 26) | discovery + datapath frames | brand-new code | kernel/userspace tiers | 5 | 5 | 5 | 1 | 125 |
| Z9 | iMessage PQ3 ratchet | post-quantum handshake/state machine | protocol state-machine logic | userspace tier | 5 | 4 | 5 | 1 | 100 |

### Tier O — network, one-click

| ID | Surface | Components | Notes | R | S | N | F | EV |
|----|---------|-----------|-------|---|---|---|---|----|
| O1 | WebKit/JSC browsing | JS engine, layout, media, PDF | most-hunted surface alive; #46 covers tooling | 4 | 3–5 | 1 | 2–3 | 30–60 |
| O2 | Universal links / URL schemes / QR→App Clips | LaunchServices/SpringBoard routing | logic flaws + parser edges | 4 | 3 | 3 | 2 | 72 |
| O3 | Downloads/file-handling flows | quarantine-equivalents, document pickers | lower ceiling on iOS | 4 | 2 | 3 | 2 | 48 |

### Tier P — wireless proximity (Apple radios)

| ID | Surface | Components | R | S | N | F | EV |
|----|---------|-----------|---|---|---|---|----|
| P1 | BT LE/BREDR stacks (adv, ATT/GATT, SMP, AVDTP/HFP) | bluetoothd + driver paths | 3 | 5 | 3 | 1–2 (#63) | 45–90 |
| P2 | AWDL/AirDrop/AirPlay receiver | action-frame TLVs, mDNS, RTSP/HTTP sessions | 3 | 5 | 3 | 2 | 90 |
| P3 | UWB ranging / NFC background tags | Nearby Interaction, CoreNFC NDEF | 3 | 4 | 4 | 1 | 48 |
| P4 | Continuity beacons (Handoff/Find My/instant hotspot) | cross-device record parsing | 3 | 4 | 4 | 2 | 96 |
| P5 | CarPlay/wireless accessory pairing | iAP2 over BT/Wi-Fi | 3 | 4 | 4 | 1 | 48 |

### Tier L — physical access, locked device ($500K tier)

| ID | Surface | Components | R | S | N | F | EV |
|----|---------|-----------|---|---|---|---|----|
| L1 | Lock-screen renderers | notifications/widgets/live activities/wallet quick-view | 2 | 4 | 4 | 2 | 64 |
| L2 | USB accessory negotiation | usbmuxd, lockdownd services, MFi/iAP2 auth challenges, USB-PD | 2 | 4 | 4 | 2 | 64 |
| L3 | Crash-log/backup service paths | backup format, crash report collection | 2 | 3 | 4 | 2 | 48 |
| L4 | Siri/CallKit while locked | voice-triggered parse + call UI actions | 2 | 4 | 3 | 1 | 48 |

### Tier A — app-sandbox escape endpoints (local)

| ID | Surface | Components | R | S | N | F | EV |
|----|---------|-----------|---|---|---|---|----|
| A1 | Exposed XPC/Mach services of system daemons | hundreds of services; each a privesc endpoint | 1 | 5 | 2 | 2 | 20 |
| A2 | Kernel user clients (IOKit/DriverKit) from sandbox | IOGPU, IOSurface, framebuffer classes | 1 | 5 | 2 | 2 (#68) | 20 |
| A3 | IPC-emitting frameworks (share extensions, document providers) | extension payload decode across trust boundary | 1 | 4 | 3 | 2 | 24 |

### Tier K — cloud/services & special categories

| ID | Surface | Notes | EV |
|----|---------|-------|----|
| K1 | iCloud account-data access | services-tier $1M; needs server-side authorization-logic research — outside current framework scope (0) | — |
| K2 | Private Cloud Compute | attestation protocol; $100K–$1M; host-side protocol reasoning possible later | — |
| K3 | macOS-only rewards | Gatekeeper/TCC/App Sandbox — covered by #62 oracles | — |
| K4 | Lockdown Mode differential (+100%) | covered by #60 | — |
| K5 | Beta-window discoveries (+50%) | covered by #56 | — |

## 4. Risk evaluation (ranked directions)

Ranking by EV-proxy × reward-tier leverage, adjusted by feasibility:

| Rank | Surface(s) | Why now | Framework path |
|------|-----------|---------|----------------|
| 1 | **Z7 IP-stack/resolver inputs** | highest R×S with realistic host-side repro (mDNSResponder ships on macOS); kernel-tier upside via crafted records/options | mac harness profile + #57 stream transport |
| 2 | **Z8/Z9 new stacks (Wi-Fi Aware, PQ3, RCS)** | novelty 5/5 — least-audited code shipped recently; even userspace-tier outcomes are strong | target profiles + n-day radar (#69) |
| 3 | **P2/P4 proximity app-processor paths** | $1M tier; macOS-ships parsing code enables host fuzzing subset (#63) | #63 harness profiles |
| 4 | **Z1/Z3/Z4 message-channel parsers** | canonical spyware-delivery path; separated-parser design means crash ≠ compromise but evidence-rich | Issue B profiles (filed) |
| 5 | **L1/L2 locked-device surfaces** | dedicated $500K tier, low crowding, on-device confirmation already supported | Issue C profiles (filed) |
| 6 | **O2 link/routing logic** | cheap wins, one-click tier | stateful workflow fuzzer (#39) |
| 7 | **A1/A2 local endpoints** | needed as *chain tail* for max tiers rather than standalone | #44/#45/#68 |
| 8 | K2 PCC | high value, currently no tooling fit | watchlist |

**Chaining reality:** top-tier rewards require chains (entry bug → sandbox
context → escalation → Target-Flag-demonstrated primitive). The framework's
differential + matrix + evidence tooling covers the *reporting* half of
chains; entry-bug discovery coverage per the table above is the gap.

**Mitigation-era risk note:** MIE/EMTE devices change which outcomes are
demonstrable at all; discovery campaigns should stratify devices by mitigation
generation and record it in provenance (Issue D, filed).

## 5. Traceability — issues filed from this map

| New issue | Covers | Distinct from existing work because |
|---|---|---|
| [#84](https://github.com/break-the-build/ios-research/issues/84) — Target-Flag capture detection & taxonomy refresh | §2 mechanics | #58 maps findings→categories; nothing detects commpage/TCC captures in evidence or encodes flag constants/PCC-services tiers |
| [#85](https://github.com/break-the-build/ios-research/issues/85) — network zero-click communication-parser profiles | Z1–Z4, Z6, O2-adjacent | #57 adds transports, #63 is proximity-host-parse, #46 is WebKit; no messaging/MIME/link-preview target family exists |
| [#86](https://github.com/break-the-build/ios-research/issues/86) — locked-device surface profiles | L1–L3 | #38 imports sysdiagnose evidence; nothing exercises lockscreen/lockdownd/iAP2 surfaces |
| [#87](https://github.com/break-the-build/ios-research/issues/87) — on-device MIE provenance probe | mitigation stratification | #67 is a host sanitizer profile; nothing probes/records device mitigation state |

Existing issues already covering other map rows: #46 (O1), #56 (K5), #57
(transports), #59 (n-day context), #60 (K4), #61 (mapper/EV tooling),
#62 (K3), #63 (P1–P3), #68 (A2/kernel), #69 (novel-stack radar).

## 6. Boundary

Out of scope for this framework regardless of EV: baseband firmware, SEP
internals, radio injection/replay against third parties, persistence,
surveillance, credential theft, and any unowned-target operation. All
device work requires explicit authorization (see [SECURITY.md](../SECURITY.md)
and docs/ON-DEVICE-TARGET.md).
