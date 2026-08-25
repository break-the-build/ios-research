# mDNSResponder Scoping & Radio-Path Follow-up (#228 §1)

Status: **scoping documents** — mDNSResponder record parsing is actionable on
this host today; AWDL/BT radio-path fuzzing stays parked until injection
hardware exists.

## 1. mDNSResponder record-parsing fuzz plan

**Surface**: `mDNSResponder` parses attacker-influencable resource records
from every mDNS/DNS-SD packet it accepts. On macOS the daemon
(`/usr/libexec/mDNSResponder`) is launchd-managed, so crashes are safe to
observe (same property that made the usbmuxd probe viable).

### Path A — loopback unicast first (no hardware, start here)

mDNSResponder answers *legacy unicast queries* on UDP 5353 from any local
source port, and its response/query **record parser** runs before any
network-origin trust decision. A loopback prober can therefore reach the
parsing code without touching the LAN:

1. Craft mDNS-format datagrams (header + question/answer/additional
   sections) with mutation focus on: compressed-name pointers (loops,
   forward offsets), rdata length vs actual, TXT/SRV/PTR record shapes,
   OPT/EDNS pseudo-records, oversized label chains, zero-question responses.
2. Send to `127.0.0.1:5353` from an ephemeral source port (legacy-unicast
   path); vary QCLASS/QTYPE/QDCOUNT fields per round.
3. Liveness oracle after each round: valid ` PTR _services._dns-sd._udp.local`
   browse or `dnctl`-style health query; daemon silence followed by return =
   launchd restart = crash signal (mirror `tools/probe/usbmuxd_probe.py`).
4. Rate-limit and namespace-isolate: unique `iosr-probe.local` names, no
   multi-second floods, loopback interface only.

### Path B — OSS-code harness (deep coverage)

`mDNSResponder` is open source (Apple's GitHub mirror). Build the core
record parsers (`mDNSCoreReceiveResponse`, `DNSMessage` walking,
`GetLargeResourceRecord`) as a libFuzzer target:

- Seeds: passive captures of real LAN mDNS traffic (own network, own devices),
  converted to raw message buffers.
- Dictionaries: RR type/class constants, `_services._dns-sd._udp`,
  known device-name patterns.
- Findings replayed against the live daemon over Path A for confirmation;
  only confirmed daemon-level effects get imported into the crash store.

### Safety boundary

Loopback and own-LAN only; never emit spoofed-source packets toward third
parties; stop if any non-probe device reacts. This matches the framework's
authorized-research boundary (`SECURITY.md`).

## 2. AWDL / Bluetooth radio-path fuzzing — parked follow-up

Out of scope until injection hardware is acquired. What unlocks it:

| Surface | Requirement | Notes |
|---|---|---|
| AWDL (Apple Wireless Direct Link) | 802.11 ac PHY monitor+inject NIC with firmware permitting arbitrary action frames (historically Broadcom-based SDR/modded radios) | AWDL is proprietary; alignment/election state machines are the juicy parsers. macOS host cannot self-inject without such hardware |
| Bluetooth (BT/LE classic services) | Hardware sniffer with follow ability (nRF52-family sniffer, Ellisys) plus an inject-capable stack | L2CAP/SDP/GATT record parsing reachable only with over-air frame control |

When hardware arrives: reuse the campaign pattern proven this quarter —
record legitimate traffic for seeds, mutate at the *parser* layer first
(harness from any available OSS implementations), confirm against the real
radio stack last, and treat daemon/service restarts as the crash signal.
These surfaces sit inside Apple's bounty-relevant categories once reachable
(proximity attack surface), which is why they stay tracked rather than cut.
