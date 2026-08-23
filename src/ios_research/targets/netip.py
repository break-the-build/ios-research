"""Mock IP-stack input-path research targets (mDNS/DHCPv6/ICMPv6/EDNS0).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes. No
sockets, no network binding, no packet injection.

Normalized mock message (after each target's magic bytes)::

    [declared_length u16 BE][rr_type u8][opt_flags u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# rr-type / flag tags that trigger deterministic defect paths
_NULL_TYPE = 0x00        # null rdata pointer dereference
_CONFUSION_TYPE = 0xC0   # record reinterpreted as incompatible state
_ASSERT_TYPE = 0x7E      # resource-record invariant assertion


class NetIpTarget(Target):
    kind = "netip"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock IP-stack record parser; no sockets or network access"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 2])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.netip(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        rr_type = body[2]
        opt_flags = body[3]
        payload = body[4:]
        return {"declared": declared, "rr_type": rr_type,
                "opt_flags": opt_flags, "payload": payload}

    def _crash(self, data, classification, symbols, detail):
        module = f"{self.format_name}Parser"
        diag = diagnostics.build(data, classification, module, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        fields = self._extract(data)
        if fields is None:
            return ExecResult(outcome=Outcome.REJECTED,
                              detail=f"not a valid {self.format_name} record",
                              duration_ms=1)

        declared = fields["declared"]
        payload = fields["payload"]

        if declared >= 0xF000:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="declared record length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["parse_message", "decode_name", "read_rdata"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["rr_type"] == _NULL_TYPE:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["parse_message", "resolve_owner", "deref_rdata"],
                "record type 0 dereferences a null rdata pointer")
        if fields["opt_flags"] & 0x01:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["parse_message", "release_name", "use_name"],
                "name buffer used after release during decompression")
        if fields["rr_type"] == _CONFUSION_TYPE:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["parse_message", "reinterpret_record"],
                "resource record reinterpreted as incompatible class/type state")
        if fields["rr_type"] == _ASSERT_TYPE:
            return self._crash(
                data, "ASSERTION",
                ["parse_message", "assert_rr_invariant"],
                "resource-record invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} message decoded", duration_ms=1)


class MdnsTarget(NetIpTarget):
    target_id = "netip:mdns-record"
    format_name = "MDNS"
    description = "Mock mDNS/DNS resource-record parser (CI-safe)"
    formats = ("mdns-record",)
    magic = b"MDNS"


class DhcpV6OptTarget(NetIpTarget):
    target_id = "netip:dhcpv6-opt"
    format_name = "DHCPV6_OPT"
    description = "Mock DHCPv6/RA option-chain parser (CI-safe)"
    formats = ("dhcpv6-opt",)
    magic = b"DHC6"


class Icmp6InfoTarget(NetIpTarget):
    target_id = "netip:icmp6-info"
    format_name = "ICMP6_INFO"
    description = "Mock ICMPv6 informational-payload parser (CI-safe)"
    formats = ("icmp6-info",)
    magic = b"ICP6"


class EdnsTarget(NetIpTarget):
    target_id = "netip:edns"
    format_name = "EDNS"
    description = "Mock EDNS0 OPT pseudo-record parser (CI-safe)"
    formats = ("edns",)
    magic = b"EDNS"


NETIP_TARGETS = {
    "netip:mdns-record": MdnsTarget,
    "netip:dhcpv6-opt": DhcpV6OptTarget,
    "netip:icmp6-info": Icmp6InfoTarget,
    "netip:edns": EdnsTarget,
}
