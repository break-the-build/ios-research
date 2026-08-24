"""Mock geodata/workout importer research targets (GPX / FIT / GeoJSON / tiles).

Mock parser targets following the audio-module contract: deterministic,
CI-safe, and exercising the standard ``prepare/execute/collect/cleanup``
lifecycle. They only *parse bytes* and report normalized outcomes using
**synthetic coordinates**. No person or device is tracked; no location,
workout, or health data is read, stored, or transmitted.

Normalized mock import record (after each target's magic bytes)::

    [declared_length u16 BE][geom_kind u8][pt_scale u8][payload...]
"""

from __future__ import annotations

from .base import ExecResult, Outcome, Target
from . import diagnostics, _structure

# geometry-kind tags that trigger deterministic defect paths
_NULL_KIND = 0x00        # null track-record dereference
_CONFUSION_KIND = 0xC0   # geometry reinterpreted as incompatible state
_ASSERT_KIND = 0x7E      # coordinate-bounds invariant assertion


class GeoImportTarget(Target):
    kind = "geo"
    mock = True
    magic = b""
    format_name = ""

    def describe(self):
        d = super().describe()
        d["note"] = "mock geodata importer parser; synthetic coordinates only"
        return d

    def seeds(self) -> list[bytes]:
        payload = b"data"
        header = len(payload).to_bytes(2, "big") + bytes([1, 8])
        return [self.magic + header + payload]

    def structure_mutate(self, data: bytes, rng):
        return _structure.geo(self.magic, data, rng)

    def _extract(self, data: bytes):
        m = self.magic
        if len(data) < len(m) + 4 or data[:len(m)] != m:
            return None
        body = data[len(m):]
        declared = int.from_bytes(body[0:2], "big")
        geom_kind = body[2]
        pt_scale = body[3]
        payload = body[4:]
        return {"declared": declared, "kind": geom_kind,
                "scale": pt_scale, "payload": payload}

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
                              detail="declared import length exceeds time budget",
                              duration_ms=1000)
        if declared > len(payload):
            return self._crash(
                data, "OUT_OF_BOUNDS_READ",
                ["import_geodata", "walk_points", "read_point_data"],
                f"declared_length={declared} exceeds payload={len(payload)}")
        if fields["scale"] == 0:
            return self._crash(
                data, "INTEGER_ERROR",
                ["import_geodata", "rescale_points", "div_by_scale"],
                "point scale 0 causes divide-by-zero rescaling coordinates")
        if fields["kind"] == _NULL_KIND:
            return self._crash(
                data, "NULL_DEREFERENCE",
                ["import_geodata", "resolve_geometry", "deref_track"],
                "geometry kind 0 dereferences a null track record")
        if b"\xde\xad" in payload:
            return self._crash(
                data, "USE_AFTER_FREE",
                ["import_geodata", "release_tile", "use_tile"],
                "tile buffer used after release during import")
        if fields["kind"] == _CONFUSION_KIND:
            return self._crash(
                data, "TYPE_CONFUSION",
                ["import_geodata", "reinterpret_geometry"],
                "geometry reinterpreted as incompatible coordinate system")
        if fields["kind"] == _ASSERT_KIND:
            return self._crash(
                data, "ASSERTION",
                ["import_geodata", "assert_coord_bounds"],
                "coordinate-bounds invariant assertion failed")
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"{self.format_name} geodata imported",
                          duration_ms=1)


class GpxTarget(GeoImportTarget):
    target_id = "geo:gpx"
    format_name = "G_GPX"
    description = "Mock GPX trackpoint-sequence importer parser (CI-safe)"
    formats = ("gpx",)
    magic = b"GGPX"


class FitTarget(GeoImportTarget):
    target_id = "geo:fit"
    format_name = "G_FIT"
    description = "Mock FIT message-header/table importer parser (CI-safe)"
    formats = ("fit",)
    magic = b"GFIT"


class GeoJsonTarget(GeoImportTarget):
    target_id = "geo:geojson"
    format_name = "G_GSJ"
    description = "Mock GeoJSON nested-geometry importer parser (CI-safe)"
    formats = ("geojson",)
    magic = b"GGSJ"


class TileProtoTarget(GeoImportTarget):
    target_id = "geo:tile-proto"
    format_name = "G_TIL"
    description = "Mock map-tile protobuf wire-format parser (CI-safe)"
    formats = ("tile-proto",)
    magic = b"GTIL"


GEO_TARGETS = {
    "geo:gpx": GpxTarget,
    "geo:fit": FitTarget,
    "geo:geojson": GeoJsonTarget,
    "geo:tile-proto": TileProtoTarget,
}
