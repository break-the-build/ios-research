"""tools/beta/lane_diff.py: which lane's iOS binaries changed between builds."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "beta"))
import lane_diff  # noqa: E402


def _image(root: Path, name: str, exports: list[str], starts: list[int],
           tokens: dict[str, list[str]]) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "exports.txt").write_text(
        "".join(f"0x{1000 + i:x}: (regular) {e}\n" for i, e in enumerate(exports)))
    (d / "starts.txt").write_text("".join(f"0x{s:016X}\n" for s in starts))
    (d / "fingerprint.json").write_text(json.dumps(
        {"ok": True, "data": {"matches": {fam: [{"hits": 1, "token": t} for t in toks]
                                          for fam, toks in tokens.items()}}}))


def _build(root: Path, build: str, images: dict) -> Path:
    d = root / build
    d.mkdir(parents=True)
    (d / "manifest.json").write_text("{}")
    for name, spec in images.items():
        _image(d, name, *spec)
    return root


def test_lanes_rank_by_what_changed(tmp_path):
    old = _build(tmp_path / "old", "24B119__iPhone14,2", {
        "RawCamera": (["_A", "_B"], [0, 16, 48, 64], {"imageio": ["tiff"]}),
        "CoreText": (["_C"], [0, 32, 64], {}),
    })
    new = _build(tmp_path / "new", "24C5027a__iPhone14,2", {
        # one function grew (16 -> 20 bytes), one export added, a new token
        "RawCamera": (["_A", "_B", "_NewDecoder"], [0, 20, 52, 68],
                      {"imageio": ["tiff", "jxl "]}),
        "CoreText": (["_C"], [100, 132, 164], {}),        # moved, unchanged
    })
    result = lane_diff.diff(old, new)
    raw, ct = result["images"]["RawCamera"], result["images"]["CoreText"]
    assert raw["exports_added"] == ["_NewDecoder"] and raw["tokens_added"] == ["imageio:jxl "]
    assert raw["functions_changed_est"] == 1
    assert ct["functions_changed_est"] == 0 and not ct["exports_added"]
    assert result["lanes"][0]["lane"] == "1 DNG / camera RAW"
    md = lane_diff.markdown(result)
    assert "24B119__iPhone14,2 → 24C5027a__iPhone14,2" in md and "_NewDecoder" in md


def test_missing_images_are_reported_not_fatal(tmp_path):
    old = _build(tmp_path / "old", "a", {"ImageIO": (["_X"], [0, 8], {})})
    new = _build(tmp_path / "new", "b", {})
    result = lane_diff.diff(old, new)
    assert result["images"]["ImageIO"]["present"] == [True, False]
    assert result["images"]["ImageIO"]["exports_removed"] == ["_X"]
