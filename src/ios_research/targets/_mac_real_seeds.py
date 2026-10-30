"""Real-file seed corpora for the mac-native targets.

Mutation-based fuzzing explores only what its seeds' structure reaches. The
built-in seeds (``_mac_seeds``) are 2-5 synthetic containers of 12-248 bytes
per framework -- 1x1 images, empty audio headers -- so codec paths behind real
structure (tiles, ICC profiles, multiple chunks, AAC magic cookies, font
tables) were never seeded. macOS ships thousands of real files in exactly the
formats these frameworks parse; this module picks a deterministic, diverse,
size-bounded sample of them.

Selection: walk each source root in sorted order, keep files with a matching
extension and 0 < size <= ``max_bytes`` (large files slow every execution),
then round-robin across extensions so one format cannot crowd out the rest,
de-duplicating by content. Same machine + same arguments => same seeds.
"""

from __future__ import annotations

import hashlib
import os

Sources = dict[str, tuple[tuple[str, ...], tuple[str, ...]]]

REAL_SEED_SOURCES: Sources = {
    "imageio": (
        ("/System/Library/CoreServices/CoreTypes.bundle",
         "/System/Library/Desktop Pictures",
         "/System/Library/PrivateFrameworks"),
        (".png", ".jpg", ".jpeg", ".gif", ".heic", ".tif", ".tiff", ".icns",
         ".bmp", ".webp", ".dng"),
    ),
    "coretext": (
        ("/System/Library/Fonts", "/Library/Fonts"),
        (".ttf", ".otf", ".ttc"),
    ),
    "audiotoolbox": (
        ("/System/Library/Sounds",
         "/System/Library/PrivateFrameworks/ToneLibrary.framework",
         "/System/Library/Components"),
        (".aiff", ".aif", ".caf", ".m4r", ".m4a", ".mp3", ".wav", ".aac"),
    ),
    "coregraphics": (
        ("/System/Library", "/Library/Documentation"),
        (".pdf",),
    ),
}

DEFAULT_LIMIT = 200
DEFAULT_MAX_BYTES = 256 * 1024
CANDIDATES_PER_SEED = 4          # stop walking once this many candidates per seed exist


def _candidates(roots: tuple[str, ...], exts: tuple[str, ...], max_bytes: int,
                wanted: int) -> dict[str, list[str]]:
    """Matching paths grouped by extension, gathered in sorted walk order."""
    groups: dict[str, list[str]] = {ext: [] for ext in exts}
    found = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                ext = os.path.splitext(name)[1].lower()
                if ext not in groups:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if 0 < size <= max_bytes:
                    groups[ext].append(path)
                    found += 1
            if found >= wanted:
                return groups
    return groups


def real_file_seeds(key: str, *, sources: Sources | None = None,
                    limit: int = DEFAULT_LIMIT,
                    max_bytes: int = DEFAULT_MAX_BYTES) -> list[bytes]:
    """Up to ``limit`` distinct real files for target ``key`` ([] if none/unknown)."""
    roots, exts = (sources or REAL_SEED_SOURCES).get(key, ((), ()))
    if limit <= 0 or not roots:
        return []
    groups = _candidates(roots, exts, max_bytes, limit * CANDIDATES_PER_SEED)
    queues = [paths for _ext, paths in sorted(groups.items()) if paths]
    seeds: list[bytes] = []
    seen: set[str] = set()
    while queues and len(seeds) < limit:
        for queue in list(queues):
            if not queue:
                queues.remove(queue)
                continue
            path = queue.pop(0)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(max_bytes + 1)
            except OSError:
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen or not data or len(data) > max_bytes:
                continue
            seen.add(digest)
            seeds.append(data)
            if len(seeds) >= limit:
                break
    return seeds
