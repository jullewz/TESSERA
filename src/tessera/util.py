"""Small, dependency-free helpers: sizes, durations, paths and canonical JSON."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from typing import Any

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$")
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": 1000,
    "kb": 1000,
    "kib": 1024,
    "m": 1000**2,
    "mb": 1000**2,
    "mib": 1024**2,
    "g": 1000**3,
    "gb": 1000**3,
    "gib": 1024**3,
    "t": 1000**4,
    "tb": 1000**4,
    "tib": 1024**4,
}


def parse_size(value: str | int) -> int:
    """Parse ``"512MiB"``, ``"2 GB"`` or ``1024`` into a byte count."""
    if isinstance(value, bool):
        raise ValueError("size must be a number or a string like '512MiB'")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("size must not be negative")
        return value
    match = _SIZE_RE.match(value)
    if not match:
        raise ValueError(f"invalid size {value!r}, expected e.g. '512MiB'")
    number, unit = match.groups()
    factor = _SIZE_UNITS.get(unit.lower())
    if factor is None:
        raise ValueError(f"unknown size unit {unit!r} in {value!r}")
    return int(float(number) * factor)


def format_size(num_bytes: int) -> str:
    """Human-readable binary size, e.g. ``1.5 MiB``."""
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"  # pragma: no cover


def format_duration(seconds: float) -> str:
    """Compact duration, e.g. ``850 ms``, ``4.2 s`` or ``3m 05s``."""
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs:02d}s"


def expand_path(value: str) -> str:
    """Expand ``~`` and environment variables, then make the path absolute."""
    return os.path.abspath(os.path.expandvars(os.path.expanduser(value)))


def match_path(path: str) -> str:
    """Normalise a native path for pattern matching (forward slashes)."""
    return path.replace("\\", "/")


def safe_path(path: str) -> str:
    """Return a path string that always encodes to UTF-8.

    POSIX file names are arbitrary bytes. Python decodes undecodable bytes
    as lone surrogates, which SQLite and JSON reject. Such names are mapped
    deterministically to backslash escapes so every scan stores them the
    same way.
    """
    try:
        path.encode("utf-8")
        return path
    except UnicodeEncodeError:
        return os.fsencode(path).decode("utf-8", "backslashreplace")


def canonical_json(data: Any) -> bytes:
    """Deterministic JSON bytes used for hashing and sealing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def utc_now() -> str:
    """Current UTC time as an ISO-8601 string with second precision."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()
