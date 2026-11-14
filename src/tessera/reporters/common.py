"""Formatting shared by several reporters."""

from __future__ import annotations

import stat
from datetime import UTC, datetime
from typing import Any

from tessera.models import AttrDelta, ChangeKind

KIND_LABEL = {
    ChangeKind.ADDED: "added",
    ChangeKind.REMOVED: "removed",
    ChangeKind.MODIFIED: "modified",
    ChangeKind.METADATA: "metadata",
    ChangeKind.TYPE_CHANGED: "type",
    ChangeKind.MOVED: "moved",
    ChangeKind.UNREADABLE: "unreadable",
}

ATTR_LABEL = {
    "digest": "content",
    "mtime_ns": "mtime",
    "link_target": "target",
    "attributes": "attrs",
}


def format_value(name: str, value: Any) -> str:
    if value is None:
        return "-"
    if name == "mode" and isinstance(value, int):
        return f"{stat.filemode(value | stat.S_IFREG)[1:]} ({value:04o})"
    if name == "mtime_ns" and isinstance(value, int):
        return datetime.fromtimestamp(value / 1e9, UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    if name == "digest" and isinstance(value, str):
        algo, _, hexdigest = value.partition(":")
        return f"{algo}:{hexdigest[:16]}"
    if name == "attributes" and isinstance(value, int):
        return f"0x{value:x}"
    if name == "size" and isinstance(value, int):
        return f"{value:,} B"
    return str(value)


def delta_text(delta: AttrDelta, arrow: str = "->") -> tuple[str, str]:
    """``(label, "old -> new")`` for display."""
    label = ATTR_LABEL.get(delta.name, delta.name)
    return label, f"{format_value(delta.name, delta.old)} {arrow} {format_value(delta.name, delta.new)}"
