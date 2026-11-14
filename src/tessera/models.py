"""Core data model: file records, severities, changes and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from tessera import __version__


class EntryKind(StrEnum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    OTHER = "other"


class Severity(IntEnum):
    """Ordered severity levels. Higher is worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r}, expected one of: {names}") from None

    @property
    def label(self) -> str:
        return self.name.lower()

    def bump(self, levels: int) -> Severity:
        return Severity(max(0, min(int(Severity.CRITICAL), int(self) + levels)))


class ChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    METADATA = "metadata"
    TYPE_CHANGED = "type_changed"
    MOVED = "moved"
    UNREADABLE = "unreadable"


# Attributes a profile can track. ``digest`` is the content hash.
ALL_ATTRIBUTES: tuple[str, ...] = (
    "kind",
    "size",
    "mode",
    "uid",
    "gid",
    "mtime_ns",
    "inode",
    "nlink",
    "digest",
    "link_target",
    "attributes",
)


@dataclass(frozen=True, slots=True)
class FileRecord:
    """Everything Tessera knows about one filesystem entry at scan time."""

    path: str
    kind: EntryKind
    size: int = 0
    mode: int = 0
    uid: int | None = None
    gid: int | None = None
    mtime_ns: int = 0
    inode: int = 0
    nlink: int = 0
    digest: str | None = None
    link_target: str | None = None
    attributes: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        values = dict(data)
        values["kind"] = EntryKind(values["kind"])
        return cls(**values)

    def get(self, attribute: str) -> Any:
        value = getattr(self, attribute)
        return value.value if isinstance(value, EntryKind) else value


@dataclass(frozen=True, slots=True)
class AttrDelta:
    name: str
    old: Any
    new: Any


@dataclass(slots=True)
class Change:
    """One difference between a baseline and the current state."""

    path: str
    kind: ChangeKind
    severity: Severity
    rule: str | None = None
    deltas: list[AttrDelta] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    old_path: str | None = None

    def fingerprint(self) -> str:
        """Stable identity used by watch mode to avoid repeat alerts."""
        parts = [self.kind.value, self.path, self.old_path or ""]
        parts += [f"{d.name}={d.new!r}" for d in self.deltas]
        return "|".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind.value,
            "severity": self.severity.label,
            "rule": self.rule,
            "old_path": self.old_path,
            "deltas": [{"name": d.name, "old": d.old, "new": d.new} for d in self.deltas],
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class ScanStats:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    other: int = 0
    hashed_files: int = 0
    hashed_bytes: int = 0
    skipped_large: int = 0
    errors: int = 0
    seconds: float = 0.0

    @property
    def entries(self) -> int:
        return self.files + self.dirs + self.symlinks + self.other

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["entries"] = self.entries
        return data


@dataclass(slots=True)
class Snapshot:
    """The result of one scan, before or after it is stored."""

    records: dict[str, FileRecord]
    stats: ScanStats
    created_at: str
    host: str
    platform: str
    algorithm: str
    roots: list[str]


@dataclass(frozen=True, slots=True)
class BaselineInfo:
    """Metadata of a stored baseline."""

    id: int
    created_at: str
    label: str | None
    host: str
    platform: str
    algorithm: str
    file_count: int
    merkle_root: str
    seal: str | None
    config_digest: str
    roots: list[str]
    scan_seconds: float
    error_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Report:
    """Input to every reporter."""

    changes: list[Change]
    baseline: BaselineInfo | None
    stats: ScanStats | None
    generated_at: str
    host: str
    platform: str
    title: str = "Integrity check"
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[Severity, int]:
        result = dict.fromkeys(Severity, 0)
        for change in self.changes:
            result[change.severity] += 1
        return result

    @property
    def highest(self) -> Severity | None:
        return max((c.severity for c in self.changes), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "tessera", "version": __version__},
            "title": self.title,
            "generated_at": self.generated_at,
            "host": self.host,
            "platform": self.platform,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "stats": self.stats.to_dict() if self.stats else None,
            "summary": {s.label: n for s, n in self.counts().items()},
            "notes": list(self.notes),
            "changes": [c.to_dict() for c in self.changes],
        }
