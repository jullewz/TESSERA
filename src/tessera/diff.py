"""Diff engine: compares two sets of file records under a policy."""

from __future__ import annotations

from collections.abc import Mapping

from tessera import risk
from tessera.models import AttrDelta, Change, ChangeKind, EntryKind, FileRecord, Severity
from tessera.policy import Policy

# Order in which deltas are displayed.
_DELTA_ORDER = ("kind", "digest", "size", "mode", "uid", "gid", "attributes",
                "link_target", "mtime_ns", "inode", "nlink")  # fmt: skip


def _deltas(old: FileRecord, new: FileRecord, attributes: frozenset[str],
            *, paranoid: bool = False) -> list[AttrDelta]:  # fmt: skip
    deltas: list[AttrDelta] = []
    for name in _DELTA_ORDER:
        if name not in attributes:
            continue
        if name == "mtime_ns" and new.kind is EntryKind.DIR and not paranoid:
            continue  # a directory's mtime changes with its entries, which are reported themselves
        before, after = old.get(name), new.get(name)
        if name == "digest" and (before is None or after is None):
            continue  # not hashed on one side (too large, unreadable, policy change)
        if before != after:
            deltas.append(AttrDelta(name, before, after))
    return deltas


def compare_records(old: FileRecord, new: FileRecord, policy: Policy) -> Change | None:
    """Compare one path present in both snapshots."""
    res = policy.resolve(new.path)
    if res.ignored:
        return None

    if new.error and not old.error:
        return Change(new.path, ChangeKind.UNREADABLE, res.severity, res.label,
                      reasons=[new.error])  # fmt: skip

    if old.kind is not new.kind:
        change = Change(new.path, ChangeKind.TYPE_CHANGED, res.severity.bump(1), res.label,
                        deltas=[AttrDelta("kind", old.kind.value, new.kind.value)])  # fmt: skip
        return risk.assess(change, old, new)

    attributes = res.attributes
    if res.profile == "append":
        deltas = _deltas(old, new, attributes)
        if new.kind is EntryKind.FILE and new.size < old.size:
            deltas.insert(0, AttrDelta("size", old.size, new.size))
            change = Change(new.path, ChangeKind.MODIFIED, max(res.severity, Severity.HIGH),
                            res.label, deltas=deltas,
                            reasons=["append-only file shrank (possible log tampering)"])  # fmt: skip
            return risk.assess(change, old, new)
        if not deltas:
            return None
        return risk.assess(Change(new.path, ChangeKind.METADATA, res.severity, res.label, deltas), old, new)

    deltas = _deltas(old, new, attributes, paranoid=res.profile == "paranoid")
    if not deltas:
        return None
    content = any(d.name in ("digest", "size", "link_target") for d in deltas)
    kind = ChangeKind.MODIFIED if content else ChangeKind.METADATA
    severity = res.severity if content else res.severity.bump(-1)
    only_times = all(d.name in ("mtime_ns", "inode", "nlink") for d in deltas)
    if only_times:
        severity = min(severity, Severity.LOW)
    return risk.assess(Change(new.path, kind, severity, res.label, deltas), old, new)


def compare(
    old: Mapping[str, FileRecord],
    new: Mapping[str, FileRecord],
    policy: Policy,
    *,
    detect_moves: bool = True,
) -> list[Change]:
    """Return every change between ``old`` and ``new``, worst first."""
    changes: list[Change] = []
    removed = [path for path in old if path not in new]
    added = [path for path in new if path not in old]

    for path in old.keys() & new.keys():
        change = compare_records(old[path], new[path], policy)
        if change is not None:
            changes.append(change)

    moved_from: dict[str, str] = {}
    if detect_moves:
        by_content: dict[tuple[str, int], list[str]] = {}
        for path in removed:
            rec = old[path]
            if rec.kind is EntryKind.FILE and rec.digest:
                by_content.setdefault((rec.digest, rec.size), []).append(path)
        for path in sorted(added):
            rec = new[path]
            if rec.kind is not EntryKind.FILE or not rec.digest:
                continue
            candidates = by_content.get((rec.digest, rec.size))
            if candidates:
                moved_from[path] = candidates.pop(0)

    consumed = set(moved_from.values())
    for path in added:
        res = policy.resolve(path)
        if res.ignored:
            continue
        rec = new[path]
        if path in moved_from:
            source = moved_from[path]
            change = Change(path, ChangeKind.MOVED, res.severity, res.label, old_path=source)
            changes.append(risk.assess(change, old[source], rec))
        else:
            change = Change(path, ChangeKind.ADDED, res.severity, res.label)
            if rec.error:
                change.reasons.append(rec.error)
            changes.append(risk.assess(change, None, rec))

    for path in removed:
        if path in consumed:
            continue
        res = policy.resolve(path)
        if res.ignored:
            continue
        change = Change(path, ChangeKind.REMOVED, res.severity, res.label)
        changes.append(risk.assess(change, old[path], None))

    changes.sort(key=lambda c: (-int(c.severity), c.path))
    return changes
