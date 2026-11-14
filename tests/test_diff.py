from __future__ import annotations

from tessera.diff import compare
from tessera.models import ChangeKind, EntryKind, Severity
from tessera.policy import Policy, Rule

from .conftest import rec


def _one(old, new, policy=None):  # type: ignore[no-untyped-def]
    changes = compare(old, new, policy or Policy())
    assert len(changes) == 1, changes
    return changes[0]


def test_no_changes() -> None:
    state = {"/a": rec("/a")}
    assert compare(state, dict(state), Policy()) == []


def test_added_and_removed() -> None:
    changes = compare({"/old": rec("/old", digest="sha256:1")}, {"/new": rec("/new", digest="sha256:2")}, Policy())
    kinds = {c.kind for c in changes}
    assert kinds == {ChangeKind.ADDED, ChangeKind.REMOVED}


def test_content_modification() -> None:
    c = _one({"/a": rec("/a")}, {"/a": rec("/a", digest="sha256:bb", mtime_ns=2)})
    assert c.kind is ChangeKind.MODIFIED
    assert [d.name for d in c.deltas] == ["digest", "mtime_ns"]
    assert c.severity is Severity.MEDIUM


def test_metadata_only_is_one_level_lower() -> None:
    c = _one({"/a": rec("/a")}, {"/a": rec("/a", gid=0)})
    assert c.kind is ChangeKind.METADATA
    assert c.severity is Severity.LOW


def test_mtime_only_is_low() -> None:
    policy = Policy([Rule("/a", "full", Severity.CRITICAL)])
    c = _one({"/a": rec("/a")}, {"/a": rec("/a", mtime_ns=5)}, policy)
    assert c.severity is Severity.LOW


def test_directory_mtime_is_not_noise() -> None:
    old = {"/d": rec("/d", kind=EntryKind.DIR, digest=None)}
    new = {"/d": rec("/d", kind=EntryKind.DIR, digest=None, mtime_ns=99)}
    assert compare(old, new, Policy()) == []
    assert len(compare(old, new, Policy(default_profile="paranoid"))) == 1


def test_type_change() -> None:
    c = _one({"/a": rec("/a")}, {"/a": rec("/a", kind=EntryKind.SYMLINK, digest=None, link_target="/x")})
    assert c.kind is ChangeKind.TYPE_CHANGED
    assert c.severity is Severity.HIGH


def test_move_detection_by_content() -> None:
    c = _one({"/a": rec("/a", digest="sha256:abc")}, {"/b": rec("/b", digest="sha256:abc")})
    assert c.kind is ChangeKind.MOVED
    assert c.old_path == "/a"


def test_move_detection_can_be_disabled() -> None:
    changes = compare({"/a": rec("/a")}, {"/b": rec("/b")}, Policy(), detect_moves=False)
    assert {c.kind for c in changes} == {ChangeKind.ADDED, ChangeKind.REMOVED}


def test_unhashed_side_does_not_report_content_change() -> None:
    assert compare({"/a": rec("/a")}, {"/a": rec("/a", digest=None)}, Policy()) == []


def test_profile_limits_attributes() -> None:
    policy = Policy([Rule("/a", "content")])
    assert compare({"/a": rec("/a")}, {"/a": rec("/a", mode=0o600, uid=0)}, policy) == []


def test_append_profile() -> None:
    policy = Policy([Rule("*.log", "append")])
    old = {"/x.log": rec("/x.log", size=100)}
    assert compare(old, {"/x.log": rec("/x.log", size=200, digest="sha256:new")}, policy) == []
    c = _one(old, {"/x.log": rec("/x.log", size=10, digest="sha256:new")}, policy)
    assert c.kind is ChangeKind.MODIFIED
    assert c.severity >= Severity.HIGH
    assert any("shrank" in r for r in c.reasons)


def test_unreadable() -> None:
    c = _one({"/a": rec("/a")}, {"/a": rec("/a", digest=None, error="PermissionError: denied")})
    assert c.kind is ChangeKind.UNREADABLE


def test_ignored_paths_never_reported() -> None:
    policy = Policy([Rule("**/*.tmp", "ignore")])
    assert compare({}, {"/x.tmp": rec("/x.tmp")}, policy) == []


def test_sorted_worst_first() -> None:
    policy = Policy([Rule("/z", "full", Severity.CRITICAL), Rule("/a", "full", Severity.LOW)])
    changes = compare({}, {"/a": rec("/a", digest="sha256:1"), "/z": rec("/z", digest="sha256:2")}, policy)
    assert [c.path for c in changes] == ["/z", "/a"]


def test_fingerprint_stable_and_distinct() -> None:
    a = _one({"/a": rec("/a")}, {"/a": rec("/a", digest="sha256:bb")})
    b = _one({"/a": rec("/a")}, {"/a": rec("/a", digest="sha256:cc")})
    assert a.fingerprint() == _one({"/a": rec("/a")}, {"/a": rec("/a", digest="sha256:bb")}).fingerprint()
    assert a.fingerprint() != b.fingerprint()
