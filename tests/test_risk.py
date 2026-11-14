from __future__ import annotations

import stat

from tessera.diff import compare
from tessera.models import Change, ChangeKind, Severity
from tessera.policy import Policy, Rule
from tessera.risk import FILE_ATTRIBUTE_HIDDEN, assess

from .conftest import rec

LOW = Policy(default_severity=Severity.LOW)


def _change(old, new, path="/srv/x"):  # type: ignore[no-untyped-def]
    changes = compare({path: old} if old else {}, {path: new} if new else {}, LOW)
    assert len(changes) == 1
    return changes[0]


def test_setuid_is_critical() -> None:
    c = _change(rec("/srv/x", mode=0o755), rec("/srv/x", mode=0o755 | stat.S_ISUID))
    assert c.severity is Severity.CRITICAL
    assert "setuid bit set on file" in c.reasons


def test_world_writable() -> None:
    c = _change(rec("/srv/x", mode=0o644), rec("/srv/x", mode=0o646))
    assert c.severity is Severity.HIGH


def test_sticky_world_writable_dir_is_fine() -> None:
    from tessera.models import EntryKind

    old = rec("/srv/x", kind=EntryKind.DIR, digest=None, mode=0o755)
    new = rec("/srv/x", kind=EntryKind.DIR, digest=None, mode=0o777 | stat.S_ISVTX)
    c = _change(old, new)
    assert "became world-writable" not in c.reasons


def test_timestomping() -> None:
    c = _change(rec("/srv/x", digest="sha256:1"), rec("/srv/x", digest="sha256:2"))
    assert c.severity is Severity.CRITICAL
    assert any("timestomping" in r for r in c.reasons)


def test_root_ownership_change() -> None:
    c = _change(rec("/srv/x", uid=1000), rec("/srv/x", uid=0))
    assert c.severity is Severity.HIGH


def test_sensitive_file_names() -> None:
    c = _change(rec("/etc/sudoers", mtime_ns=1), rec("/etc/sudoers", digest="sha256:z", mtime_ns=2), "/etc/sudoers")
    assert c.severity >= Severity.HIGH


def test_persistence_locations() -> None:
    c = _change(None, rec("/etc/cron.d/job"), "/etc/cron.d/job")
    assert c.kind is ChangeKind.ADDED and c.severity is Severity.HIGH
    win = _change(None, rec("C:/Users/a/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk"),
                  "C:/Users/a/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk")  # fmt: skip
    assert win.severity is Severity.HIGH


def test_new_binary_in_system_dir() -> None:
    c = _change(None, rec("/usr/bin/evil", mode=0o755), "/usr/bin/evil")
    assert c.severity is Severity.HIGH
    w = _change(None, rec("C:/Windows/System32/evil.dll", uid=None, gid=None), "C:/Windows/System32/evil.dll")
    assert w.severity is Severity.HIGH


def test_windows_hidden_attribute() -> None:
    old = rec("C:/data/x.txt", uid=None, gid=None)
    new = rec("C:/data/x.txt", uid=None, gid=None, attributes=FILE_ATTRIBUTE_HIDDEN)
    c = _change(old, new, "C:/data/x.txt")
    assert "hidden or system attribute set" in c.reasons


def test_three_signals_bump_one_level() -> None:
    old = rec("/usr/bin/sudoers", mode=0o644, uid=1000)
    new = rec("/usr/bin/sudoers", mode=0o757, uid=0)
    c = _change(old, new, "/usr/bin/sudoers")
    assert len(c.reasons) >= 3
    assert c.severity is Severity.CRITICAL


def test_heuristics_never_lower_severity() -> None:
    change = Change("/plain", ChangeKind.REMOVED, Severity.CRITICAL)
    assert assess(change, rec("/plain"), None).severity is Severity.CRITICAL


def test_rule_severity_kept_when_no_heuristic_fires() -> None:
    policy = Policy([Rule("/srv/**", "full", Severity.MEDIUM)])
    changes = compare({"/srv/a": rec("/srv/a")}, {"/srv/a": rec("/srv/a", digest="sha256:b", mtime_ns=9)}, policy)
    assert changes[0].severity is Severity.MEDIUM and changes[0].reasons == []
