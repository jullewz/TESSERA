"""Risk heuristics that raise the severity of suspicious changes.

Each heuristic looks at one change and returns ``(floor, reason)`` when it
fires. The floor is the minimum severity the change deserves. Heuristics
only ever raise a severity, never lower it. When three or more heuristics
fire on the same change, it is raised one more level.

The goal is to surface the changes an intruder tends to make: new setuid
binaries, loosened permissions, persistence mechanisms, rewritten logs and
content changes hidden behind a preserved timestamp.
"""

from __future__ import annotations

import posixpath
import stat
from collections.abc import Callable

from tessera.models import Change, ChangeKind, EntryKind, FileRecord, Severity
from tessera.util import match_path

Finding = tuple[Severity, str]
Heuristic = Callable[[Change, FileRecord | None, FileRecord | None], Finding | None]

# Windows file attribute flags (winnt.h)
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

EXECUTABLE_SUFFIXES = (
    ".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".psm1", ".bat", ".cmd",
    ".vbs", ".js", ".hta", ".msi", ".so", ".dylib", ".sh",
)  # fmt: skip

SENSITIVE_NAMES = {
    "passwd", "shadow", "group", "gshadow", "sudoers", "authorized_keys",
    "authorized_keys2", "known_hosts", "hosts", "crontab", "ld.so.preload",
    "ld.so.conf", "sshd_config", "pam.conf", "login.defs", "profile",
    ".bashrc", ".bash_profile", ".zshrc", ".profile",
}  # fmt: skip

PERSISTENCE_FRAGMENTS = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/etc/init.d",
    "/etc/sudoers.d",
    "/etc/profile.d",
    "/etc/pam.d",
    "/library/launchdaemons",
    "/library/launchagents",
    "/start menu/programs/startup",
    "/windows/system32/tasks",
    "/.ssh/",
)

BIN_DIR_NAMES = {"bin", "sbin", "lib", "lib64", "libexec", "system32", "syswow64", "macos"}


def _lower(path: str) -> str:
    return match_path(path).lower()


def _basename(path: str) -> str:
    return posixpath.basename(match_path(path))


def _setid_gained(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if new is None or new.kind is not EntryKind.FILE:
        return None
    special = stat.S_ISUID | stat.S_ISGID
    old_bits = (old.mode & special) if old else 0
    gained = (new.mode & special) & ~old_bits
    if gained:
        which = "setuid" if gained & stat.S_ISUID else "setgid"
        return Severity.CRITICAL, f"{which} bit set on file"
    return None


def _world_writable(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if new is None or new.kind not in (EntryKind.FILE, EntryKind.DIR) or new.uid is None:
        return None
    if new.kind is EntryKind.DIR and new.mode & stat.S_ISVTX:
        return None  # sticky dirs like /tmp are meant to be world-writable
    was = bool(old and old.mode & stat.S_IWOTH)
    if new.mode & stat.S_IWOTH and not was:
        return Severity.HIGH, "became world-writable"
    return None


def _became_executable(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if old is None or new is None or new.kind is not EntryKind.FILE or new.uid is None:
        return None
    exec_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if new.mode & exec_bits and not old.mode & exec_bits:
        return Severity.MEDIUM, "execute permission added"
    return None


def _owner_changed(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if old is None or new is None or old.uid is None or new.uid is None:
        return None
    if old.uid != new.uid and 0 in (old.uid, new.uid):
        return Severity.HIGH, "ownership moved to or from root"
    return None


def _timestomp(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if change.kind is not ChangeKind.MODIFIED or old is None or new is None:
        return None
    if old.digest and new.digest and old.digest != new.digest and old.mtime_ns == new.mtime_ns:
        return Severity.CRITICAL, "content changed but modification time preserved (possible timestomping)"
    return None


def _sensitive_file(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if _basename(change.path).lower() in SENSITIVE_NAMES:
        return Severity.HIGH, "security-sensitive file"
    return None


def _persistence(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if change.kind not in (ChangeKind.ADDED, ChangeKind.MODIFIED, ChangeKind.MOVED):
        return None
    lowered = _lower(change.path)
    for fragment in PERSISTENCE_FRAGMENTS:
        if fragment in lowered:
            return Severity.HIGH, "persistence location (autostart, scheduler or service)"
    return None


def _new_binary(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if change.kind not in (ChangeKind.ADDED, ChangeKind.MODIFIED) or new is None:
        return None
    if new.kind is not EntryKind.FILE:
        return None
    parts = _lower(change.path).split("/")
    in_bin_dir = any(p in BIN_DIR_NAMES for p in parts[:-1])
    is_exec_name = parts[-1].endswith(EXECUTABLE_SUFFIXES)
    is_exec_mode = new.uid is not None and bool(new.mode & stat.S_IXUSR)
    if in_bin_dir and (is_exec_name or is_exec_mode):
        verb = "new" if change.kind is ChangeKind.ADDED else "modified"
        return Severity.HIGH, f"{verb} executable in a system binary directory"
    if change.kind is ChangeKind.ADDED and is_exec_name:
        return Severity.MEDIUM, "new executable or script"
    return None


def _hidden_attribute(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if new is None or new.uid is not None:
        return None  # only meaningful on Windows
    flags = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    gained = (new.attributes & flags) & ~((old.attributes if old else 0) & flags)
    if gained and change.kind is not ChangeKind.REMOVED:
        return Severity.MEDIUM, "hidden or system attribute set"
    return None


def _symlink_retarget(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if any(d.name == "link_target" for d in change.deltas):
        return Severity.MEDIUM, "symbolic link now points somewhere else"
    return None


HEURISTICS: tuple[Heuristic, ...] = (
    _setid_gained,
    _world_writable,
    _became_executable,
    _owner_changed,
    _timestomp,
    _sensitive_file,
    _persistence,
    _new_binary,
    _hidden_attribute,
    _symlink_retarget,
)


def assess(change: Change, old: FileRecord | None, new: FileRecord | None) -> Change:
    """Apply every heuristic to ``change`` in place and return it."""
    fired = 0
    for heuristic in HEURISTICS:
        finding = heuristic(change, old, new)
        if finding is None:
            continue
        floor, reason = finding
        change.reasons.append(reason)
        change.severity = max(change.severity, floor)
        fired += 1
    if fired >= 3:
        change.severity = change.severity.bump(1)
    return change
