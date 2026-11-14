from __future__ import annotations

import os
from pathlib import Path

import pytest

from tessera.hashing import hash_bytes
from tessera.models import EntryKind, ScanStats
from tessera.policy import Policy, Rule
from tessera.scanner import Scanner, ScanRoot, ScanSettings

from .conftest import posix_only


def _scan(root: Path, *, policy: Policy | None = None, **settings: object) -> dict:  # type: ignore[type-arg]
    scanner = Scanner(ScanSettings(**settings), policy or Policy())  # type: ignore[arg-type]
    return scanner.scan([ScanRoot(str(root))]).records


def test_records_files_dirs_and_hashes(tree: Path) -> None:
    records = _scan(tree)
    passwd = records[str(tree / "etc" / "passwd")]
    assert passwd.kind is EntryKind.FILE
    assert passwd.digest == hash_bytes(b"root:x:0:0\n")
    assert passwd.size == len(b"root:x:0:0\n")
    assert records[str(tree / "etc")].kind is EntryKind.DIR
    assert str(tree) in records


def test_ignore_rule_prunes_subtree(tree: Path) -> None:
    policy = Policy([Rule("**/logs/**", "ignore")])
    records = _scan(tree, policy=policy)
    assert not any("logs" in p for p in records)


def test_watch_excludes(tree: Path) -> None:
    scanner = Scanner(ScanSettings(), Policy())
    snap = scanner.scan([ScanRoot(str(tree), exclude=["*.conf"])])
    assert str(tree / "etc" / "app.conf") not in snap.records
    assert str(tree / "etc" / "passwd") in snap.records


def test_profiles_without_digest_skip_hashing(tree: Path) -> None:
    records = _scan(tree, policy=Policy(default_profile="permissions"))
    assert all(r.digest is None for r in records.values())


def test_large_files_are_not_hashed(tree: Path) -> None:
    big = tree / "big.bin"
    big.write_bytes(b"x" * 5000)
    scanner = Scanner(ScanSettings(max_file_size=1000), Policy())
    snap = scanner.scan([ScanRoot(str(tree))])
    assert snap.records[str(big)].digest is None
    assert snap.stats.skipped_large == 1


def test_missing_root_is_recorded_as_error(tmp_path: Path) -> None:
    snap = Scanner(ScanSettings(), Policy()).scan([ScanRoot(str(tmp_path / "nope"))])
    rec = snap.records[str(tmp_path / "nope")]
    assert rec.error and "FileNotFoundError" in rec.error
    assert snap.stats.errors == 1


def test_single_file_root(tree: Path) -> None:
    records = _scan(tree / "etc" / "passwd")
    assert list(records) == [str(tree / "etc" / "passwd")]


@posix_only
def test_symlinks_are_not_followed_by_default(tree: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("x")
    os.symlink(outside, tree / "link")
    records = _scan(tree)
    link = records[str(tree / "link")]
    assert link.kind is EntryKind.SYMLINK
    assert link.link_target == str(outside)
    assert str(tree / "link" / "secret") not in records


@posix_only
def test_symlink_loops_terminate(tree: Path) -> None:
    os.symlink(tree, tree / "etc" / "loop")
    records = _scan(tree, follow_symlinks=True)
    assert str(tree / "etc" / "passwd") in records


@posix_only
def test_unreadable_file_recorded(tree: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    secret = tree / "etc" / "locked"
    secret.write_text("x")
    secret.chmod(0)
    try:
        records = _scan(tree)
    finally:
        secret.chmod(0o600)
    assert records[str(secret)].error is not None


def test_progress_callback(tree: Path) -> None:
    seen: list[ScanStats] = []
    Scanner(ScanSettings(), Policy(), progress=seen.append, progress_interval=0).scan([ScanRoot(str(tree))])
    assert seen and seen[-1].files == 5
    assert seen[-1].hashed_files == 5
