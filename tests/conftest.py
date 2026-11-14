from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from tessera.config import Config, parse_config
from tessera.models import EntryKind, FileRecord

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TESSERA_CONFIG", raising=False)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small directory tree standing in for a monitored system."""
    root = tmp_path / "site"
    (root / "etc" / "cron.d").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "logs").mkdir()
    (root / "etc" / "passwd").write_text("root:x:0:0\n")
    (root / "etc" / "app.conf").write_text("debug = false\n")
    (root / "etc" / "motd").write_text("welcome\n")
    (root / "bin" / "tool").write_text("#!/bin/sh\necho hi\n")
    (root / "logs" / "app.log").write_text("one\ntwo\nthree\n")
    if os.name != "nt":
        os.chmod(root / "bin" / "tool", 0o755)
    return root


ConfigFactory = Callable[..., Config]


@pytest.fixture
def make_config(tmp_path: Path, tree: Path) -> ConfigFactory:
    def factory(**overrides: object) -> Config:
        data: dict[str, object] = {
            "general": {
                "store": str(tmp_path / "state" / "tessera.db"),
                "key_file": str(tmp_path / "state" / "seal.key"),
                "workers": 2,
            },
            "watch": [{"path": str(tree)}],
            "rule": [
                {"pattern": "**/bin/**", "profile": "full", "severity": "high"},
                {"pattern": "**/*.log", "profile": "append"},
                {"pattern": "**/etc/passwd", "profile": "full", "severity": "critical"},
            ],
        }
        data.update(overrides)  # type: ignore[arg-type]
        return parse_config(data)

    return factory


@pytest.fixture
def write_config(tmp_path: Path, tree: Path) -> Callable[[str], Path]:
    def factory(extra: str = "") -> Path:
        state = tmp_path / "state"
        text = f"""
[general]
store = '{(state / "tessera.db").as_posix()}'
key_file = '{(state / "seal.key").as_posix()}'
workers = 2

[[watch]]
path = '{tree.as_posix()}'

[[rule]]
pattern = "**/bin/**"
profile = "full"
severity = "high"

[[rule]]
pattern = "**/*.log"
profile = "append"

[[rule]]
pattern = "**/etc/passwd"
profile = "full"
severity = "critical"
{extra}
"""
        path = tmp_path / "tessera.toml"
        path.write_text(text, encoding="utf-8")
        return path

    return factory


def rec(path: str, **kw: object) -> FileRecord:
    """Shorthand for building records in tests."""
    values: dict[str, object] = {
        "kind": EntryKind.FILE,
        "size": 10,
        "mode": 0o644,
        "uid": 1000,
        "gid": 1000,
        "mtime_ns": 1_700_000_000_000_000_000,
        "inode": 1,
        "nlink": 1,
        "digest": "sha256:aa",
    }
    values.update(kw)
    return FileRecord(path=path, **values)  # type: ignore[arg-type]


def python_cmd(*args: str) -> list[str]:
    return [sys.executable, *args]
