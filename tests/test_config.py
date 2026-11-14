from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from tessera.config import find_config, load_config, parse_config
from tessera.errors import ConfigError
from tessera.models import Severity
from tessera.templates import starter_config


def base(**extra: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"watch": [{"path": "/etc"}]}
    data.update(extra)
    return data


def test_minimal_config_defaults() -> None:
    cfg = parse_config(base(), platform="linux")
    assert cfg.scan.algorithm == "sha256"
    assert cfg.scan.case_sensitive is True
    assert cfg.report.fail_on is Severity.LOW
    assert cfg.roots[0].path.endswith("etc")
    assert parse_config(base(), platform="windows").scan.case_sensitive is False


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({}, "no \\[\\[watch\\]\\]"),
        (base(general={"algoritm": "sha256"}), "unknown key 'algoritm'"),
        (base(general={"algorithm": "md5"}), "unsupported hash"),
        (base(general={"workers": 0}), "between 1 and 64"),
        (base(general={"workers": True}), "number"),
        (base(general={"max_file_size": "lots"}), "invalid size"),
        (base(general={"chunk_size": 10}), "at least 4KiB"),
        (base(rule=[{"pattern": "/x"}]), "needs both"),
        (base(rule=[{"pattern": "/x", "profile": "nope"}]), "unknown profile"),
        (base(rule=[{"pattern": "/x", "profile": "full", "severity": "bad"}]), "unknown severity"),
        (base(hook=[{"name": "x"}]), "exactly one"),
        (base(hook=[{"command": []}]), "must not be empty"),
        (base(hook=[{"url": "ftp://x"}]), "https://"),
        (base(hook=[{"command": ["x"], "timeout": 9999}]), "timeout"),
        (base(report={"format": "pdf"}), "not supported"),
        (base(profiles={"x": {"attributes": ["kind"], "extra": 1}}), "unknown key"),
        ({"watch": [{"exclude": []}]}, "missing 'path'"),
        (base(bogus=1), "unknown key 'bogus'"),
    ],
)
def test_validation_errors(data: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config(data)


def test_typo_suggestion() -> None:
    with pytest.raises(ConfigError) as info:
        parse_config(base(general={"worker": 2}))
    assert info.value.hint == "did you mean 'workers'?"


def test_hooks_and_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKEN", "s3cret")
    cfg = parse_config(base(
        profiles={"hashonly": {"attributes": ["kind", "digest"]}},
        rule=[{"pattern": "/data/**", "profile": "hashonly"}],
        hook=[{"name": "w", "url": "https://example.invalid/x", "headers": {"Authorization": "Bearer $TOKEN"},
               "min_severity": "critical"}],
    ))  # fmt: skip
    assert cfg.hooks[0].headers["Authorization"] == "Bearer s3cret"
    assert cfg.hooks[0].min_severity is Severity.CRITICAL
    assert cfg.policy.resolve("/data/a").profile == "hashonly"


def test_digest_tracks_policy() -> None:
    a = parse_config(base())
    b = parse_config(base(rule=[{"pattern": "/etc/**", "profile": "content"}]))
    assert a.digest() == parse_config(base()).digest()
    assert a.digest() != b.digest()


def test_load_and_find(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "t.toml"
    path.write_text('[[watch]]\npath = "/etc"\n')
    assert load_config(str(path)).source == path
    monkeypatch.setenv("TESSERA_CONFIG", str(path))
    assert find_config(None) == path
    bad = tmp_path / "bad.toml"
    bad.write_text("[[watch]\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(str(bad))
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "missing.toml"))


@pytest.mark.parametrize("platform", ["linux", "macos", "windows"])
def test_starter_configs_are_valid(platform: str) -> None:
    text = starter_config(platform)  # type: ignore[arg-type]
    cfg = parse_config(tomllib.loads(text), platform=platform)  # type: ignore[arg-type]
    assert cfg.roots and cfg.policy.rules
    assert "jullewz" in text
