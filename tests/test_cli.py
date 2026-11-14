"""End-to-end tests that drive the real command-line entry point."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from tessera import __version__
from tessera.cli import main

from .conftest import posix_only

Run = Callable[..., tuple[int, str, str]]


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str], write_config: Callable[[str], Path]) -> Run:
    config = write_config("")

    def invoke(*args: str) -> tuple[int, str, str]:
        code = main([*args[:1], "-c", str(config), *args[1:]] if args else [])
        out, err = capsys.readouterr()
        return code, out, err

    return invoke


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out


def test_full_workflow(run: Run, tree: Path, tmp_path: Path) -> None:
    assert run("keygen")[0] == 0
    code, out, _ = run("snapshot", "-l", "initial")
    assert code == 0 and "baseline #1 recorded" in out and "valid" in out

    code, out, _ = run("check")
    assert code == 0 and "No changes" in out

    (tree / "etc" / "passwd").write_text("root:x:0:0\nmallory:x:0:0\n")
    code, out, _ = run("check", "-f", "json")
    assert code == 1
    data = json.loads(out)
    assert data["summary"]["critical"] >= 1

    assert run("check", "--fail-on", "critical", "-q")[0] == 1
    assert run("check", "--min-severity", "critical", "--fail-on", "critical", "-q")[0] == 1

    report = tmp_path / "report.html"
    code, _, _ = run("check", "-f", "html", "-o", str(report))
    assert code == 1 and report.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    code, out, _ = run("check", "--update", "-q")
    assert code == 1
    assert run("check", "-q")[0] == 0

    code, out, _ = run("baselines", "--json")
    assert [b["id"] for b in json.loads(out)] == [2, 1]
    assert run("diff", "1", "2", "-f", "json")[0] == 1

    code, out, _ = run("verify", "--all", "--strict")
    assert code == 0 and out.count("valid") >= 2


def test_export_prove_and_verify(run: Run, tree: Path, tmp_path: Path) -> None:
    run("keygen")
    run("snapshot")
    manifest, proof = tmp_path / "m.json", tmp_path / "p.json"
    assert run("export", "-o", str(manifest))[0] == 0
    assert run("verify", "--manifest", str(manifest), "--strict")[0] == 0
    assert run("prove", str(tree / "etc" / "passwd"), "-o", str(proof))[0] == 0
    code, out, _ = run("verify-proof", str(proof), "--strict")
    assert code == 0 and "proven" in out

    data = json.loads(proof.read_text())
    data["record"]["digest"] = "sha256:" + "0" * 64
    proof.write_text(json.dumps(data))
    assert run("verify-proof", str(proof))[0] == 3

    data = json.loads(manifest.read_text())
    data["records"].pop()
    manifest.write_text(json.dumps(data))
    assert run("verify", "--manifest", str(manifest))[0] == 3

    assert run("prove", str(tree / "not-there"))[0] == 3


def test_tampered_store_exits_3(run: Run, tmp_path: Path) -> None:
    run("keygen")
    run("snapshot")
    conn = sqlite3.connect(tmp_path / "state" / "tessera.db")
    conn.execute("DELETE FROM files WHERE path LIKE '%motd'")
    conn.commit()
    conn.close()
    assert run("verify")[0] == 3
    assert run("check", "-q")[0] == 3


def test_strict_requires_seal(run: Run) -> None:
    code, _, err = run("snapshot")
    assert code == 0 and "will not be sealed" in err
    assert run("check", "-q", "--strict")[0] == 3
    assert run("verify")[0] == 0
    assert run("snapshot", "--require-seal")[0] == 2


def test_errors_have_hints(run: Run) -> None:
    code, _, err = run("check")
    assert code == 2 and "no baseline recorded yet" in err and "tessera snapshot" in err
    code, _, err = run("show", "42")
    assert code == 2 and "does not exist" in err


def test_missing_config(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["check", "-c", str(tmp_path / "missing.toml")]) == 2
    assert "tessera init" in capsys.readouterr().err


def test_init_writes_valid_config(capsys: pytest.CaptureFixture[str], tmp_path: Path,
                                  monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "cfg"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "data"))
    target = tmp_path / "tessera.toml"
    for platform in ("linux", "macos", "windows"):
        assert main(["init", str(target), "--platform", platform, "--force", "--no-key"]) == 0
        assert main(["config", "-c", str(target)]) == 0
    assert main(["init", str(target)]) == 2
    out = capsys.readouterr()
    assert "already exists" in out.err


def test_explain_show_config_prune(run: Run, tree: Path) -> None:
    run("snapshot")
    run("snapshot")
    code, out, _ = run("explain", str(tree / "logs" / "app.log"), "/elsewhere")
    assert code == 0 and "append" in out and "not under any" in out
    code, out, _ = run("show", "-p", "**/etc/*", "--json")
    assert code == 0 and {Path(r["path"]).name for r in json.loads(out)} == {"passwd", "app.conf", "motd", "cron.d"}
    code, out, _ = run("config", "-v")
    assert code == 0 and "rule  1" in out
    code, out, _ = run("prune", "--keep", "1")
    assert code == 0 and "deleted 1" in out


def test_watch_cycles(run: Run, tree: Path) -> None:
    run("snapshot")
    (tree / "etc" / "motd").write_text("changed\n")
    code, out, err = run("watch", "--interval", "1", "--cycles", "2", "--no-hooks")
    assert code == 1
    assert out.count("Watch cycle 1") == 1 and "Watch cycle 2" not in out
    assert "cycle 2: no new changes" in err


def test_hook_runs_from_check(capsys: pytest.CaptureFixture[str], write_config: Callable[[str], Path],
                              tree: Path, tmp_path: Path) -> None:  # fmt: skip
    marker = tmp_path / "hook-ran.json"
    script = tmp_path / "hook.py"
    script.write_text(f"import sys; open({str(marker)!r}, 'w').write(sys.stdin.read())")
    config = write_config(
        f"\n[[hook]]\nname = 'save'\ncommand = [{json.dumps(sys.executable)}, {json.dumps(str(script))}]\n"
        "min_severity = 'high'\n"
    )
    assert main(["snapshot", "-c", str(config), "-q"]) == 0
    (tree / "etc" / "passwd").write_text("changed")
    assert main(["check", "-c", str(config), "-q"]) == 1
    assert json.loads(marker.read_text())["hook"] == "save"
    marker.unlink()
    assert main(["check", "-c", str(config), "-q", "--no-hooks"]) == 1
    assert not marker.exists()
    capsys.readouterr()


@posix_only
def test_setuid_detection_end_to_end(run: Run, tree: Path) -> None:
    run("snapshot")
    os.chmod(tree / "bin" / "tool", 0o4755)
    _, out, _ = run("check", "-f", "json")
    change = next(c for c in json.loads(out)["changes"] if c["path"].endswith("tool"))
    assert change["severity"] == "critical"
