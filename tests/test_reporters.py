from __future__ import annotations

import io
import json

import pytest

from tessera.models import AttrDelta, BaselineInfo, Change, ChangeKind, Report, ScanStats, Severity
from tessera.reporters import FORMATS, get_renderer, render
from tessera.term import Style, shorten, visible_len


def sample_report(changes: list[Change] | None = None) -> Report:
    baseline = BaselineInfo(1, "2026-01-01T00:00:00+00:00", "initial", "host", "linux", "sha256", 3,
                            "ab" * 32, "cd" * 32, "cfg", ["/etc"], 0.1, 0)  # fmt: skip
    default = [
        Change("/etc/passwd", ChangeKind.MODIFIED, Severity.CRITICAL, "**/etc/passwd",
               [AttrDelta("digest", "sha256:" + "1" * 64, "sha256:" + "2" * 64), AttrDelta("mode", 0o644, 0o4755)],
               ["setuid bit set on file"]),
        Change("/etc/<script>x</script>", ChangeKind.ADDED, Severity.LOW),
        Change("/etc/b", ChangeKind.MOVED, Severity.MEDIUM, old_path="/etc/a"),
    ]  # fmt: skip
    return Report(default if changes is None else changes, baseline, ScanStats(files=3, dirs=1),
                  "2026-01-02T00:00:00+00:00", "host", "linux", notes=["a note"])  # fmt: skip


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_renders(fmt: str) -> None:
    out = render(sample_report(), fmt, Style(io.StringIO(), color=False))
    assert "/etc/passwd" in out
    assert render(sample_report([]), fmt)


def test_terminal_plain_and_colour() -> None:
    plain = render(sample_report(), "terminal", Style(io.StringIO(), color=False, unicode=False))
    assert "\x1b[" not in plain
    assert "CRITICAL" in plain and "rwsr-xr-x (4755)" in plain and "->" in plain
    coloured = render(sample_report(), "terminal", Style(io.StringIO(), color=True, unicode=True))
    assert "\x1b[" in coloured and "→" in coloured
    assert "No changes" in render(sample_report([]), "terminal")


def test_json_structure() -> None:
    data = json.loads(render(sample_report(), "json"))
    assert data["summary"]["critical"] == 1
    assert data["changes"][0]["deltas"][1] == {"name": "mode", "old": 0o644, "new": 0o4755}
    assert data["tool"]["name"] == "tessera"


def test_html_escapes_content() -> None:
    html = render(sample_report(), "html")
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html
    assert "jullewz" in html


def test_sarif_levels() -> None:
    doc = json.loads(render(sample_report(), "sarif"))
    results = doc["runs"][0]["results"]
    assert doc["version"] == "2.1.0"
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "note"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("file:")


def test_sarif_uris_for_both_path_styles() -> None:
    from tessera.reporters.sarif import _uri

    assert _uri("/etc/my file") == "file:///etc/my%20file"
    assert _uri("C:\\Windows\\hosts") == "file:///C:/Windows/hosts"
    assert _uri("relative/x") == "relative/x"


def test_markdown_table_escaping() -> None:
    md = render(sample_report([Change("/a|b", ChangeKind.ADDED, Severity.LOW)]), "markdown")
    assert "`/a\\|b`" in md


def test_unknown_format() -> None:
    with pytest.raises(ValueError):
        get_renderer("pdf")


def test_term_helpers() -> None:
    assert visible_len("\x1b[1mabc\x1b[0m") == 3
    assert shorten("/a/very/long/path/to/some/file.txt", 16).count("…") == 1
    assert len(shorten("/a/very/long/path/to/some/file.txt", 16)) == 16
    assert shorten("short", 16) == "short"
