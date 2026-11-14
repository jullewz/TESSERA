from __future__ import annotations

import pytest

from tessera.matcher import GlobSet, compile_glob, glob_match


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/etc/**", "/etc", True),
        ("/etc/**", "/etc/ssh/sshd_config", True),
        ("/etc/**", "/etcetera/x", False),
        ("*.log", "/var/log/syslog.log", True),
        ("*.log", "/var/log/syslog.log.1", False),
        ("**/*.log", "/a.log", True),
        ("**/cron.d/*", "/etc/cron.d/job", True),
        ("**/cron.d/*", "/etc/cron.d/sub/job", False),
        ("/usr/*/bin", "/usr/local/bin", True),
        ("/usr/*/bin", "/usr/a/b/bin", False),
        ("/a/?.txt", "/a/x.txt", True),
        ("/a/?.txt", "/a/xy.txt", False),
        ("/a/[abc].txt", "/a/b.txt", True),
        ("/a/[!abc].txt", "/a/b.txt", False),
        ("/etc/{passwd,shadow}", "/etc/shadow", True),
        ("/etc/{passwd,shadow}", "/etc/group", False),
        ("**/Launch{Agents,Daemons}/**", "/Library/LaunchDaemons/x.plist", True),
        ("/a/{b,c/**}", "/a/c/d/e", True),
        ("/literal{brace", "/literal{brace", True),
        ("/a/b/", "/a/b", True),
    ],
)
def test_glob_semantics(pattern: str, path: str, expected: bool) -> None:
    assert glob_match(pattern, path) is expected


def test_windows_paths_and_case_folding() -> None:
    assert glob_match("C:/Windows/System32/**", r"C:\Windows\System32\drivers\etc\hosts")
    assert glob_match(r"C:\Windows\**", r"C:\Windows\notepad.exe")
    assert not glob_match("c:/windows/**", r"C:\Windows\x", case_sensitive=True)
    assert glob_match("c:/windows/**", r"C:\Windows\x", case_sensitive=False)


def test_regex_metacharacters_are_literal() -> None:
    assert glob_match("/a/file(1).txt", "/a/file(1).txt")
    assert not glob_match("/a/file.txt", "/a/fileXtxt")
    assert glob_match("/a/c++/x", "/a/c++/x")


def test_empty_pattern_rejected() -> None:
    with pytest.raises(ValueError):
        compile_glob("  ")


def test_globset() -> None:
    gs = GlobSet(["*.swp", "/etc/mtab"])
    assert gs.matches("/etc/.x.swp")
    assert gs.matches("/etc/mtab")
    assert not gs.matches("/etc/hosts")
    assert not GlobSet([])
