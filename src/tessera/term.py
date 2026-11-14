"""Terminal styling: colour detection, the Tessera palette and layout helpers.

Honours ``NO_COLOR`` (https://no-color.org) and ``FORCE_COLOR``. On
Windows 10+ ANSI processing is switched on through the console API, with a
plain-text fallback when the console refuses.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import TextIO

from tessera.models import ScanStats, Severity
from tessera.osinfo import enable_windows_vt_mode
from tessera.util import format_size

# Obsidian, graphite and electric violet.
PALETTE = {
    "accent": "38;2;167;139;250",  # violet-400
    "accent_strong": "1;38;2;196;181;253",
    "muted": "38;2;113;113;122",  # graphite / zinc-500
    "text": "38;2;228;228;231",
    "ok": "38;2;52;211;153",
    "path": "38;2;228;228;231",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: "1;38;2;255;255;255;48;2;190;24;93",
    Severity.HIGH: "1;38;2;251;113;133",
    Severity.MEDIUM: "38;2;251;191;36",
    Severity.LOW: "38;2;125;211;252",
    Severity.INFO: "38;2;161;161;170",
}


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return enable_windows_vt_mode()


def supports_unicode(stream: TextIO) -> bool:
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        "─│→✓✗●".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


class Style:
    """Applies ANSI styles when enabled and returns plain text otherwise."""

    def __init__(self, stream: TextIO, *, color: bool | None = None, unicode: bool | None = None) -> None:
        self.stream = stream
        self.color = supports_color(stream) if color is None else color
        self.unicode = supports_unicode(stream) if unicode is None else unicode
        if self.unicode:
            self.sym = {"arrow": "→", "rule": "─", "bullet": "●", "ok": "✓", "fail": "✗",
                        "bar": "│", "corner": "╰", "dot": "·"}  # fmt: skip
        else:
            self.sym = {"arrow": "->", "rule": "-", "bullet": "*", "ok": "OK", "fail": "X",
                        "bar": "|", "corner": "`", "dot": "."}  # fmt: skip

    def paint(self, text: str, code: str) -> str:
        if not self.color or not code:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def __call__(self, text: str, role: str) -> str:
        return self.paint(text, PALETTE.get(role, ""))

    def severity(self, sev: Severity, text: str | None = None) -> str:
        label = text if text is not None else sev.label.upper()
        return self.paint(label, SEVERITY_STYLE[sev])

    def bold(self, text: str) -> str:
        return self.paint(text, "1")

    def width(self) -> int:
        return max(60, min(120, shutil.get_terminal_size((100, 24)).columns))

    def rule(self, title: str = "") -> str:
        width = self.width()
        if not title:
            return self(self.sym["rule"] * width, "muted")
        head = f"{self.sym['rule'] * 2} "
        tail = self.sym["rule"] * max(2, width - len(title) - len(head) - 1)
        return self(head, "muted") + self(title, "accent_strong") + " " + self(tail, "muted")


def visible_len(text: str) -> int:
    """Length of ``text`` without ANSI escape sequences."""
    length, i = 0, 0
    while i < len(text):
        if text[i] == "\x1b":
            end = text.find("m", i)
            i = end + 1 if end >= 0 else len(text)
            continue
        length += 1
        i += 1
    return length


def shorten(text: str, limit: int) -> str:
    if len(text) <= limit or limit < 8:
        return text
    keep = limit - 1
    head = keep // 3
    return text[:head] + "…" + text[len(text) - (keep - head) :]


class Progress:
    """Single-line progress indicator written to stderr while scanning."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, stream: TextIO | None = None, *, enabled: bool | None = None) -> None:
        self.stream = stream or sys.stderr
        isatty = getattr(self.stream, "isatty", None)
        self.enabled = bool(isatty and isatty()) if enabled is None else enabled
        self.style = Style(self.stream)
        self._frame = 0

    def update(self, stats: ScanStats) -> None:
        if not self.enabled:
            return
        frames = self.FRAMES if self.style.unicode else "|/-\\"
        self._frame = (self._frame + 1) % len(frames)
        line = (
            f"{self.style(frames[self._frame], 'accent')} scanning  "
            f"{stats.entries:,} entries  {stats.hashed_files:,} hashed  "
            f"{format_size(stats.hashed_bytes)}"
        )
        self.stream.write("\r\x1b[2K" + line if self.style.color else "\r" + line)
        self.stream.flush()

    def done(self) -> None:
        if self.enabled:
            self.stream.write("\r\x1b[2K" if self.style.color else "\r" + " " * 70 + "\r")
            self.stream.flush()
