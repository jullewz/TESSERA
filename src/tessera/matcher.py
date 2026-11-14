"""Glob patterns with ``**`` support, compiled to regular expressions.

Syntax (paths always use ``/``, backslashes in patterns are treated as ``/``):

* ``*``       any run of characters except ``/``
* ``?``       one character except ``/``
* ``[abc]``   character class, ``[!abc]`` negated
* ``{a,b}``   alternatives, e.g. ``/etc/{passwd,shadow}``
* ``**``      any number of path segments, including none
* A pattern without ``/`` matches the final path component anywhere,
  e.g. ``*.log`` matches ``/var/log/syslog.log``.
"""

from __future__ import annotations

import re
from functools import lru_cache

from tessera.util import match_path


def _split_braces(pattern: str, start: int) -> tuple[int, list[str]]:
    """Find the ``}`` matching ``pattern[start]`` and split on top-level commas."""
    depth = 0
    options: list[str] = []
    current: list[str] = []
    for j in range(start + 1, len(pattern)):
        ch = pattern[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            if depth == 0:
                options.append("".join(current))
                return (j, options) if len(options) > 1 else (-1, [])
            depth -= 1
        elif ch == "," and depth == 0:
            options.append("".join(current))
            current = []
            continue
        current.append(ch)
    return -1, []


def _translate(pattern: str) -> str:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                at_start = i == 0 or pattern[i - 1] == "/"
                j = i + 2
                if at_start and j < n and pattern[j] == "/":
                    out.append("(?:.*/)?")  # "**/" -> zero or more segments
                    i = j + 1
                    continue
                if at_start and j == n and i > 0:
                    # trailing "/**": drop the slash already emitted, match the dir itself too
                    out.pop()
                    out.append("(?:/.*)?")
                    i = j
                    continue
                out.append(".*")
                i = j
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "{":
            end, options = _split_braces(pattern, i)
            if end < 0:
                out.append(re.escape(c))
            else:
                out.append("(?:" + "|".join(_translate(opt) for opt in options) + ")")
                i = end
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : j].replace("\\", "\\\\")
                if body[:1] in "!^":
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@lru_cache(maxsize=1024)
def compile_glob(pattern: str, case_sensitive: bool = True) -> re.Pattern[str]:
    """Compile a glob pattern into an anchored regular expression."""
    if not pattern.strip():
        raise ValueError("empty pattern")
    norm = match_path(pattern.strip())
    if len(norm) > 1 and norm.endswith("/") and not norm.endswith("**/"):
        norm = norm.rstrip("/")
    body = _translate(norm)
    if "/" not in norm:
        body = "(?:.*/)?" + body
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(body, flags)


class GlobSet:
    """A list of patterns that matches when any member matches."""

    def __init__(self, patterns: list[str], case_sensitive: bool = True) -> None:
        self.patterns = list(patterns)
        self._compiled = [compile_glob(p, case_sensitive) for p in self.patterns]

    def matches(self, path: str) -> bool:
        target = match_path(path)
        return any(rx.fullmatch(target) for rx in self._compiled)

    def __bool__(self) -> bool:
        return bool(self._compiled)


def glob_match(pattern: str, path: str, case_sensitive: bool = True) -> bool:
    """Return ``True`` when ``path`` matches ``pattern``."""
    return compile_glob(pattern, case_sensitive).fullmatch(match_path(path)) is not None
