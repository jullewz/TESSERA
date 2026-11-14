"""Report renderers. Each module exposes ``render(report, style) -> str``."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tessera.models import Report
    from tessera.term import Style

FORMATS: tuple[str, ...] = ("terminal", "json", "markdown", "html", "sarif")

_MODULES = {
    "terminal": "tessera.reporters.terminal",
    "json": "tessera.reporters.json_report",
    "markdown": "tessera.reporters.markdown",
    "html": "tessera.reporters.html",
    "sarif": "tessera.reporters.sarif",
}

Renderer = Callable[["Report", "Style | None"], str]


def get_renderer(name: str) -> Renderer:
    if name not in _MODULES:
        raise ValueError(f"unknown report format {name!r}, expected one of: {', '.join(FORMATS)}")
    module = importlib.import_module(_MODULES[name])
    renderer: Renderer = module.render
    return renderer


def render(report: Report, fmt: str, style: Style | None = None) -> str:
    return get_renderer(fmt)(report, style)
