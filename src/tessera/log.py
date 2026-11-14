"""Logging setup. Logs go to stderr so stdout stays clean for reports."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from tessera.term import Style

_LEVEL_ROLE = {
    logging.DEBUG: "muted",
    logging.INFO: "accent",
    logging.WARNING: "",
    logging.ERROR: "",
}


class _ConsoleFormatter(logging.Formatter):
    def __init__(self, style: Style) -> None:
        super().__init__()
        self.style = style

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.levelno >= logging.ERROR:
            prefix = self.style.paint("error:", "1;38;2;251;113;133")
        elif record.levelno >= logging.WARNING:
            prefix = self.style.paint("warning:", "1;38;2;251;191;36")
        elif record.levelno >= logging.INFO:
            prefix = self.style("info:", "accent")
        else:
            prefix = self.style(f"debug[{record.name}]:", "muted")
        text = f"{prefix} {message}"
        if record.exc_info:
            text += "\n" + self.formatException(record.exc_info)
        return text


def setup_logging(verbosity: int = 0, *, log_file: str | None = None, color: bool | None = None) -> None:
    """Configure the ``tessera`` logger.

    ``verbosity``: -1 quiet (errors only), 0 warnings, 1 info, 2+ debug.
    """
    level = {-1: logging.ERROR, 0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)
    logger = logging.getLogger("tessera")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(_ConsoleFormatter(Style(sys.stderr, color=color)))
    logger.addHandler(console)

    if log_file:
        path = Path(log_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        logger.addHandler(handler)
