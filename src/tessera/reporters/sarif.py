"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from tessera import __url__, __version__
from tessera.models import ChangeKind, Report, Severity
from tessera.reporters.common import delta_text
from tessera.term import Style

_DRIVE = re.compile(r"^[A-Za-z]:/")

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
          Severity.LOW: "3.0", Severity.INFO: "1.0"}  # fmt: skip


def _uri(path: str) -> str:
    """``file://`` URI for POSIX (``/etc/x``) and Windows (``C:\\x``) paths on any host."""
    norm = path.replace("\\", "/")
    if _DRIVE.match(norm):
        return "file:///" + quote(norm, safe="/:")
    if norm.startswith("/"):
        return "file://" + quote(norm, safe="/")
    return quote(norm, safe="/")


def render(report: Report, style: Style | None = None) -> str:
    rules: list[dict[str, Any]] = [
        {
            "id": f"tessera/{kind.value}",
            "name": kind.value.replace("_", " ").title().replace(" ", ""),
            "shortDescription": {"text": f"File {kind.value.replace('_', ' ')}"},
            "helpUri": f"{__url__}/blob/main/docs/change-kinds.md#{kind.value}",
        }
        for kind in ChangeKind
    ]
    results = []
    for change in report.changes:
        details = [f"{label}: {text}" for label, text in (delta_text(d) for d in change.deltas)]
        message = f"{change.kind.value.replace('_', ' ')}: {change.path}"
        if change.old_path:
            message += f" (from {change.old_path})"
        if details or change.reasons:
            message += ". " + "; ".join(details + change.reasons)
        results.append({
            "ruleId": f"tessera/{change.kind.value}",
            "level": _LEVEL[change.severity],
            "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(change.path)}}}],
            "properties": {"severity": change.severity.label,
                           "security-severity": _SCORE[change.severity],
                           "rule": change.rule},
        })  # fmt: skip
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tessera", "version": __version__,
                                "informationUri": __url__, "rules": rules}},
            "results": results,
        }],
    }  # fmt: skip
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
