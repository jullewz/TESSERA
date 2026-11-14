"""Machine-readable JSON report."""

from __future__ import annotations

import json

from tessera.models import Report
from tessera.term import Style


def render(report: Report, style: Style | None = None) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
