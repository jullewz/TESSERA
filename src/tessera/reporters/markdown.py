"""Markdown report, suited to pull-request comments and tickets."""

from __future__ import annotations

from tessera.models import Report, Severity
from tessera.reporters.common import KIND_LABEL, delta_text
from tessera.term import Style


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render(report: Report, style: Style | None = None) -> str:
    lines = [f"# Tessera: {report.title}", ""]
    lines.append(f"- **Host:** {report.host} ({report.platform})")
    lines.append(f"- **Generated:** {report.generated_at}")
    if report.baseline:
        b = report.baseline
        lines.append(f"- **Baseline:** #{b.id} from {b.created_at}" + (f" ({b.label})" if b.label else ""))
    if report.stats:
        lines.append(f"- **Scanned:** {report.stats.entries:,} entries")
    for note in report.notes:
        lines.append(f"- **Note:** {note}")
    lines.append("")

    if not report.changes:
        lines += ["**No changes.** Everything matches the baseline.", ""]
        return "\n".join(lines)

    counts = report.counts()
    summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s])
    lines += [f"**{len(report.changes)} change(s):** {summary}", ""]
    lines += ["| Severity | Change | Path | Details |", "|---|---|---|---|"]
    for c in report.changes:
        details = [f"{label}: {text}" for label, text in (delta_text(d) for d in c.deltas)]
        if c.old_path:
            details.insert(0, f"from {c.old_path}")
        details += c.reasons
        lines.append(
            f"| {c.severity.label} | {KIND_LABEL[c.kind]} | `{_cell(c.path)}` | {_cell('; '.join(details)) or '-'} |"
        )
    lines.append("")
    return "\n".join(lines)
