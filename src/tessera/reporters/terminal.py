"""Rich, colour-aware terminal report."""

from __future__ import annotations

import io

from tessera.models import Report, Severity
from tessera.reporters.common import KIND_LABEL, delta_text
from tessera.term import Style, shorten
from tessera.util import format_duration, format_size


def render(report: Report, style: Style | None = None) -> str:
    s = style or Style(io.StringIO(), color=False, unicode=True)
    out: list[str] = []
    width = s.width()

    out.append(s.rule(f"tessera {s.sym['dot']} {report.title}"))
    meta = [f"{s('host', 'muted')} {report.host}", f"{s('platform', 'muted')} {report.platform}"]
    if report.baseline:
        b = report.baseline
        label = f" {b.label}" if b.label else ""
        meta.append(f"{s('baseline', 'muted')} {s('#' + str(b.id), 'accent')}{label} "
                    f"{s(b.created_at, 'muted')}")  # fmt: skip
    out.append("  " + "   ".join(meta))
    if report.stats:
        st = report.stats
        out.append(
            "  "
            + s(
                f"scanned {st.entries:,} entries ({st.files:,} files, {st.dirs:,} dirs)  "
                f"hashed {format_size(st.hashed_bytes)}  in {format_duration(st.seconds)}"
                + (f"  {st.errors} unreadable" if st.errors else ""),
                "muted",
            )
        )
    for note in report.notes:
        out.append(f"  {s.paint('!', '1;38;2;251;191;36')} {note}")
    out.append("")

    if not report.changes:
        out.append(f"  {s(s.sym['ok'], 'ok')} {s.bold('No changes.')} "
                   f"{s('Everything matches the baseline.', 'muted')}")  # fmt: skip
        out.append("")
        return "\n".join(out) + "\n"

    counts = report.counts()
    badges = [
        f"{s.severity(sev, f'{counts[sev]} {sev.label}')}" for sev in sorted(Severity, reverse=True) if counts[sev]
    ]
    out.append(f"  {s.bold(str(len(report.changes)))} change(s)   " + "  ".join(badges))
    out.append("")

    path_width = max(30, width - 26)
    for change in report.changes:
        sev = s.severity(change.severity, f"{change.severity.label.upper():<8}")
        kind = s(f"{KIND_LABEL[change.kind]:<10}", "accent")
        out.append(f"  {sev} {kind} {s(shorten(change.path, path_width), 'path')}")
        indent = "  " + " " * 9 + " " * 11
        if change.old_path:
            out.append(f"{indent}{s('from', 'muted')} {shorten(change.old_path, path_width - 5)}")
        for delta in change.deltas:
            label, text = delta_text(delta, s.sym["arrow"])
            out.append(f"{indent}{s(f'{label:<8}', 'muted')} {text}")
        for reason in change.reasons:
            out.append(f"{indent}{s(s.sym['bullet'], 'accent')} {reason}")
        if change.rule:
            out.append(f"{indent}{s('rule ' + change.rule, 'muted')}")
    out.append("")
    return "\n".join(out) + "\n"
