"""Self-contained HTML report: one file, no external requests, dark theme."""

from __future__ import annotations

from html import escape

from tessera import __url__, __version__
from tessera.models import Change, Report, Severity
from tessera.reporters.common import KIND_LABEL, delta_text
from tessera.term import Style
from tessera.util import format_duration, format_size

_CSS = """
:root{--bg:#09090b;--panel:#111114;--panel2:#17171c;--line:#26262d;--text:#e4e4e7;
--muted:#8b8b96;--accent:#a78bfa;--accent2:#c4b5fd;--glow:rgba(167,139,250,.14);
--critical:#e11d74;--high:#fb7185;--medium:#fbbf24;--low:#7dd3fc;--info:#a1a1aa;
--mono:"JetBrains Mono","Cascadia Code","SF Mono",ui-monospace,Menlo,Consolas,monospace;
--sans:Inter,"Segoe UI",system-ui,-apple-system,sans-serif}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,var(--glow),transparent 60%),var(--bg);
color:var(--text);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased;min-height:100vh}
.wrap{max-width:1180px;margin:0 auto;padding:40px 28px 64px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;flex-wrap:wrap;
border-bottom:1px solid var(--line);padding-bottom:22px}
.brand{display:flex;align-items:center;gap:12px;font:600 13px var(--mono);letter-spacing:.18em;
text-transform:uppercase;color:var(--accent2)}
.mark{width:22px;height:22px;display:grid;grid-template-columns:1fr 1fr;gap:3px}
.mark i{border-radius:2px;background:var(--accent)}.mark i:nth-child(2){opacity:.55}
.mark i:nth-child(3){opacity:.3}.mark i:nth-child(4){opacity:.8}
h1{margin:10px 0 0;font-size:28px;font-weight:650;letter-spacing:-.02em}
.meta{color:var(--muted);font:12px var(--mono);text-align:right;line-height:1.8}
.meta b{color:var(--text);font-weight:500}
.notes{margin:20px 0 0;padding:0;list-style:none;display:grid;gap:8px}
.notes li{border:1px solid rgba(251,191,36,.3);background:rgba(251,191,36,.06);color:#fde68a;
border-radius:8px;padding:9px 14px;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:26px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;
cursor:pointer;transition:border-color .15s,transform .15s;user-select:none}
.card:hover{border-color:#3a3a44;transform:translateY(-1px)}
.card.off{opacity:.38}
.card .n{font:600 26px var(--mono);letter-spacing:-.03em}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.card.total .n{color:var(--accent2)}
.toolbar{display:flex;gap:12px;align-items:center;margin-bottom:14px}
input[type=search]{flex:1;background:var(--panel);border:1px solid var(--line);border-radius:10px;
color:var(--text);padding:11px 14px;font:13px var(--mono);outline:none;transition:border-color .15s}
input[type=search]:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
.count{color:var(--muted);font:12px var(--mono);white-space:nowrap}
.list{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--panel)}
details{border-top:1px solid var(--line)}details:first-child{border-top:0}
summary{display:grid;grid-template-columns:96px 96px 1fr;gap:14px;align-items:center;
padding:12px 18px;cursor:pointer;list-style:none;transition:background .12s}
summary::-webkit-details-marker{display:none}
summary:hover{background:var(--panel2)}
.sev{font:600 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;
border-radius:999px;justify-self:start;border:1px solid currentColor}
.sev.critical{background:var(--critical);border-color:var(--critical);color:#fff}
.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}.sev.low{color:var(--low)}
.sev.info{color:var(--info)}
.kind{font:12px var(--mono);color:var(--accent)}
.path{font:13px var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;
text-align:left}
.body{padding:4px 18px 16px 238px;font:12.5px var(--mono);color:var(--muted)}
.body table{border-collapse:collapse}
.body td{padding:3px 18px 3px 0;vertical-align:top}
.body td:first-child{color:#6b6b76;text-transform:uppercase;font-size:11px;letter-spacing:.08em}
.body .v{color:var(--text);word-break:break-all}
.reason{color:var(--accent2)}.reason:before{content:"\\25CF  ";color:var(--accent)}
.empty{padding:56px;text-align:center;color:var(--muted)}
.empty b{display:block;color:#6ee7b7;font-size:18px;margin-bottom:6px}
footer{margin-top:34px;color:#5d5d68;font:12px var(--mono);display:flex;justify-content:space-between;
flex-wrap:wrap;gap:12px}
footer a{color:var(--accent);text-decoration:none}
@media (max-width:760px){summary{grid-template-columns:84px 1fr}.kind{display:none}
.body{padding-left:18px}.meta{text-align:left}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

_JS = """
(()=>{const cards=[...document.querySelectorAll('.card[data-sev]')];
const rows=[...document.querySelectorAll('details[data-sev]')];
const q=document.getElementById('q');const count=document.getElementById('count');
const off=new Set();
function apply(){const t=(q.value||'').toLowerCase();let shown=0;
rows.forEach(r=>{const ok=!off.has(r.dataset.sev)&&r.dataset.text.includes(t);
r.style.display=ok?'':'none';if(ok)shown++;});
if(count)count.textContent=shown+' of '+rows.length+' shown';}
cards.forEach(c=>c.addEventListener('click',()=>{const s=c.dataset.sev;
off.has(s)?off.delete(s):off.add(s);c.classList.toggle('off');apply();}));
if(q)q.addEventListener('input',apply);apply();})();
"""


def _row(change: Change) -> str:
    sev = change.severity.label
    details: list[tuple[str, str]] = []
    if change.old_path:
        details.append(("from", change.old_path))
    details += [delta_text(d, "→") for d in change.deltas]
    if change.rule:
        details.append(("rule", change.rule))
    body_rows = "".join(
        f"<tr><td>{escape(label)}</td><td class=v>{escape(value)}</td></tr>" for label, value in details
    )
    reasons = "".join(f"<div class=reason>{escape(r)}</div>" for r in change.reasons)
    search = escape(f"{change.path} {change.kind.value} {' '.join(change.reasons)}".lower(), quote=True)
    path = escape(change.path)
    opened = " open" if change.severity is Severity.CRITICAL else ""
    return (
        f'<details data-sev="{sev}" data-text="{search}"{opened}><summary>'
        f'<span class="sev {sev}">{sev}</span><span class=kind>{KIND_LABEL[change.kind]}</span>'
        f'<span class=path title="{path}"><bdi>{path}</bdi></span></summary>'
        f"<div class=body><table>{body_rows}</table>{reasons}</div></details>"
    )


def render(report: Report, style: Style | None = None) -> str:
    counts = report.counts()
    meta = [f"host <b>{escape(report.host)}</b> &middot; {escape(report.platform)}",
            f"generated <b>{escape(report.generated_at)}</b>"]  # fmt: skip
    if report.baseline:
        b = report.baseline
        meta.append(f"baseline <b>#{b.id}</b> &middot; {escape(b.created_at)}")
    if report.stats:
        st = report.stats
        meta.append(f"<b>{st.entries:,}</b> entries &middot; {escape(format_size(st.hashed_bytes))} hashed"
                    f" &middot; {escape(format_duration(st.seconds))}")  # fmt: skip

    cards = [f'<div class="card total"><div class=n>{len(report.changes)}</div><div class=l>changes</div></div>']
    for sev in sorted(Severity, reverse=True):
        cards.append(
            f'<div class=card data-sev="{sev.label}"><div class=n style="color:var(--{sev.label})">'
            f"{counts[sev]}</div><div class=l>{sev.label}</div></div>"
        )
    notes = "".join(f"<li>{escape(n)}</li>" for n in report.notes)
    if report.changes:
        listing = (
            '<div class=toolbar><input id=q type=search placeholder="Filter by path, change or reason"'
            " autocomplete=off spellcheck=false><span class=count id=count></span></div>"
            f"<div class=list>{''.join(_row(c) for c in report.changes)}</div>"
        )
    else:
        listing = ('<div class="list empty"><b>No changes</b>Everything matches the sealed baseline.'
                   "</div>")  # fmt: skip

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Tessera &middot; {escape(report.title)}</title>
<style>{_CSS}</style></head>
<body><div class=wrap>
<header><div><div class=brand><span class=mark><i></i><i></i><i></i><i></i></span>tessera</div>
<h1>{escape(report.title)}</h1></div><div class=meta>{"<br>".join(meta)}</div></header>
{f"<ul class=notes>{notes}</ul>" if notes else ""}
<div class=cards>{"".join(cards)}</div>
{listing}
<footer><span>tessera {escape(__version__)} &middot; tamper-evident integrity monitoring</span>
<span>Created by <a href="https://github.com/jullewz">jullewz</a> &middot;
<a href="{escape(__url__)}">source</a></span></footer>
</div><script>{_JS}</script></body></html>
"""
