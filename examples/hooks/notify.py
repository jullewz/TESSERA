#!/usr/bin/env python3
"""Example Tessera hook: append findings to a log and show a desktop notification.

Tessera writes the JSON report to this script's standard input. Configure it with:

    [[hook]]
    name = "notify"
    command = ["python3", "/path/to/examples/hooks/notify.py"]
    min_severity = "high"

Works on Linux (notify-send), macOS (osascript) and Windows (PowerShell toast), and
falls back to the log file alone when no notifier is available. Standard library only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

LOG = Path(os.environ.get("TESSERA_HOOK_LOG", Path.home() / "tessera-alerts.log"))


def notify(title: str, body: str) -> None:
    osascript, powershell, notify_send = (shutil.which(n) for n in ("osascript", "powershell", "notify-send"))
    if sys.platform == "darwin" and osascript:
        script = f"display notification {json.dumps(body)} with title {json.dumps(title)}"
        subprocess.run([osascript, "-e", script], check=False, timeout=10)
    elif sys.platform.startswith("win") and powershell:
        ps = (
            "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
            "$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Warning;"
            "$n.Visible=$true;$n.ShowBalloonTip(10000,$env:T_TITLE,$env:T_BODY,'Warning');Start-Sleep 11"
        )
        env = {**os.environ, "T_TITLE": title, "T_BODY": body}
        subprocess.run([powershell, "-NoProfile", "-Command", ps], check=False, timeout=20, env=env)
    elif notify_send:
        subprocess.run([notify_send, "--urgency=critical", title, body], check=False, timeout=10)


def main() -> int:
    report = json.load(sys.stdin)
    changes = report.get("changes", [])
    if not changes:
        return 0
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    with LOG.open("a", encoding="utf-8") as fh:
        for change in changes:
            fh.write(f"{stamp} {report['host']} {change['severity'].upper():8} {change['kind']:12} {change['path']}\n")
    worst = changes[0]
    notify(
        f"Tessera: {len(changes)} change(s) on {report['host']}",
        f"{worst['severity'].upper()} {worst['kind']}: {worst['path']}",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
