from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from tessera.config import HookConfig
from tessera.hooks import run_hooks
from tessera.models import Change, ChangeKind, Report, Severity

from .conftest import python_cmd


def report(*severities: Severity) -> Report:
    changes = [Change(f"/f{i}", ChangeKind.ADDED, s) for i, s in enumerate(severities)]
    return Report(changes, None, None, "now", "host", "linux")


def test_command_receives_filtered_json(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    script = tmp_path / "hook.py"
    script.write_text(f"import sys; open({str(out)!r}, 'w').write(sys.stdin.read())")
    hook = HookConfig("save", command=python_cmd(str(script)), min_severity=Severity.HIGH)
    [result] = run_hooks([hook], report(Severity.LOW, Severity.CRITICAL))
    assert result.ok and not result.skipped
    data = json.loads(out.read_text())
    assert data["hook"] == "save"
    assert [c["severity"] for c in data["changes"]] == ["critical"]


def test_below_threshold_skips() -> None:
    hook = HookConfig("x", command=python_cmd("-c", "raise SystemExit(1)"), min_severity=Severity.HIGH)
    [result] = run_hooks([hook], report(Severity.LOW))
    assert result.skipped
    [result] = run_hooks([hook], report())
    assert result.skipped


def test_command_failures_are_reported() -> None:
    failing = HookConfig("f", command=python_cmd("-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"),
                         min_severity=Severity.INFO)  # fmt: skip
    missing = HookConfig("m", command=["definitely-not-a-real-binary-xyz"], min_severity=Severity.INFO)
    slow = HookConfig("s", command=python_cmd("-c", "import time; time.sleep(5)"), min_severity=Severity.INFO,
                      timeout=0.3)  # fmt: skip
    results = run_hooks([failing, missing, slow], report(Severity.HIGH))
    assert [r.ok for r in results] == [False, False, False]
    assert "exit code 3: boom" in results[0].detail
    assert "not found" in results[1].detail
    assert "timed out" in results[2].detail


def test_webhook_post() -> None:
    received: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            received["body"] = json.loads(self.rfile.read(length))
            received["auth"] = self.headers.get("Authorization")
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/hook"
    hook = HookConfig("w", url=url, min_severity=Severity.LOW, headers={"Authorization": "Bearer t"})
    [result] = run_hooks([hook], report(Severity.HIGH))
    thread.join(5)
    server.server_close()
    assert result.ok and result.detail == "HTTP 204"
    assert received["auth"] == "Bearer t"
    assert isinstance(received["body"], dict) and received["body"]["hook"] == "w"


def test_webhook_unreachable() -> None:
    hook = HookConfig("w", url="http://127.0.0.1:9/none", min_severity=Severity.LOW, timeout=1)
    [result] = run_hooks([hook], report(Severity.HIGH))
    assert not result.ok and "request failed" in result.detail
