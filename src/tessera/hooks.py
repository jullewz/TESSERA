"""Alert hooks: run a command or POST to a webhook when changes are found.

Commands receive the JSON report on standard input. They are started
without a shell (``shell=False``), so report content can never be
interpreted as shell syntax.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass

from tessera import __version__
from tessera.config import HookConfig
from tessera.models import Report, Severity

log = logging.getLogger(__name__)

MAX_OUTPUT = 2000


@dataclass(frozen=True, slots=True)
class HookResult:
    name: str
    ok: bool
    detail: str
    skipped: bool = False


def _payload(report: Report, hook: HookConfig) -> bytes:
    data = report.to_dict()
    data["changes"] = [c for c in data["changes"] if _sev_ok(c["severity"], hook)]
    data["hook"] = hook.name
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def _sev_ok(label: str, hook: HookConfig) -> bool:
    return Severity.parse(label) >= hook.min_severity


def _run_command(hook: HookConfig, body: bytes) -> HookResult:
    assert hook.command is not None
    program = shutil.which(hook.command[0])
    if program is None:
        return HookResult(hook.name, False, f"command not found: {hook.command[0]}")
    try:
        proc = subprocess.run(
            [program, *hook.command[1:]],
            input=body,
            capture_output=True,
            timeout=hook.timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return HookResult(hook.name, False, f"command not found: {hook.command[0]}")
    except subprocess.TimeoutExpired:
        return HookResult(hook.name, False, f"timed out after {hook.timeout:g}s")
    except OSError as exc:
        return HookResult(hook.name, False, f"cannot start command: {exc}")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()[:MAX_OUTPUT]
        return HookResult(hook.name, False, f"exit code {proc.returncode}" + (f": {err}" if err else ""))
    return HookResult(hook.name, True, "command succeeded")


def _post(hook: HookConfig, body: bytes) -> HookResult:
    assert hook.url is not None
    if not hook.url.startswith(("https://", "http://")):
        return HookResult(hook.name, False, "refusing non-HTTP URL")
    headers = {"Content-Type": "application/json", "User-Agent": f"tessera/{__version__}"}
    headers.update(hook.headers)
    # The scheme is restricted to http(s) above and during config validation.
    request = urllib.request.Request(hook.url, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=hook.timeout) as response:  # noqa: S310
            status = response.status
    except urllib.error.HTTPError as exc:
        return HookResult(hook.name, False, f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return HookResult(hook.name, False, f"request failed: {reason}")
    return HookResult(hook.name, 200 <= status < 300, f"HTTP {status}")


def run_hooks(hooks: Iterable[HookConfig], report: Report) -> list[HookResult]:
    """Trigger each hook whose ``min_severity`` is reached by the report."""
    results: list[HookResult] = []
    highest = report.highest
    for hook in hooks:
        if highest is None or highest < hook.min_severity:
            results.append(HookResult(hook.name, True, "below threshold", skipped=True))
            continue
        body = _payload(report, hook)
        result = _run_command(hook, body) if hook.command else _post(hook, body)
        if result.ok:
            log.info("hook %s: %s", hook.name, result.detail)
        else:
            log.warning("hook %s failed: %s", hook.name, result.detail)
        results.append(result)
    return results
