"""Watch mode: re-scan on an interval and alert on new changes only.

Polling is deliberate. It works the same on Linux, macOS and Windows, it
survives event-queue overflows, and it catches changes made while Tessera
was not running. Each cycle compares against the same sealed baseline, and
a change is reported once until it disappears or changes again.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tessera import engine, hooks
from tessera.config import Config
from tessera.models import Report
from tessera.store import BaselineStore

log = logging.getLogger(__name__)

ReportSink = Callable[[Report, int], None]


@dataclass(slots=True)
class WatchState:
    cycles: int = 0
    alerts: int = 0
    seen: set[str] = field(default_factory=set)


class Watcher:
    def __init__(
        self,
        config: Config,
        store: BaselineStore,
        *,
        interval: float = 60.0,
        baseline_id: int | None = None,
        key: bytes | None = None,
        sink: ReportSink | None = None,
        run_hooks: bool = True,
    ) -> None:
        if interval < 1:
            raise ValueError("interval must be at least 1 second")
        self.config = config
        self.store = store
        self.interval = interval
        self.baseline_id = baseline_id
        self.key = key
        self.sink = sink
        self.run_hooks = run_hooks
        self.state = WatchState()
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def cycle(self) -> Report:
        """Run one scan and return a report holding only *new* changes."""
        result = engine.check(self.config, self.store, baseline_id=self.baseline_id, key=self.key,
                              min_severity=self.config.report.min_severity)  # fmt: skip
        current = {c.fingerprint(): c for c in result.report.changes}
        fresh = [c for fp, c in current.items() if fp not in self.state.seen]
        self.state.seen = set(current)
        self.state.cycles += 1
        report = result.report
        report.changes = fresh
        report.title = f"Watch cycle {self.state.cycles}"
        if self.state.cycles > 1:
            report.notes = [n for n in report.notes if "INVALID" in n or "modified" in n]
        if fresh:
            self.state.alerts += len(fresh)
            if self.run_hooks and self.config.hooks:
                hooks.run_hooks(self.config.hooks, report)
        return report

    def run(self, max_cycles: int | None = None) -> WatchState:
        log.info("watching %d root(s) every %gs", len(self.config.roots), self.interval)
        while not self._stop.is_set():
            started = time.monotonic()
            report = self.cycle()
            if self.sink:
                self.sink(report, self.state.cycles)
            if max_cycles is not None and self.state.cycles >= max_cycles:
                break
            remaining = self.interval - (time.monotonic() - started)
            if remaining > 0 and self._stop.wait(remaining):
                break
        return self.state
