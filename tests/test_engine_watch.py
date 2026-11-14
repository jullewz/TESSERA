from __future__ import annotations

import sqlite3
from pathlib import Path

from tessera import engine, sealing
from tessera.models import ChangeKind, Severity
from tessera.store import BaselineStore
from tessera.watch import Watcher

from .conftest import ConfigFactory


def test_snapshot_check_roundtrip(make_config: ConfigFactory, tree: Path) -> None:
    config = make_config()
    key = sealing.load_key(sealing.generate_key(config.key_file))
    with BaselineStore(config.store) as store:
        saved = engine.save_snapshot(config, store, engine.scan(config), key=key, label="t")
        assert saved.sealed and saved.baseline.seal
        clean = engine.check(config, store, key=key)
        assert clean.report.changes == [] and clean.seal_status == "valid"

        (tree / "etc" / "passwd").write_text("root:x:0:0\nevil:x:0:0\n")
        (tree / "etc" / "new.conf").write_text("x")
        dirty = engine.check(config, store, key=key)
        by_path = {c.path: c for c in dirty.report.changes}
        assert by_path[str(tree / "etc" / "passwd")].severity is Severity.CRITICAL
        assert by_path[str(tree / "etc" / "new.conf")].kind is ChangeKind.ADDED
        assert engine.exit_code_for(dirty.report.changes, Severity.LOW) == 1
        assert engine.exit_code_for(dirty.report.changes, Severity.CRITICAL) == 1

        only_critical = engine.check(config, store, key=key, min_severity=Severity.CRITICAL)
        assert all(c.severity is Severity.CRITICAL for c in only_critical.report.changes)


def test_check_flags_store_tampering(make_config: ConfigFactory) -> None:
    config = make_config()
    key = sealing.load_key(sealing.generate_key(config.key_file))
    with BaselineStore(config.store) as store:
        bid = engine.save_snapshot(config, store, engine.scan(config), key=key).baseline.id
    conn = sqlite3.connect(config.store)
    conn.execute("UPDATE files SET digest = 'sha256:00' WHERE baseline_id = ? AND path LIKE '%passwd'", (bid,))
    conn.commit()
    conn.close()
    with BaselineStore(config.store) as store:
        result = engine.check(config, store, key=key)
    assert result.seal_status == "invalid"
    assert any("Merkle root" in n for n in result.report.notes)


def test_unsealed_and_policy_drift_notes(make_config: ConfigFactory) -> None:
    config = make_config()
    with BaselineStore(config.store) as store:
        engine.save_snapshot(config, store, engine.scan(config))
        changed = make_config(rule=[{"pattern": "**", "profile": "content"}])
        result = engine.check(changed, store)
    assert result.seal_status == "unsealed"
    assert any("configuration changed" in n for n in result.report.notes)


def test_compare_baselines(make_config: ConfigFactory, tree: Path) -> None:
    config = make_config()
    with BaselineStore(config.store) as store:
        a = engine.save_snapshot(config, store, engine.scan(config)).baseline.id
        (tree / "etc" / "motd").unlink()
        b = engine.save_snapshot(config, store, engine.scan(config)).baseline.id
        report = engine.compare_baselines(config, store, a, b)
    assert [c.kind for c in report.changes] == [ChangeKind.REMOVED]


def test_watcher_reports_each_change_once(make_config: ConfigFactory, tree: Path) -> None:
    config = make_config()
    with BaselineStore(config.store) as store:
        engine.save_snapshot(config, store, engine.scan(config))
        seen: list[int] = []
        watcher = Watcher(config, store, interval=1, sink=lambda r, c: seen.append(len(r.changes)),
                          run_hooks=False)  # fmt: skip
        assert watcher.cycle().changes == []
        (tree / "etc" / "app.conf").write_text("debug = true\n")
        assert len(watcher.cycle().changes) == 1
        assert watcher.cycle().changes == []
        (tree / "etc" / "app.conf").write_text("debug = maybe\n")
        assert len(watcher.cycle().changes) == 1
        assert watcher.state.alerts == 2

        assert watcher.run(max_cycles=5).cycles == 5  # four cycles above, one more here
        watcher.stop()
        assert watcher.run(max_cycles=10).cycles == 5  # a stopped watcher does not scan again
