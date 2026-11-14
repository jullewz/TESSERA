from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tessera.errors import BaselineNotFoundError, StoreError
from tessera.models import ScanStats, Snapshot
from tessera.store import BaselineStore

from .conftest import rec


def snap(n: int = 3) -> Snapshot:
    records = {f"/f{i}": rec(f"/f{i}", digest=f"sha256:{i}") for i in range(n)}
    return Snapshot(records, ScanStats(files=n, seconds=0.1), "2026-01-01T00:00:00+00:00", "host",
                    "linux", "sha256", ["/"])  # fmt: skip


def save(store: BaselineStore, n: int = 3, label: str | None = None) -> int:
    return store.save(snap(n), merkle_root="root", seal=None, config_digest="cfg", label=label)


def test_save_and_load(tmp_path: Path) -> None:
    with BaselineStore(tmp_path / "db" / "t.db") as store:
        bid = save(store, 4, "first")
        info = store.get(bid)
        assert info.file_count == 4 and info.label == "first" and info.roots == ["/"]
        records = store.records(bid)
        assert records == snap(4).records


def test_latest_resolve_and_list(tmp_path: Path) -> None:
    with BaselineStore(tmp_path / "t.db") as store:
        with pytest.raises(BaselineNotFoundError):
            store.resolve(None)
        a, b = save(store), save(store)
        assert store.resolve(None).id == b
        assert store.resolve(a).id == a
        assert [i.id for i in store.list()] == [b, a]
        with pytest.raises(BaselineNotFoundError):
            store.get(999)


def test_prune_and_delete(tmp_path: Path) -> None:
    with BaselineStore(tmp_path / "t.db") as store:
        ids = [save(store) for _ in range(5)]
        assert store.prune(2) == ids[:3][::-1]
        assert [i.id for i in store.list()] == ids[3:][::-1]
        assert store.records(ids[0]) == {}
        store.delete(ids[4])
        assert [i.id for i in store.list()] == [ids[3]]
        with pytest.raises(ValueError):
            store.prune(0)


def test_persistence_across_connections(tmp_path: Path) -> None:
    path = tmp_path / "t.db"
    with BaselineStore(path) as store:
        bid = save(store)
    with BaselineStore(path) as store:
        assert store.get(bid).file_count == 3


def test_rejects_garbage_and_newer_schema(tmp_path: Path) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"definitely not sqlite" * 100)
    with pytest.raises(StoreError):
        BaselineStore(junk)
    path = tmp_path / "t.db"
    BaselineStore(path).close()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    with pytest.raises(StoreError, match="newer Tessera"):
        BaselineStore(path)
