"""SQLite baseline store.

One database file holds every baseline. Records of a baseline are written
in a single transaction, so a crash never leaves a half-written baseline.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType

from tessera.errors import BaselineNotFoundError, StoreError
from tessera.models import BaselineInfo, EntryKind, FileRecord, Snapshot

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS baselines (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT    NOT NULL,
    label         TEXT,
    host          TEXT    NOT NULL,
    platform      TEXT    NOT NULL,
    algorithm     TEXT    NOT NULL,
    file_count    INTEGER NOT NULL,
    merkle_root   TEXT    NOT NULL,
    seal          TEXT,
    config_digest TEXT    NOT NULL,
    roots         TEXT    NOT NULL,
    scan_seconds  REAL    NOT NULL,
    error_count   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    baseline_id INTEGER NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    path        TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    mode        INTEGER NOT NULL,
    uid         INTEGER,
    gid         INTEGER,
    mtime_ns    INTEGER NOT NULL,
    inode       INTEGER NOT NULL,
    nlink       INTEGER NOT NULL,
    digest      TEXT,
    link_target TEXT,
    attributes  INTEGER NOT NULL,
    error       TEXT,
    PRIMARY KEY (baseline_id, path)
) WITHOUT ROWID;
"""

_FILE_COLUMNS = ("path", "kind", "size", "mode", "uid", "gid", "mtime_ns", "inode", "nlink",
                 "digest", "link_target", "attributes", "error")  # fmt: skip

_BASELINE_COLUMNS = ("id", "created_at", "label", "host", "platform", "algorithm", "file_count",
                     "merkle_root", "seal", "config_digest", "roots", "scan_seconds",
                     "error_count")  # fmt: skip


def _to_info(row: sqlite3.Row) -> BaselineInfo:
    return BaselineInfo(
        id=row["id"],
        created_at=row["created_at"],
        label=row["label"],
        host=row["host"],
        platform=row["platform"],
        algorithm=row["algorithm"],
        file_count=row["file_count"],
        merkle_root=row["merkle_root"],
        seal=row["seal"],
        config_digest=row["config_digest"],
        roots=json.loads(row["roots"]),
        scan_seconds=row["scan_seconds"],
        error_count=row["error_count"],
    )


class BaselineStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path))
        except (OSError, sqlite3.Error) as exc:
            raise StoreError(f"cannot open baseline store {path}: {exc}") from None
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._migrate()
        except sqlite3.DatabaseError as exc:
            self._conn.close()
            raise StoreError(f"{path} is not a valid Tessera database: {exc}") from None

    # ----------------------------------------------------------- lifecycle
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> BaselineStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            with self._conn:
                yield self._conn
        except sqlite3.Error as exc:
            raise StoreError(f"baseline store error: {exc}") from None

    def _migrate(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)
            row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                self._conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif int(row["value"]) > SCHEMA_VERSION:
                raise StoreError(
                    f"baseline store {self.path} was written by a newer Tessera "
                    f"(schema {row['value']}, this version supports {SCHEMA_VERSION})"
                )

    # --------------------------------------------------------------- write
    def save(
        self,
        snapshot: Snapshot,
        *,
        merkle_root: str,
        seal: str | None,
        config_digest: str,
        label: str | None = None,
    ) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO baselines(created_at, label, host, platform, algorithm, file_count,"
                " merkle_root, seal, config_digest, roots, scan_seconds, error_count)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    snapshot.created_at,
                    label,
                    snapshot.host,
                    snapshot.platform,
                    snapshot.algorithm,
                    len(snapshot.records),
                    merkle_root,
                    seal,
                    config_digest,
                    json.dumps(snapshot.roots),
                    snapshot.stats.seconds,
                    snapshot.stats.errors,
                ),
            )
            baseline_id = cur.lastrowid
            assert baseline_id is not None
            conn.executemany(
                f"INSERT INTO files(baseline_id, {', '.join(_FILE_COLUMNS)})"
                f" VALUES(?, {', '.join('?' * len(_FILE_COLUMNS))})",
                (
                    (baseline_id, r.path, r.kind.value, r.size, r.mode, r.uid, r.gid, r.mtime_ns,
                     r.inode, r.nlink, r.digest, r.link_target, r.attributes, r.error)
                    for r in snapshot.records.values()
                ),
            )  # fmt: skip
        return baseline_id

    def delete(self, baseline_id: int) -> None:
        self.get(baseline_id)
        with self._tx() as conn:
            conn.execute("DELETE FROM baselines WHERE id = ?", (baseline_id,))

    def prune(self, keep: int) -> list[int]:
        """Delete all but the newest ``keep`` baselines. Returns deleted ids."""
        if keep < 1:
            raise ValueError("keep must be at least 1")
        ids = [b.id for b in self.list()][keep:]
        with self._tx() as conn:
            conn.executemany("DELETE FROM baselines WHERE id = ?", ((i,) for i in ids))
        if ids:
            self._conn.execute("VACUUM")
        return ids

    # ---------------------------------------------------------------- read
    def list(self) -> list[BaselineInfo]:
        rows = self._conn.execute(f"SELECT {', '.join(_BASELINE_COLUMNS)} FROM baselines ORDER BY id DESC").fetchall()
        return [_to_info(r) for r in rows]

    def latest(self) -> BaselineInfo | None:
        row = self._conn.execute(
            f"SELECT {', '.join(_BASELINE_COLUMNS)} FROM baselines ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return _to_info(row) if row else None

    def get(self, baseline_id: int) -> BaselineInfo:
        row = self._conn.execute(
            f"SELECT {', '.join(_BASELINE_COLUMNS)} FROM baselines WHERE id = ?", (baseline_id,)
        ).fetchone()
        if row is None:
            raise BaselineNotFoundError(
                f"baseline #{baseline_id} does not exist", hint="list baselines with `tessera baselines`"
            )
        return _to_info(row)

    def resolve(self, baseline_id: int | None) -> BaselineInfo:
        """Return the given baseline, or the latest one when ``None``."""
        if baseline_id is not None:
            return self.get(baseline_id)
        info = self.latest()
        if info is None:
            raise BaselineNotFoundError("no baseline recorded yet", hint="create one with `tessera snapshot`")
        return info

    def records(self, baseline_id: int) -> dict[str, FileRecord]:
        cur = self._conn.execute(f"SELECT {', '.join(_FILE_COLUMNS)} FROM files WHERE baseline_id = ?", (baseline_id,))
        result: dict[str, FileRecord] = {}
        for row in cur:
            rec = FileRecord(
                path=row["path"],
                kind=EntryKind(row["kind"]),
                size=row["size"],
                mode=row["mode"],
                uid=row["uid"],
                gid=row["gid"],
                mtime_ns=row["mtime_ns"],
                inode=row["inode"],
                nlink=row["nlink"],
                digest=row["digest"],
                link_target=row["link_target"],
                attributes=row["attributes"],
                error=row["error"],
            )
            result[rec.path] = rec
        return result
