"""Filesystem scanner.

Walks the configured roots iteratively (no recursion limits), records
metadata with ``lstat`` and hashes file contents in a thread pool. Hashing
is I/O bound and ``hashlib`` releases the GIL, so threads scale well.

Errors never abort a scan. A file the scanner cannot read is stored with
an ``error`` field so the diff engine can report it.
"""

from __future__ import annotations

import logging
import os
import stat
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from tessera.hashing import DEFAULT_ALGORITHM, DEFAULT_CHUNK_SIZE, hash_file
from tessera.matcher import GlobSet
from tessera.models import EntryKind, FileRecord, ScanStats, Snapshot
from tessera.osinfo import IS_WINDOWS, current_platform, hostname
from tessera.policy import Policy
from tessera.util import safe_path, utc_now

log = logging.getLogger(__name__)

ProgressCallback = Callable[[ScanStats], None]


@dataclass(slots=True)
class ScanRoot:
    path: str
    exclude: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanSettings:
    algorithm: str = DEFAULT_ALGORITHM
    workers: int = 4
    max_file_size: int = 512 * 1024 * 1024
    follow_symlinks: bool = False
    one_filesystem: bool = True
    chunk_size: int = DEFAULT_CHUNK_SIZE
    case_sensitive: bool = True


def _kind_of(mode: int) -> EntryKind:
    if stat.S_ISLNK(mode):
        return EntryKind.SYMLINK
    if stat.S_ISDIR(mode):
        return EntryKind.DIR
    if stat.S_ISREG(mode):
        return EntryKind.FILE
    return EntryKind.OTHER


def _platform_attributes(st: os.stat_result) -> int:
    """Windows file attributes (hidden, system, ...) or BSD/macOS file flags."""
    if IS_WINDOWS:
        return int(getattr(st, "st_file_attributes", 0))
    return int(getattr(st, "st_flags", 0))


def _is_junction(path: str) -> bool:
    checker = getattr(os.path, "isjunction", None)  # Python 3.12+
    return bool(checker and checker(path))


def record_from_stat(path: str, st: os.stat_result, *, link_target: str | None = None) -> FileRecord:
    kind = _kind_of(st.st_mode)
    return FileRecord(
        path=safe_path(path),
        kind=kind,
        size=st.st_size if kind is EntryKind.FILE else 0,
        mode=stat.S_IMODE(st.st_mode),
        uid=None if IS_WINDOWS else st.st_uid,
        gid=None if IS_WINDOWS else st.st_gid,
        mtime_ns=st.st_mtime_ns,
        inode=st.st_ino,
        nlink=st.st_nlink,
        link_target=safe_path(link_target) if link_target is not None else None,
        attributes=_platform_attributes(st),
    )


@dataclass(slots=True)
class _WalkState:
    """Mutable state shared by one scan's walk and hashing steps."""

    records: dict[str, FileRecord]
    stats: ScanStats
    pending: list[tuple[str, Future[str]]]
    pool: ThreadPoolExecutor


class Scanner:
    def __init__(
        self,
        settings: ScanSettings,
        policy: Policy,
        *,
        progress: ProgressCallback | None = None,
        progress_interval: float = 0.2,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.progress = progress
        self.progress_interval = progress_interval
        self._last_progress = 0.0

    def scan(self, roots: Iterable[ScanRoot]) -> Snapshot:
        started = time.perf_counter()
        stats = ScanStats()
        records: dict[str, FileRecord] = {}
        pending: list[tuple[str, Future[str]]] = []
        root_list = list(roots)
        workers = max(1, self.settings.workers)

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tessera-hash") as pool:
            state = _WalkState(records, stats, pending, pool)
            for root in root_list:
                self._walk_root(root, state)
            for key, future in pending:
                rec = records[key]
                try:
                    digest = future.result()
                except OSError as exc:
                    stats.errors += 1
                    records[key] = replace(rec, error=_describe_error(exc))
                    log.debug("cannot hash %s: %s", rec.path, exc)
                else:
                    stats.hashed_files += 1
                    stats.hashed_bytes += rec.size
                    records[key] = replace(rec, digest=digest)
                self._report(stats)

        stats.seconds = time.perf_counter() - started
        self._report(stats, force=True)
        return Snapshot(
            records=records,
            stats=stats,
            created_at=utc_now(),
            host=hostname(),
            platform=current_platform(),
            algorithm=self.settings.algorithm,
            roots=[r.path for r in root_list],
        )

    # ------------------------------------------------------------------ walk
    def _walk_root(self, root: ScanRoot, state: _WalkState) -> None:
        records, stats = state.records, state.stats
        excludes = GlobSet(root.exclude, self.settings.case_sensitive)
        root_path = os.path.abspath(root.path)
        try:
            root_st = os.stat(root_path) if self.settings.follow_symlinks else os.lstat(root_path)
        except OSError as exc:
            stats.errors += 1
            log.warning("cannot read watch root %s: %s", root_path, _describe_error(exc))
            records[safe_path(root_path)] = FileRecord(
                path=safe_path(root_path), kind=EntryKind.OTHER, error=_describe_error(exc)
            )
            return

        root_dev = root_st.st_dev
        visited: set[tuple[int, int]] = set()
        self._add_entry(root_path, root_st, state)
        if not stat.S_ISDIR(root_st.st_mode):
            return
        visited.add((root_st.st_dev, root_st.st_ino))
        stack = [root_path]

        while stack:
            directory = stack.pop()
            try:
                with os.scandir(directory) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as exc:
                stats.errors += 1
                key = safe_path(directory)
                if key in records:
                    records[key] = replace(records[key], error=_describe_error(exc))
                log.debug("cannot list %s: %s", directory, exc)
                continue

            subdirs: list[str] = []
            for entry in entries:
                path = entry.path
                if excludes and excludes.matches(path):
                    continue
                if self.policy.resolve(safe_path(path)).ignored:
                    continue
                try:
                    st = entry.stat(follow_symlinks=self.settings.follow_symlinks)
                except FileNotFoundError:
                    continue  # vanished between listing and stat
                except OSError as exc:
                    if self.settings.follow_symlinks and entry.is_symlink():
                        try:
                            st = entry.stat(follow_symlinks=False)  # dangling link
                        except OSError:
                            stats.errors += 1
                            continue
                    else:
                        stats.errors += 1
                        key = safe_path(path)
                        records[key] = FileRecord(path=key, kind=EntryKind.OTHER, error=_describe_error(exc))
                        continue

                self._add_entry(path, st, state)
                if not stat.S_ISDIR(st.st_mode):
                    continue
                if self.settings.one_filesystem and st.st_dev != root_dev:
                    log.debug("not crossing filesystem boundary at %s", path)
                    continue
                if not self.settings.follow_symlinks and (entry.is_symlink() or _is_junction(path)):
                    continue
                ident = (st.st_dev, st.st_ino)
                if ident in visited:
                    log.debug("skipping already visited directory %s", path)
                    continue
                visited.add(ident)
                subdirs.append(path)
            stack.extend(reversed(subdirs))

    def _add_entry(self, path: str, st: os.stat_result, state: _WalkState) -> None:
        records, stats, pending, pool = state.records, state.stats, state.pending, state.pool
        link_target: str | None = None
        if stat.S_ISLNK(st.st_mode):
            try:
                link_target = os.readlink(path)
            except OSError:
                link_target = None
        record = record_from_stat(path, st, link_target=link_target)
        key = record.path
        records[key] = record

        kind = record.kind
        if kind is EntryKind.FILE:
            stats.files += 1
        elif kind is EntryKind.DIR:
            stats.dirs += 1
        elif kind is EntryKind.SYMLINK:
            stats.symlinks += 1
        else:
            stats.other += 1

        if kind is EntryKind.FILE and self.policy.resolve(key).wants_hash:
            if record.size > self.settings.max_file_size:
                stats.skipped_large += 1
            else:
                pending.append((key, pool.submit(hash_file, path, self.settings.algorithm, self.settings.chunk_size)))
        self._report(stats)

    def _report(self, stats: ScanStats, force: bool = False) -> None:
        if self.progress is None:
            return
        now = time.perf_counter()
        if force or now - self._last_progress >= self.progress_interval:
            self._last_progress = now
            self.progress(stats)


def _describe_error(exc: OSError) -> str:
    name = type(exc).__name__
    return f"{name}: {exc.strerror or exc}"
