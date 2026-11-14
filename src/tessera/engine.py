"""High-level operations shared by the CLI and the watch loop.

The CLI stays thin: it parses arguments and renders output, while this
module performs snapshots, checks and verification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from tessera import diff, sealing
from tessera.config import Config
from tessera.errors import KeyFileError
from tessera.models import BaselineInfo, Change, Report, Severity, Snapshot
from tessera.osinfo import current_platform, hostname
from tessera.scanner import ProgressCallback, Scanner
from tessera.store import BaselineStore
from tessera.util import utc_now

log = logging.getLogger(__name__)


def try_load_key(config: Config, *, required: bool = False) -> bytes | None:
    """Load the sealing key. Missing keys are an error only when required."""
    if not config.key_file.exists() and not required:
        return None
    try:
        return sealing.load_key(config.key_file)
    except KeyFileError:
        if required:
            raise
        log.warning("sealing key unavailable at %s, continuing without seals", config.key_file)
        return None


def scan(config: Config, progress: ProgressCallback | None = None) -> Snapshot:
    return Scanner(config.scan, config.policy, progress=progress).scan(config.roots)


def header_for(info: BaselineInfo) -> sealing.SealHeader:
    return sealing.SealHeader(
        created_at=info.created_at,
        host=info.host,
        platform=info.platform,
        algorithm=info.algorithm,
        file_count=info.file_count,
        merkle_root=info.merkle_root,
        config_digest=info.config_digest,
    )


@dataclass(slots=True)
class SnapshotResult:
    baseline: BaselineInfo
    snapshot: Snapshot
    sealed: bool


def save_snapshot(
    config: Config, store: BaselineStore, snapshot: Snapshot, *, label: str | None = None,
    key: bytes | None = None,
) -> SnapshotResult:  # fmt: skip
    root = sealing.compute_root(snapshot.records)
    header = sealing.SealHeader(
        created_at=snapshot.created_at,
        host=snapshot.host,
        platform=snapshot.platform,
        algorithm=snapshot.algorithm,
        file_count=len(snapshot.records),
        merkle_root=root,
        config_digest=config.digest(),
    )
    seal_hex = sealing.seal(key, header) if key else None
    baseline_id = store.save(snapshot, merkle_root=root, seal=seal_hex,
                             config_digest=header.config_digest, label=label)  # fmt: skip
    return SnapshotResult(store.get(baseline_id), snapshot, seal_hex is not None)


@dataclass(slots=True)
class CheckResult:
    report: Report
    snapshot: Snapshot
    baseline: BaselineInfo
    seal_status: str


def verify_baseline(store: BaselineStore, info: BaselineInfo, key: bytes | None) -> sealing.VerifyResult:
    records = store.records(info.id)
    return sealing.verify(header_for(info), info.seal, records.values(), key)


def check(
    config: Config,
    store: BaselineStore,
    *,
    baseline_id: int | None = None,
    key: bytes | None = None,
    progress: ProgressCallback | None = None,
    min_severity: Severity = Severity.INFO,
) -> CheckResult:
    info = store.resolve(baseline_id)
    old = store.records(info.id)
    notes: list[str] = []

    verdict = sealing.verify(header_for(info), info.seal, old.values(), key)
    if not verdict.root_ok or not verdict.count_ok:
        notes.append("baseline records do not match their Merkle root: the store was modified")
    if verdict.seal_status == "invalid":
        notes.append("baseline seal is INVALID: the baseline was altered or the key changed")
    elif verdict.seal_status == "unsealed":
        notes.append("baseline is not sealed, tampering with the store cannot be detected")
    elif verdict.seal_status == "no-key":
        notes.append("sealing key unavailable, the baseline seal was not verified")
    if info.config_digest != config.digest():
        notes.append("configuration changed since this baseline was taken, results include policy drift")

    snapshot = scan(config, progress)
    changes = diff.compare(old, snapshot.records, config.policy)
    changes = [c for c in changes if c.severity >= min_severity]
    report = Report(
        changes=changes,
        baseline=info,
        stats=snapshot.stats,
        generated_at=utc_now(),
        host=hostname(),
        platform=current_platform(),
        notes=notes,
    )
    seal_status = verdict.seal_status
    if not verdict.root_ok or not verdict.count_ok:
        seal_status = "invalid"
    return CheckResult(report, snapshot, info, seal_status)


def compare_baselines(config: Config, store: BaselineStore, old_id: int, new_id: int) -> Report:
    old_info, new_info = store.get(old_id), store.get(new_id)
    changes = diff.compare(store.records(old_info.id), store.records(new_info.id), config.policy)
    return Report(
        changes=changes,
        baseline=old_info,
        stats=None,
        generated_at=utc_now(),
        host=hostname(),
        platform=current_platform(),
        title=f"Baseline #{old_id} {chr(8594)} #{new_id}",
        notes=[f"comparing stored baselines #{old_id} ({old_info.created_at}) and "
               f"#{new_id} ({new_info.created_at})"],
    )  # fmt: skip


def exit_code_for(changes: list[Change], fail_on: Severity) -> int:
    return 1 if any(c.severity >= fail_on for c in changes) else 0
