"""Tamper evidence: keys, seals, manifests and inclusion proofs.

A *seal* is ``HMAC-SHA256(key, canonical(header))`` where the header holds
the baseline metadata and its Merkle root. Anyone who modifies the stored
baseline (to hide a change) must also forge the seal, which requires the
key. Keep the key off the monitored host, or on read-only media, for the
strongest guarantee. See docs/security-model.md.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tessera import __version__, merkle
from tessera.errors import IntegrityError, KeyFileError
from tessera.models import FileRecord
from tessera.osinfo import IS_WINDOWS
from tessera.util import canonical_json

log = logging.getLogger(__name__)

SEAL_CONTEXT = b"tessera-seal-v1\n"
KEY_BYTES = 32
MANIFEST_VERSION = 1


# --------------------------------------------------------------------- keys
def generate_key(path: Path, *, force: bool = False) -> Path:
    """Create a new random sealing key, readable only by the owner."""
    if path.exists() and not force:
        raise KeyFileError(f"key file already exists: {path}", hint="pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = secrets.token_hex(KEY_BYTES) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data.encode("ascii"))
    finally:
        os.close(fd)
    if not IS_WINDOWS:
        os.chmod(path, 0o600)
    return path


def load_key(path: Path) -> bytes:
    """Read a key file and return the raw key bytes."""
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        raise KeyFileError(f"key file not found: {path}", hint="run `tessera keygen` to create one") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise KeyFileError(f"cannot read key file {path}: {exc}") from None
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise KeyFileError(f"key file {path} is not valid hex") from None
    if len(key) < 16:
        raise KeyFileError(f"key in {path} is too short ({len(key)} bytes, need at least 16)")
    if not IS_WINDOWS:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            log.warning("key file %s is accessible by other users (mode %o), run: chmod 600 %s",
                        path, mode, path)  # fmt: skip
    return key


# --------------------------------------------------------------- hashing
def record_leaf(record: FileRecord) -> bytes:
    return merkle.leaf_hash(canonical_json(record.to_dict()))


def sorted_records(records: Mapping[str, FileRecord] | Iterable[FileRecord]) -> list[FileRecord]:
    items = records.values() if isinstance(records, Mapping) else records
    return sorted(items, key=lambda r: r.path)


def compute_root(records: Mapping[str, FileRecord] | Iterable[FileRecord]) -> str:
    leaves = [record_leaf(r) for r in sorted_records(records)]
    return merkle.merkle_root(leaves).hex()


@dataclass(frozen=True, slots=True)
class SealHeader:
    created_at: str
    host: str
    platform: str
    algorithm: str
    file_count: int
    merkle_root: str
    config_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": 1,
            "created_at": self.created_at,
            "host": self.host,
            "platform": self.platform,
            "algorithm": self.algorithm,
            "file_count": self.file_count,
            "merkle_root": self.merkle_root,
            "config_digest": self.config_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SealHeader:
        if data.get("v") != 1:
            raise IntegrityError(f"unsupported seal header version {data.get('v')!r}")
        try:
            return cls(
                created_at=str(data["created_at"]),
                host=str(data["host"]),
                platform=str(data["platform"]),
                algorithm=str(data["algorithm"]),
                file_count=int(data["file_count"]),
                merkle_root=str(data["merkle_root"]),
                config_digest=str(data["config_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrityError(f"malformed seal header: {exc}") from None


def seal(key: bytes, header: SealHeader) -> str:
    return hmac.new(key, SEAL_CONTEXT + canonical_json(header.to_dict()), "sha256").hexdigest()


def check_seal(key: bytes, header: SealHeader, expected: str) -> bool:
    return hmac.compare_digest(seal(key, header), expected)


# -------------------------------------------------------------- manifests
def build_manifest(header: SealHeader, seal_hex: str | None, records: Mapping[str, FileRecord]) -> dict[str, Any]:
    return {
        "tessera_manifest": MANIFEST_VERSION,
        "generator": f"tessera {__version__}",
        "header": header.to_dict(),
        "seal": seal_hex,
        "records": [r.to_dict() for r in sorted_records(records)],
    }


@dataclass(frozen=True, slots=True)
class VerifyResult:
    root_ok: bool
    count_ok: bool
    seal_status: str  # "valid", "invalid", "unsealed", "no-key"
    computed_root: str

    @property
    def ok(self) -> bool:
        return self.root_ok and self.count_ok and self.seal_status in ("valid", "unsealed", "no-key")

    @property
    def strict_ok(self) -> bool:
        return self.root_ok and self.count_ok and self.seal_status == "valid"


def verify(header: SealHeader, seal_hex: str | None, records: Iterable[FileRecord], key: bytes | None) -> VerifyResult:
    record_list = list(records)
    root = compute_root(record_list)
    if seal_hex is None:
        status = "unsealed"
    elif key is None:
        status = "no-key"
    else:
        status = "valid" if check_seal(key, header, seal_hex) else "invalid"
    return VerifyResult(
        root_ok=hmac.compare_digest(root, header.merkle_root),
        count_ok=len(record_list) == header.file_count,
        seal_status=status,
        computed_root=root,
    )


def verify_manifest(data: Mapping[str, Any], key: bytes | None) -> VerifyResult:
    if data.get("tessera_manifest") != MANIFEST_VERSION:
        raise IntegrityError("not a Tessera manifest (missing or unknown 'tessera_manifest')")
    header = SealHeader.from_dict(data.get("header") or {})
    try:
        records = [FileRecord.from_dict(r) for r in data.get("records", [])]
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError(f"malformed manifest record: {exc}") from None
    seal_hex = data.get("seal")
    return verify(header, seal_hex if isinstance(seal_hex, str) else None, records, key)


# ------------------------------------------------------------------ proofs
def build_proof(
    header: SealHeader, seal_hex: str | None, records: Mapping[str, FileRecord], path: str
) -> dict[str, Any]:
    ordered = sorted_records(records)
    index = next((i for i, r in enumerate(ordered) if r.path == path), None)
    if index is None:
        raise IntegrityError(f"path is not part of this baseline: {path}")
    leaves = [record_leaf(r) for r in ordered]
    return {
        "tessera_proof": 1,
        "header": header.to_dict(),
        "seal": seal_hex,
        "index": index,
        "size": len(leaves),
        "record": ordered[index].to_dict(),
        "path": [p.hex() for p in merkle.inclusion_proof(leaves, index)],
    }


def verify_proof(data: Mapping[str, Any], key: bytes | None) -> tuple[bool, str]:
    """Verify an inclusion proof. Returns ``(included, seal_status)``."""
    if data.get("tessera_proof") != 1:
        raise IntegrityError("not a Tessera inclusion proof")
    header = SealHeader.from_dict(data.get("header") or {})
    try:
        record = FileRecord.from_dict(data["record"])
        index, size = int(data["index"]), int(data["size"])
        path = [bytes.fromhex(p) for p in data["path"]]
        root = bytes.fromhex(header.merkle_root)
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError(f"malformed proof: {exc}") from None
    included = size == header.file_count and merkle.verify_inclusion(record_leaf(record), index, size, path, root)
    seal_hex = data.get("seal")
    if not isinstance(seal_hex, str):
        status = "unsealed"
    elif key is None:
        status = "no-key"
    else:
        status = "valid" if check_seal(key, header, seal_hex) else "invalid"
    return included, status
