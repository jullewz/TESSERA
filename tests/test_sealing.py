from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tessera import sealing
from tessera.errors import IntegrityError, KeyFileError

from .conftest import posix_only, rec

RECORDS = {p: rec(p, digest=f"sha256:{i:02x}") for i, p in enumerate(["/a", "/b", "/c", "/d", "/e"])}


def header(**kw: object) -> sealing.SealHeader:
    values: dict[str, object] = {
        "created_at": "2026-01-01T00:00:00+00:00",
        "host": "h",
        "platform": "linux",
        "algorithm": "sha256",
        "file_count": len(RECORDS),
        "merkle_root": sealing.compute_root(RECORDS),
        "config_digest": "cfg",
    }
    values.update(kw)
    return sealing.SealHeader(**values)  # type: ignore[arg-type]


def test_key_roundtrip(tmp_path: Path) -> None:
    path = sealing.generate_key(tmp_path / "k" / "seal.key")
    key = sealing.load_key(path)
    assert len(key) == sealing.KEY_BYTES
    with pytest.raises(KeyFileError):
        sealing.generate_key(path)
    sealing.generate_key(path, force=True)
    assert sealing.load_key(path) != key


@posix_only
def test_key_permissions(tmp_path: Path) -> None:
    path = sealing.generate_key(tmp_path / "seal.key")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.parametrize(("content", "message"), [("zz", "not valid hex"), ("abcd", "too short")])
def test_bad_keys(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "bad.key"
    path.write_text(content)
    with pytest.raises(KeyFileError, match=message):
        sealing.load_key(path)
    with pytest.raises(KeyFileError, match="not found"):
        sealing.load_key(tmp_path / "missing.key")


def test_root_independent_of_insertion_order() -> None:
    reversed_records = dict(reversed(list(RECORDS.items())))
    assert sealing.compute_root(RECORDS) == sealing.compute_root(reversed_records)


def test_seal_detects_header_changes() -> None:
    key = os.urandom(32)
    h = header()
    s = sealing.seal(key, h)
    assert sealing.check_seal(key, h, s)
    assert not sealing.check_seal(key, header(host="other"), s)
    assert not sealing.check_seal(os.urandom(32), h, s)


def test_verify_statuses() -> None:
    key = os.urandom(32)
    h = header()
    s = sealing.seal(key, h)
    assert sealing.verify(h, s, RECORDS.values(), key).strict_ok
    assert sealing.verify(h, None, RECORDS.values(), key).seal_status == "unsealed"
    assert sealing.verify(h, s, RECORDS.values(), None).seal_status == "no-key"
    tampered = dict(RECORDS)
    tampered["/c"] = rec("/c", digest="sha256:ff")
    result = sealing.verify(h, s, tampered.values(), key)
    assert not result.root_ok and not result.ok
    missing = list(RECORDS.values())[:-1]
    assert not sealing.verify(h, s, missing, key).ok


def test_manifest_roundtrip_and_tamper() -> None:
    key = os.urandom(32)
    h = header()
    manifest = sealing.build_manifest(h, sealing.seal(key, h), RECORDS)
    assert sealing.verify_manifest(manifest, key).strict_ok
    manifest["records"][2]["size"] = 1
    assert not sealing.verify_manifest(manifest, key).ok
    with pytest.raises(IntegrityError):
        sealing.verify_manifest({"tessera_manifest": 99}, key)


def test_inclusion_proofs() -> None:
    key = os.urandom(32)
    h = header()
    proof = sealing.build_proof(h, sealing.seal(key, h), RECORDS, "/c")
    assert sealing.verify_proof(proof, key) == (True, "valid")
    proof["record"]["size"] = 999
    assert sealing.verify_proof(proof, key)[0] is False
    with pytest.raises(IntegrityError):
        sealing.build_proof(h, None, RECORDS, "/zzz")
    with pytest.raises(IntegrityError):
        sealing.verify_proof({"tessera_proof": 1, "header": h.to_dict()}, key)
