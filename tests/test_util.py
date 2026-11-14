from __future__ import annotations

import pytest

from tessera.hashing import hash_bytes, hash_file, validate_algorithm
from tessera.util import canonical_json, format_duration, format_size, parse_size, safe_path


@pytest.mark.parametrize(
    ("value", "expected"),
    [("512MiB", 512 * 1024**2), ("1 GB", 10**9), ("10k", 10_000), (2048, 2048), ("7", 7), ("1.5KiB", 1536)],
)
def test_parse_size(value: str | int, expected: int) -> None:
    assert parse_size(value) == expected


@pytest.mark.parametrize("bad", ["", "abc", "5 parsecs", -1, True])
def test_parse_size_rejects(bad: object) -> None:
    with pytest.raises(ValueError):
        parse_size(bad)  # type: ignore[arg-type]


def test_formatting() -> None:
    assert format_size(512) == "512 B"
    assert format_size(1536) == "1.5 KiB"
    assert format_duration(0.25) == "250 ms"
    assert format_duration(4.21) == "4.2 s"
    assert format_duration(185) == "3m 05s"


def test_canonical_json_is_deterministic() -> None:
    assert canonical_json({"b": 1, "a": "é"}) == canonical_json({"a": "é", "b": 1})
    assert canonical_json({"a": 1}) == b'{"a":1}'


def test_safe_path_handles_undecodable_names() -> None:
    weird = "/tmp/bad-\udcff-name"
    out = safe_path(weird)
    out.encode("utf-8")
    assert out == safe_path(weird)
    assert safe_path("/plain") == "/plain"


def test_hashing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    f = tmp_path / "data.bin"
    payload = b"tessera" * 100_000
    f.write_bytes(payload)
    for algo in ("sha256", "blake2b", "sha3_256", "sha512"):
        assert hash_file(str(f), algo, chunk_size=4096) == hash_bytes(payload, algo)
    assert validate_algorithm("SHA-256") == "sha256"
    with pytest.raises(ValueError):
        validate_algorithm("md5")
