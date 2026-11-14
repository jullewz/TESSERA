"""Streaming content hashing."""

from __future__ import annotations

import hashlib

SUPPORTED_ALGORITHMS: tuple[str, ...] = ("sha256", "sha512", "blake2b", "sha3_256")
DEFAULT_ALGORITHM = "sha256"
DEFAULT_CHUNK_SIZE = 1024 * 1024


def validate_algorithm(name: str) -> str:
    algo = name.lower().replace("-", "_")
    algo = {"sha_256": "sha256", "sha_512": "sha512", "sha3_256": "sha3_256"}.get(algo, algo)
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported hash algorithm {name!r}, expected one of: " + ", ".join(SUPPORTED_ALGORITHMS))
    return algo


def hash_file(path: str, algorithm: str = DEFAULT_ALGORITHM, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Hash a file and return ``"<algorithm>:<hex digest>"``.

    Raises ``OSError`` when the file cannot be read (permissions, locks on
    Windows, files vanishing mid-scan). Callers record that as an error.
    """
    hasher = hashlib.new(algorithm)
    with open(path, "rb", buffering=0) as handle:
        buffer = bytearray(chunk_size)
        view = memoryview(buffer)
        while True:
            read = handle.readinto(buffer)
            if not read:
                break
            hasher.update(view[:read])
    return f"{algorithm}:{hasher.hexdigest()}"


def hash_bytes(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    return f"{algorithm}:{hashlib.new(algorithm, data).hexdigest()}"
