"""Merkle tree hashing per RFC 6962 / RFC 9162 (Certificate Transparency).

Every baseline gets a Merkle root over its sorted file records. The root
is what gets sealed, and any single record can be proven to belong to a
baseline with a logarithmic-size inclusion proof, without sharing the rest
of the baseline.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _h(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(NODE_PREFIX + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly smaller than ``n`` (``n > 1``)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _root(leaves: Sequence[bytes], lo: int, hi: int) -> bytes:
    n = hi - lo
    if n == 1:
        return leaves[lo]
    k = _split(n)
    return node_hash(_root(leaves, lo, lo + k), _root(leaves, lo + k, hi))


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Root of a tree whose leaves are already leaf-hashed."""
    if not leaves:
        return _h(b"")
    return _root(leaves, 0, len(leaves))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Audit path for ``leaves[index]``, ordered from the leaf upward."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")

    def path(m: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return [*path(m, lo, lo + k), _root(leaves, lo + k, hi)]
        return [*path(m - k, lo + k, hi), _root(leaves, lo, lo + k)]

    return path(index, 0, len(leaves))


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes) -> bool:
    """Verify an inclusion proof (RFC 9162 section 2.1.3.2)."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
