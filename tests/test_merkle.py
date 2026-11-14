from __future__ import annotations

import hashlib

import pytest

from tessera.merkle import inclusion_proof, leaf_hash, merkle_root, node_hash, verify_inclusion


def leaves(n: int) -> list[bytes]:
    return [leaf_hash(f"leaf-{i}".encode()) for i in range(n)]


def test_empty_and_single() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").digest()
    one = leaves(1)
    assert merkle_root(one) == one[0]


def test_rfc6962_shape_for_three_leaves() -> None:
    a, b, c = leaves(3)
    assert merkle_root([a, b, c]) == node_hash(node_hash(a, b), c)


def test_domain_separation() -> None:
    assert leaf_hash(b"x") != hashlib.sha256(b"x").digest()


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 100])
def test_every_proof_verifies(size: int) -> None:
    items = leaves(size)
    root = merkle_root(items)
    for index in range(size):
        proof = inclusion_proof(items, index)
        assert verify_inclusion(items[index], index, size, proof, root)


def test_proofs_reject_tampering() -> None:
    items = leaves(13)
    root = merkle_root(items)
    proof = inclusion_proof(items, 6)
    assert not verify_inclusion(items[7], 6, 13, proof, root)
    assert not verify_inclusion(items[6], 5, 13, proof, root)
    # Note: the tree size is bound by the sealed header, see test_sealing.py.
    assert not verify_inclusion(items[6], 6, 13, proof[:-1], root)
    bad = list(proof)
    bad[0] = leaf_hash(b"evil")
    assert not verify_inclusion(items[6], 6, 13, bad, root)
    assert not verify_inclusion(items[6], 20, 13, proof, root)


def test_index_out_of_range() -> None:
    with pytest.raises(IndexError):
        inclusion_proof(leaves(3), 3)
