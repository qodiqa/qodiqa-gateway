"""Tests for qodiqa._verification._merkle.verify_inclusion_path.

Uses an independent (test-local) reference implementation of RFC6962
root/path computation — deliberately NOT importing the server's own
merkle.js/log.js — to cross-check the SDK's verification-only port against
a from-scratch reimplementation, not against itself.
"""

from __future__ import annotations

import hashlib
import os

from qodiqa._verification._merkle import verify_inclusion_path


def _leaf_hash(entry_hash_hex: str) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(bytes.fromhex(entry_hash_hex))
    return h.digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


def _largest_pow2_less_than(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _subtree_root(leaves, offset: int, count: int) -> bytes:
    if count == 1:
        return leaves[offset]
    k = _largest_pow2_less_than(count)
    return _node_hash(_subtree_root(leaves, offset, k), _subtree_root(leaves, offset + k, count - k))


def _root(hashes):
    leaves = [_leaf_hash(h) for h in hashes]
    return _subtree_root(leaves, 0, len(leaves)).hex()


def _path(hashes, leaf_index: int):
    n = len(hashes)
    if n == 1:
        return []
    leaves = [_leaf_hash(h) for h in hashes]
    out = []
    lo = 0
    size = n
    idx = leaf_index
    while size > 1:
        k = _largest_pow2_less_than(size)
        if idx < k:
            out.append({"hash": _subtree_root(leaves, lo + k, size - k).hex(), "side": "right"})
            size = k
        else:
            out.append({"hash": _subtree_root(leaves, lo, k).hex(), "side": "left"})
            lo += k
            idx -= k
            size -= k
    out.reverse()
    return out


def _random_entry_hash() -> str:
    return os.urandom(32).hex()


def test_verifies_every_leaf_of_trees_of_various_sizes() -> None:
    for n in (1, 2, 3, 5, 8, 13):
        hashes = [_random_entry_hash() for _ in range(n)]
        root = _root(hashes)
        for i in range(n):
            path = _path(hashes, i)
            assert verify_inclusion_path(hashes[i], path, root) is True


def test_rejects_wrong_root() -> None:
    hashes = [_random_entry_hash() for _ in range(5)]
    path = _path(hashes, 2)
    assert verify_inclusion_path(hashes[2], path, "f" * 64) is False


def test_rejects_tampered_sibling_hash() -> None:
    hashes = [_random_entry_hash() for _ in range(5)]
    root = _root(hashes)
    path = _path(hashes, 2)
    tampered = [dict(p) for p in path]
    tampered[0]["hash"] = "a" * 64
    assert verify_inclusion_path(hashes[2], tampered, root) is False


def test_rejects_flipped_side() -> None:
    hashes = [_random_entry_hash() for _ in range(5)]
    root = _root(hashes)
    path = _path(hashes, 2)
    if not path:
        return
    tampered = [dict(p) for p in path]
    tampered[0]["side"] = "right" if tampered[0]["side"] == "left" else "left"
    assert verify_inclusion_path(hashes[2], tampered, root) is False


def test_rejects_truncated_path() -> None:
    hashes = [_random_entry_hash() for _ in range(8)]
    root = _root(hashes)
    path = _path(hashes, 3)
    assert verify_inclusion_path(hashes[3], path[1:], root) is False


def test_rejects_reordered_path() -> None:
    hashes = [_random_entry_hash() for _ in range(8)]
    root = _root(hashes)
    path = _path(hashes, 3)
    if len(path) < 2:
        return
    reordered = [path[1], path[0]] + path[2:]
    assert verify_inclusion_path(hashes[3], reordered, root) is False


def test_never_raises_on_malformed_input() -> None:
    assert verify_inclusion_path("", [], "") is False
    assert verify_inclusion_path("nothex", [{"hash": "x", "side": "left"}], "root") is False
    assert verify_inclusion_path(_random_entry_hash(), [{"hash": "x", "side": "sideways"}], "a" * 64) is False


# with leaf_index/tree_size the proof is bound to its claimed position.
def test_cry16_bound_proof_verifies_only_at_its_own_position() -> None:
    for n in (2, 3, 5, 8, 13):
        hashes = [_random_entry_hash() for _ in range(n)]
        root = _root(hashes)
        for i in range(n):
            path = _path(hashes, i)
            assert verify_inclusion_path(hashes[i], path, root, leaf_index=i, tree_size=n) is True
            for j in range(n):
                if j != i:
                    assert verify_inclusion_path(hashes[i], path, root, leaf_index=j, tree_size=n) is False


def test_cry16_bound_mode_refuses_invalid_positions() -> None:
    hashes = [_random_entry_hash() for _ in range(8)]
    root = _root(hashes)
    path = _path(hashes, 3)
    for li, ts in ((None, 8), (3, None), (-1, 8), (8, 8), (3.0, 8), ("3", 8), (True, 8), (3, 0)):
        assert verify_inclusion_path(hashes[3], path, root, leaf_index=li, tree_size=ts) is False
