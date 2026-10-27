"""RFC6962-compatible Merkle tree — verification-only Python SDK-side port
of ``src/core/transparency/merkle.js``. Tree/proof *generation* is a
server-only concern; the SDK only ever needs to verify an inclusion path it
was given.

Leaf hash:  H(0x00 || bytes(entryHashHex))
Node hash:  H(0x01 || left || right)
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, TypedDict


class MerklePathStep(TypedDict):
    hash: str
    side: str  # 'left' | 'right'


_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash_buf(entry_hash_hex: str) -> bytes:
    h = hashlib.sha256()
    h.update(_LEAF_PREFIX)
    h.update(bytes.fromhex(entry_hash_hex))
    return h.digest()


def _node_hash_buf(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_NODE_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()


def _is_exact_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def expected_path_sides(leaf_index: Any, tree_size: Any) -> Optional[List[str]]:
    """the RFC6962 side sequence (deepest first) of leaf ``leaf_index``
    in a ``tree_size``-leaf tree — for a given tree size the index determines the
    path length and every side. ``None`` for an invalid (index, size) pair.
    """
    if not _is_exact_int(leaf_index) or not _is_exact_int(tree_size) or leaf_index < 0 or leaf_index >= tree_size:
        return None
    sides: List[str] = []
    size, idx = tree_size, leaf_index
    while size > 1:
        k = 1
        while k * 2 < size:
            k *= 2
        if idx < k:
            sides.append("right")
            size = k
        else:
            sides.append("left")
            idx -= k
            size -= k
    sides.reverse()
    return sides


_UNSET: Any = object()


def verify_inclusion_path(
    entry_hash_hex: str,
    path: List[Dict[str, Any]],
    root_hex: str,
    leaf_index: Any = _UNSET,
    tree_size: Any = _UNSET,
) -> bool:
    """Verify an RFC6962 Merkle audit (inclusion) proof: rebuild the Merkle
    root from the leaf's entry hash and the sibling path, then compare with
    `root_hex`. Never raises — returns ``False`` for any malformed input.

    pass ``leaf_index`` and ``tree_size`` to bind the proof to its
    claimed position — the path must then be exactly the RFC6962 path of that
    leaf (same length, same side at every step), so a proof for leaf N cannot
    be presented as leaf M. Without them only path -> root is checked (the
    pre-CRY-16 behaviour, kept for compatibility); ``verify_transparency_proof``
    always binds, and also requires ``tree_size`` to equal the signed root's
    ``entryCount``.
    """
    try:
        if not entry_hash_hex or not isinstance(path, list) or not root_hex:
            return False
        if leaf_index is not _UNSET or tree_size is not _UNSET:
            sides = expected_path_sides(leaf_index, tree_size)
            if sides is None or len(path) != len(sides):
                return False
            for step, side in zip(path, sides):
                if not isinstance(step, dict) or step.get("side") != side:
                    return False

        current = _leaf_hash_buf(entry_hash_hex)
        for step in path:
            step_side = step.get("side")
            step_hash = step.get("hash")
            if step_side not in ("left", "right") or not isinstance(step_hash, str):
                return False
            side = step_side
            sibling = bytes.fromhex(step_hash)
            current = _node_hash_buf(current, sibling) if side == "right" else _node_hash_buf(sibling, current)

        return current.hex() == root_hex
    except Exception:
        return False
