"""Local, offline verification of a QODIQA transparency-log inclusion proof —
Python SDK-side port of ``src/core/transparency/log.js``'s
``computeEntryHash``, ``computeRootSigningBuffer``,
``verifyEntrySignature``/``verifyRootSignature``, and ``verifyInclusionProof``.

Verifies, independently of the server's own verdict:

1. The entry's ``entryHash`` truly derives from its own canonical fields
   (the server's own ``verifyInclusionProof`` doesn't check this — it
   trusts ``entry.entryHash`` as given — so this is a strictly stronger
   check than the server performs).
2. The Merkle audit path reconstructs ``root.rootHash`` from ``entry.entryHash``.
3. ``proof.merkleRoot`` (if present) matches ``root.rootHash``.
4. ``leafIndex`` is within ``[0, treeSize)``.
5. The entry and root Ed25519 signatures verify against the configured
   transparency key provider — a completely separate trust domain from
   artifact-signing keys.
"""

from __future__ import annotations

from typing import Any, Dict

from ._canonical_json import stable_stringify
from ._domain_hash import TRANSPARENCY_ENTRY_DOMAIN, TRANSPARENCY_ROOT_DOMAIN, domain_separated_hash
from ._ed25519 import verify_ed25519
from ._key_providers import AsyncKeyProvider, KeyProvider, maybe_await_get_public_key
from ._merkle import verify_inclusion_path
from ._result_types import TransparencyVerificationDetail

_CANONICAL_ENTRY_FIELDS = (
    "transparencyId",
    "entryType",
    "artifactId",
    "evidenceChainId",
    "verificationId",
    "payloadHash",
    "previousEntryHash",
    "signerKeyId",
)

_CANONICAL_ROOT_FIELDS = ("rootId", "seqFrom", "seqTo", "entryCount", "rootHash", "previousRootHash")


def _pick(record: Dict[str, Any], fields: Any) -> Dict[str, Any]:
    return {f: record.get(f) for f in fields}


def _compute_entry_hash(entry: Dict[str, Any]) -> str:
    canonical = _pick(entry, _CANONICAL_ENTRY_FIELDS)
    return domain_separated_hash(TRANSPARENCY_ENTRY_DOMAIN, stable_stringify(canonical)).hex()


def _compute_root_signing_buffer(root: Dict[str, Any]) -> bytes:
    canonical = _pick(root, _CANONICAL_ROOT_FIELDS)
    return domain_separated_hash(TRANSPARENCY_ROOT_DOMAIN, stable_stringify(canonical))


def _compute_entry_signing_buffer(entry: Dict[str, Any]) -> bytes:
    return bytes.fromhex(_compute_entry_hash(entry))


def verify_transparency_proof(
    proof: Dict[str, Any],
    transparency_keys: KeyProvider,
) -> TransparencyVerificationDetail:
    """Verify a transparency inclusion proof (as returned by
    ``GET /v1/transparency/proof/:transparencyId``) entirely locally.

    Never raises — every failure mode is captured in the returned
    :class:`TransparencyVerificationDetail`.
    """
    entry_hash_valid = False
    merkle_path_valid = False
    entry_signature_valid = False
    root_signature_valid = False
    leaf_index_valid = False
    key_valid = False
    key_status = None

    if not proof or not proof.get("entry") or not proof.get("root") or not proof.get("proof"):
        return TransparencyVerificationDetail(
            entry_hash_valid=False,
            merkle_path_valid=False,
            entry_signature_valid=False,
            root_signature_valid=False,
            leaf_index_valid=False,
            key_valid=False,
            key_status=None,
        )

    # Signature-format-version validation: this SDK understands proof format
    # '2' (the only version the server currently emits). An unrecognized
    # version has no defined verification semantics, so fail closed rather
    # than attempting to interpret unknown fields.
    if proof.get("proofVersion") != "2" or proof.get("proofType") != "TRANSPARENCY_INCLUSION":
        return TransparencyVerificationDetail(
            entry_hash_valid=False,
            merkle_path_valid=False,
            entry_signature_valid=False,
            root_signature_valid=False,
            leaf_index_valid=False,
            key_valid=False,
            key_status=None,
        )

    entry = proof["entry"]
    root = proof["root"]
    proof_data = proof["proof"]

    try:
        entry_hash_valid = _compute_entry_hash(entry) == entry.get("entryHash")
    except Exception:
        entry_hash_valid = False

    try:
        leaf_index = int(proof_data.get("leafIndex"))
        tree_size = int(proof_data.get("treeSize"))
        leaf_index_valid = 0 <= leaf_index < tree_size
    except Exception:
        leaf_index_valid = False

    # position-bound (the path must be the one for this leaf in this tree), and the tree is the one the signed
    # root covers (proof.treeSize == root.entryCount). Exact integers only, as the JavaScript SDK requires.
    raw_leaf_index, raw_tree_size = proof_data.get("leafIndex"), proof_data.get("treeSize")
    tree_size_matches_root = root.get("entryCount") == raw_tree_size and not isinstance(raw_tree_size, bool)
    path_valid = tree_size_matches_root and verify_inclusion_path(
        entry.get("entryHash"), proof_data.get("merklePath"), root.get("rootHash"),
        leaf_index=raw_leaf_index, tree_size=raw_tree_size,
    )
    merkle_root = proof_data.get("merkleRoot")
    root_hash_agrees = merkle_root is not None and merkle_root == root.get("rootHash")
    merkle_path_valid = path_valid and root_hash_agrees

    resolved = transparency_keys.get_public_key(entry.get("signerKeyId"))
    if resolved:
        key_valid = resolved.status in ("active", "deprecated")
        key_status = resolved.status
        if key_valid:
            entry_signature_valid = verify_ed25519(
                _compute_entry_signing_buffer(entry), entry.get("signature"), resolved.pub_der
            )

    root_resolved = transparency_keys.get_public_key(root.get("signerKeyId"))
    if root_resolved and root_resolved.status in ("active", "deprecated"):
        root_signature_valid = verify_ed25519(
            _compute_root_signing_buffer(root), root.get("signature"), root_resolved.pub_der
        )

    return TransparencyVerificationDetail(
        entry_hash_valid=entry_hash_valid,
        merkle_path_valid=merkle_path_valid,
        entry_signature_valid=entry_signature_valid,
        root_signature_valid=root_signature_valid,
        leaf_index_valid=leaf_index_valid,
        key_valid=key_valid,
        key_status=key_status,
    )


async def async_verify_transparency_proof(
    proof: Dict[str, Any],
    transparency_keys: AsyncKeyProvider,
) -> TransparencyVerificationDetail:
    """Async counterpart of :func:`verify_transparency_proof`."""
    if not proof or not proof.get("entry") or not proof.get("root") or not proof.get("proof"):
        return TransparencyVerificationDetail(
            entry_hash_valid=False,
            merkle_path_valid=False,
            entry_signature_valid=False,
            root_signature_valid=False,
            leaf_index_valid=False,
            key_valid=False,
            key_status=None,
        )

    # Signature-format-version validation: this SDK understands proof format
    # '2' (the only version the server currently emits). An unrecognized
    # version has no defined verification semantics, so fail closed rather
    # than attempting to interpret unknown fields.
    if proof.get("proofVersion") != "2" or proof.get("proofType") != "TRANSPARENCY_INCLUSION":
        return TransparencyVerificationDetail(
            entry_hash_valid=False,
            merkle_path_valid=False,
            entry_signature_valid=False,
            root_signature_valid=False,
            leaf_index_valid=False,
            key_valid=False,
            key_status=None,
        )

    entry = proof["entry"]
    root = proof["root"]
    proof_data = proof["proof"]

    try:
        entry_hash_valid = _compute_entry_hash(entry) == entry.get("entryHash")
    except Exception:
        entry_hash_valid = False

    try:
        leaf_index = int(proof_data.get("leafIndex"))
        tree_size = int(proof_data.get("treeSize"))
        leaf_index_valid = 0 <= leaf_index < tree_size
    except Exception:
        leaf_index_valid = False

    # position-bound (the path must be the one for this leaf in this tree), and the tree is the one the signed
    # root covers (proof.treeSize == root.entryCount). Exact integers only, as the JavaScript SDK requires.
    raw_leaf_index, raw_tree_size = proof_data.get("leafIndex"), proof_data.get("treeSize")
    tree_size_matches_root = root.get("entryCount") == raw_tree_size and not isinstance(raw_tree_size, bool)
    path_valid = tree_size_matches_root and verify_inclusion_path(
        entry.get("entryHash"), proof_data.get("merklePath"), root.get("rootHash"),
        leaf_index=raw_leaf_index, tree_size=raw_tree_size,
    )
    merkle_root = proof_data.get("merkleRoot")
    root_hash_agrees = merkle_root is not None and merkle_root == root.get("rootHash")
    merkle_path_valid = path_valid and root_hash_agrees

    entry_signature_valid = False
    root_signature_valid = False
    key_valid = False
    key_status = None

    resolved = await maybe_await_get_public_key(transparency_keys, entry.get("signerKeyId"))
    if resolved:
        key_valid = resolved.status in ("active", "deprecated")
        key_status = resolved.status
        if key_valid:
            entry_signature_valid = verify_ed25519(
                _compute_entry_signing_buffer(entry), entry.get("signature"), resolved.pub_der
            )

    root_resolved = await maybe_await_get_public_key(transparency_keys, root.get("signerKeyId"))
    if root_resolved and root_resolved.status in ("active", "deprecated"):
        root_signature_valid = verify_ed25519(
            _compute_root_signing_buffer(root), root.get("signature"), root_resolved.pub_der
        )

    return TransparencyVerificationDetail(
        entry_hash_valid=entry_hash_valid,
        merkle_path_valid=merkle_path_valid,
        entry_signature_valid=entry_signature_valid,
        root_signature_valid=root_signature_valid,
        leaf_index_valid=leaf_index_valid,
        key_valid=key_valid,
        key_status=key_status,
    )
