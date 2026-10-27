"""Tests for qodiqa._verification._ed25519.verify_ed25519."""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from qodiqa._verification._ed25519 import verify_ed25519


def generate_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub_der


def sign(hash_bytes: bytes, priv: Ed25519PrivateKey) -> str:
    return base64.b64encode(priv.sign(hash_bytes)).decode()


HASH = hashlib.sha256(b"message").digest()


def test_verifies_a_genuine_signature() -> None:
    priv, pub_der = generate_keypair()
    sig = sign(HASH, priv)
    assert verify_ed25519(HASH, sig, pub_der) is True


def test_rejects_signature_from_wrong_key() -> None:
    priv, pub_der = generate_keypair()
    other_priv, _ = generate_keypair()
    sig = sign(HASH, other_priv)
    assert verify_ed25519(HASH, sig, pub_der) is False


def test_rejects_tampered_signature() -> None:
    priv, pub_der = generate_keypair()
    sig_bytes = bytearray(base64.b64decode(sign(HASH, priv)))
    sig_bytes[-1] ^= 0x01
    assert verify_ed25519(HASH, base64.b64encode(bytes(sig_bytes)).decode(), pub_der) is False


def test_rejects_tampered_hash() -> None:
    priv, pub_der = generate_keypair()
    sig = sign(HASH, priv)
    other_hash = hashlib.sha256(b"different message").digest()
    assert verify_ed25519(other_hash, sig, pub_der) is False


def test_never_raises_wrong_length_hash() -> None:
    _, pub_der = generate_keypair()
    assert verify_ed25519(b"\x00" * 16, "irrelevant", pub_der) is False


def test_never_raises_truncated_signature() -> None:
    priv, pub_der = generate_keypair()
    sig_bytes = base64.b64decode(sign(HASH, priv))[:32]
    assert verify_ed25519(HASH, base64.b64encode(sig_bytes).decode(), pub_der) is False


def test_never_raises_garbage_signature_string() -> None:
    _, pub_der = generate_keypair()
    assert verify_ed25519(HASH, "not-base64-!!!", pub_der) is False


def test_never_raises_empty_public_key() -> None:
    priv, _ = generate_keypair()
    sig = sign(HASH, priv)
    assert verify_ed25519(HASH, sig, b"") is False


def test_never_raises_malformed_public_key_der() -> None:
    priv, _ = generate_keypair()
    sig = sign(HASH, priv)
    assert verify_ed25519(HASH, sig, b"\x01\x02\x03\x04") is False
