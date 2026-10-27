"""protocol V2 on the Python SDK side: bound-request options on sign(), the signed receipt (read, fetch, verify offline),
the kill switch and the revoked artifact as errors. Mirrors sdk/javascript/tests/protocol-v2.test.ts."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pytest_httpx import HTTPXMock

from qodiqa import (
    AsyncQodiqaClient,
    KillSwitchError,
    NotFoundError,
    QodiqaClient,
    ServerError,
    VerificationError,
    VERIFICATION_REASONS,
    receipt_binds_to,
    receipt_digest,
    verify_receipt,
    RECEIPT_DOMAIN,
)
from qodiqa.exceptions import create_error

BASE_URL = "http://test.local"
RID = "6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b"
KEY_ID = "tr-default:key_v1"


def h(c: str) -> str:
    return c * 64


def make_key() -> Dict[str, Any]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {"priv": priv, "publicKey": base64.b64encode(pub).decode()}


def sign_receipt(priv: Ed25519PrivateKey, **over: Any) -> Dict[str, Any]:
    """Signed exactly as section 6 says, WITHOUT the SDK's own digest function."""
    unsigned = {"v": 1, "requestId": RID, "decision": "ALLOW", "issuedAt": 1790000000000, "entryHash": h("a"), "leafHash": h("b"), "keyId": KEY_ID}
    unsigned.update(over)
    canonical = json.dumps({k: unsigned[k] for k in sorted(unsigned)}, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(b"QODIQA::RECEIPT::V1" + canonical.encode("utf-8")).digest()
    return {**unsigned, "signature": base64.b64encode(priv.sign(digest)).decode()}


@pytest.fixture(scope="module")
def key() -> Dict[str, Any]:
    return make_key()


@pytest.fixture(scope="module")
def keys(key: Dict[str, Any]):
    return [{"keyId": KEY_ID, "publicKey": key["publicKey"], "status": "active"}]


@pytest.fixture(scope="module")
def receipt(key: Dict[str, Any]) -> Dict[str, Any]:
    return sign_receipt(key["priv"])


class TestVerifyReceipt:
    def test_verifies_a_receipt_signed_per_the_specification(self, receipt, keys) -> None:
        assert verify_receipt(receipt, keys) == (True, None)
        assert verify_receipt(receipt, {"keys": keys}) == (True, None)            # the body of /.well-known/qodiqa/transparency-keys
        assert RECEIPT_DOMAIN == "QODIQA::RECEIPT::V1"
        unsigned = {k: v for k, v in receipt.items() if k != "signature"}
        canonical = json.dumps({k: unsigned[k] for k in sorted(unsigned)}, separators=(",", ":"))
        assert receipt_digest(receipt) == hashlib.sha256(b"QODIQA::RECEIPT::V1" + canonical.encode()).digest()

    @pytest.mark.parametrize("patch", [
        {"requestId": RID.replace("6f", "7f")}, {"decision": "BLOCK"}, {"issuedAt": 1790000000001}, {"entryHash": h("c")}, {"leafHash": h("c")},
    ])
    def test_rejects_a_receipt_whose_field_changed(self, receipt, keys, patch) -> None:
        assert verify_receipt({**receipt, **patch}, keys) == (False, "BAD_SIGNATURE")

    def test_rejects_malformed_receipts_unknown_fields_versions_and_keys(self, receipt, keys, key) -> None:
        for bad in (None, "x", 7, [], [receipt]):
            assert verify_receipt(bad, keys)[0] is False
        assert verify_receipt({**receipt, "tenantId": "t1"}, keys) == (False, "FIELD_SET")
        assert verify_receipt({k: v for k, v in receipt.items() if k != "keyId"}, keys) == (False, "FIELD_SET")
        assert verify_receipt({**receipt, "v": 2}, keys) == (False, "UNSUPPORTED_VERSION")
        assert verify_receipt({**receipt, "v": True}, keys) == (False, "UNSUPPORTED_VERSION")
        assert verify_receipt({**receipt, "entryHash": h("A")}, keys) == (False, "INVALID_FIELD")
        assert verify_receipt({**receipt, "issuedAt": 1.5}, keys) == (False, "INVALID_FIELD")
        assert verify_receipt({**receipt, "issuedAt": True}, keys) == (False, "INVALID_FIELD")
        assert verify_receipt({**receipt, "decision": "EXECUTE"}, keys) == (False, "INVALID_FIELD")
        assert verify_receipt({**receipt, "keyId": "tr-other:key_v1"}, keys) == (False, "UNKNOWN_KEY")
        other = make_key()
        assert verify_receipt(receipt, [{"keyId": KEY_ID, "publicKey": other["publicKey"], "status": "active"}]) == (False, "BAD_SIGNATURE")
        assert verify_receipt({**receipt, "signature": "AA=="}, keys) == (False, "BAD_SIGNATURE")
        assert verify_receipt(receipt, [{"keyId": KEY_ID, "publicKey": "!!!", "status": "active"}]) == (False, "BAD_SIGNATURE")

    def test_a_revoked_key_verifies_only_in_the_timed_mode(self, receipt, key) -> None:
        def revoked(**extra: Any):
            return [{"keyId": KEY_ID, "publicKey": key["publicKey"], "status": "revoked", "revokedAt": 1790000100000, **extra}]

        assert verify_receipt(receipt, revoked()) == (False, "REVOKED_KEY")
        assert verify_receipt(receipt, revoked(), trusted_at=1790000050000) == (True, None)
        assert verify_receipt(receipt, revoked(), trusted_at=1790000100000) == (False, "REVOKED_KEY")
        assert verify_receipt(receipt, revoked(revokedAt=None), trusted_at=1) == (False, "REVOKED_KEY")
        iso = datetime.fromtimestamp(1790000100.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        assert verify_receipt(receipt, revoked(revokedAt=iso), trusted_at=1790000050000) == (True, None)

    def test_receipt_binds_to_names_the_values_that_differ(self, receipt) -> None:
        assert receipt_binds_to(receipt, entry_hash=h("a"), leaf_hash=h("b"), request_id=RID, decision="ALLOW") == (True, [])
        assert receipt_binds_to(receipt, entry_hash=h("c"), decision="BLOCK") == (False, ["entryHash", "decision"])


class TestOverHttp:
    def test_sign_sends_the_v2_block_the_query_and_the_bound_headers(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"artifactId": RID, "artifact": {}, "meta": {}, "requestId": "r"})
        v2 = {"bind": {"headers": ["x-tenant"]}, "model": "gpt-4", "limits": {"maxTokens": 256}, "crit": ["limits"]}
        QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, sign_token="sk_test").sign.sign({
            "request": {"method": "POST", "path": "/v1/ai/chat", "query": "stream=true&a=%2B", "headers": {"x-tenant": "acme"}, "body": {"prompt": "hi", "model": "gpt-4"}},
            "v2": v2,
        })
        sent = json.loads(httpx_mock.get_requests()[0].content)
        assert sent["v2"] == v2
        assert sent["request"]["query"] == "stream=true&a=%2B"
        assert sent["request"]["headers"] == {"x-tenant": "acme"}

    def test_chat_create_returns_the_receipt_untouched(self, httpx_mock: HTTPXMock, receipt, keys) -> None:
        httpx_mock.add_response(json={"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "response": "hello", "requestId": "r1", "receipt": receipt})
        res = QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0).chat.create("QQ==", {"prompt": "hi"})
        assert res["receipt"] == receipt
        assert verify_receipt(res["receipt"], keys) == (True, None)
        httpx_mock.add_response(json={"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "response": "hello", "requestId": "r2"})
        assert "receipt" not in QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0).chat.create("QQ==", {"prompt": "hi"})

    def test_transparency_get_receipt(self, httpx_mock: HTTPXMock, receipt) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/v1/transparency/receipt/{RID}", json={"status": "success", "timestamp": "t", "requestId": "x", "data": {"receipt": receipt}})
        res = QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0).transparency.get_receipt(RID)
        assert res["data"]["receipt"] == receipt
        with pytest.raises(Exception):
            QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0).transparency.get_receipt("")

    def test_an_expired_receipt_window_is_a_not_found_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=404, json={"status": "error", "error": {"code": "NOT_FOUND", "message": "Receipt not found"}})
        with pytest.raises(NotFoundError):
            QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0).transparency.get_receipt(RID)

    @pytest.mark.asyncio
    async def test_async_get_receipt(self, httpx_mock: HTTPXMock, receipt) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/v1/transparency/receipt/{RID}", json={"status": "success", "timestamp": "t", "requestId": "x", "data": {"receipt": receipt}})
        async with AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0) as c:
            res = await c.transparency.get_receipt(RID)
        assert res["data"]["receipt"] == receipt

    def test_the_kill_switch_is_a_kill_switch_error_a_server_error_and_is_not_retried(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={"decision": "BLOCK", "reason": "KILL_SWITCH_ACTIVE", "details": {}, "requestId": "r"}, headers={"Retry-After": "30"})
        with pytest.raises(KillSwitchError) as info:
            QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=2).chat.create("QQ==", {"prompt": "hi"})
        assert isinstance(info.value, ServerError)
        assert info.value.reason == "KILL_SWITCH_ACTIVE"
        assert info.value.status == 503
        assert len(httpx_mock.get_requests()) == 1                         # never resent

    def test_create_error_maps_both_kill_switch_reasons(self) -> None:
        for reason in ("KILL_SWITCH_ACTIVE", "KILL_SWITCH_STATE_UNAVAILABLE"):
            e = create_error(503, reason, "x", "r", {"retryAfter": 30})
            assert isinstance(e, KillSwitchError)
            assert e.retry_after == 30.0
        assert not isinstance(create_error(503, "SERVER_OVERLOADED", "x"), KillSwitchError)

    def test_a_revoked_artifact_is_a_verification_error(self, httpx_mock: HTTPXMock) -> None:
        assert "ARTIFACT_REVOKED" in VERIFICATION_REASONS
        httpx_mock.add_response(json={"decision": "BLOCK", "reason": "ARTIFACT_REVOKED", "details": {}, "requestId": "r"})
        with pytest.raises(VerificationError):
            QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0).chat.create("QQ==", {"prompt": "hi"})
