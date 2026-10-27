"""Tests for the resources (agents, sessions, actions, tools, delegations, tool registry, MCP servers, approvals) and the agent proof."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pytest_httpx import HTTPXMock

from qodiqa import (
    AGENT_PROOF_DOMAIN,
    AsyncQodiqaClient,
    QodiqaClient,
    agent_proof_digest,
    generate_agent_key_pair,
    is_approval_pending,
    sign_agent_proof,
)
from qodiqa.exceptions import AuthenticationError, TimeoutError as QTimeout, ValidationError

BASE = "http://test.local"
KEY = "ok_" + "c" * 64
SIGN = "sk_test"
CTX = {
    "tenantId": "t1",
    "agentId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "sessionId": "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb",
    "requestId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
}
ACTION = {"agentId": CTX["agentId"], "sessionId": CTX["sessionId"], "tool": {"server": "files", "name": "read"}, "args": {"path": "/a"}}


def client(**kw) -> QodiqaClient:
    return QodiqaClient(base_url=BASE, timeout=5.0, max_retries=0, api_key=KEY, sign_token=SIGN, **kw)


def aclient() -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE, timeout=5.0, max_retries=0, api_key=KEY, sign_token=SIGN)


class TestAgentProof:
    def test_digest_is_pinned_and_matches_the_js_sdk(self) -> None:
        assert agent_proof_digest(CTX).hex() == "397af04cff3064767af39481294859af1cbcd00caaf1622062e6f8be5e3e4600"
        assert AGENT_PROOF_DOMAIN == "QODIQA::AGENT_REQUEST::V1"

    def test_signature_verifies_against_the_registered_public_key(self) -> None:
        pub_b64, priv = generate_agent_key_pair()
        sig = base64.b64decode(sign_agent_proof(CTX, priv))
        pub = serialization.load_der_public_key(base64.b64decode(pub_b64))
        assert isinstance(pub, Ed25519PublicKey)
        pub.verify(sig, agent_proof_digest(CTX))

    def test_proof_is_bound_to_one_request(self) -> None:
        _, priv = generate_agent_key_pair()
        assert sign_agent_proof(CTX, priv) != sign_agent_proof({**CTX, "requestId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}, priv)

    def test_pem_and_der_keys_are_accepted(self) -> None:
        _, priv = generate_agent_key_pair()
        pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        assert sign_agent_proof(CTX, pem) == sign_agent_proof(CTX, der) == sign_agent_proof(CTX, pem.decode())

    def test_missing_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            agent_proof_digest({**CTX, "requestId": ""})


class TestAdminPlane:
    def test_agents_create_uses_ops_key(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"data": {"agentId": "a1"}})
        client().agents.create({"tenantId": "t1", "displayName": "bot"})
        req = httpx_mock.get_requests()[0]
        assert req.method == "POST" and req.url.path == "/v1/agents"
        assert req.headers["Authorization"] == f"Bearer {KEY}"
        assert json.loads(req.content)["displayName"] == "bot"

    def test_agents_revoke_is_a_patch_with_encoded_id(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"data": {}})
        client().agents.revoke("a/1", "t1")
        req = httpx_mock.get_requests()[0]
        assert req.method == "PATCH" and req.url.raw_path.decode().startswith("/v1/agents/a%2F1")
        assert json.loads(req.content) == {"tenantId": "t1", "status": "revoked"}

    def test_sessions_kill_and_list_query(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"data": {}})
        httpx_mock.add_response(json={"data": {"sessions": []}})
        c = client()
        c.sessions.kill("s1", "t1", "compromised")
        c.sessions.list("t1", status="active")
        reqs = httpx_mock.get_requests()
        assert reqs[0].url.path == "/v1/sessions/s1/kill" and json.loads(reqs[0].content)["reason"] == "compromised"
        assert dict(reqs[1].url.params) == {"tenantId": "t1", "status": "active"}

    def test_ops_key_required(self) -> None:
        with pytest.raises(AuthenticationError):
            QodiqaClient(base_url=BASE, sign_token=SIGN).agents.list("t1")

    def test_tool_registry_and_mcp_and_approvals_routes(self, httpx_mock: HTTPXMock) -> None:
        for _ in range(7):
            httpx_mock.add_response(json={"data": {}})
        c = client()
        c.tool_registry.register({"tenantId": "t1", "server": "files", "name": "read"})
        c.tool_registry.approve("t1", "files", "read", 2)
        c.mcp_servers.register({"tenantId": "t1", "serverId": "s", "url": "https://x"})
        c.mcp_servers.disable("s", "t1", "why")
        c.mcp_servers.refresh_tools("s", "t1")
        c.approvals.get("ap1", "t1")
        c.approvals.decide("ap1", {"tenantId": "t1", "decision": "approve"})
        paths = [r.url.path for r in httpx_mock.get_requests()]
        assert paths == [
            "/v1/tool-registry", "/v1/tool-registry/approve", "/v1/mcp/servers", "/v1/mcp/servers/s/disable",
            "/v1/mcp/servers/s/tools/refresh", "/v1/approvals/ap1", "/v1/approvals/ap1/decision",
        ]

    def test_validation_before_network(self) -> None:
        with pytest.raises(ValidationError):
            client().mcp_servers.disable("s", "t1", "")


class TestSigningPlane:
    def test_authorize_sends_sign_token_and_returns_artifact(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"artifact": {"kind": "action"}})
        out = client().actions.authorize(ACTION)
        req = httpx_mock.get_requests()[0]
        assert req.headers["Authorization"] == f"Bearer {SIGN}" and req.url.path == "/v1/actions/authorize"
        assert out["artifact"]["kind"] == "action" and not is_approval_pending(out)

    def test_authorize_validates_args(self) -> None:
        with pytest.raises(ValidationError):
            client().actions.authorize({**ACTION, "args": []})

    def test_pending_is_detected(self) -> None:
        assert is_approval_pending({"status": "pending", "data": {"approvalId": "ap1"}})
        assert not is_approval_pending({"artifact": {}})

    def test_authorize_and_wait_polls_then_reauthorizes_with_approval(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=202, json={"status": "pending", "data": {"approvalId": "ap1"}})
        httpx_mock.add_response(json={"data": {"status": "PENDING"}})
        httpx_mock.add_response(json={"data": {"status": "APPROVED"}})
        httpx_mock.add_response(json={"artifact": {"kind": "action", "approvalRef": "ap1"}})
        out = client().actions.authorize_and_wait(ACTION, timeout_s=5, poll_s=0.01)
        reqs = httpx_mock.get_requests()
        assert out["artifact"]["approvalRef"] == "ap1"
        assert json.loads(reqs[3].content)["approvalId"] == "ap1"

    def test_wait_for_approval_times_out(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"data": {"status": "PENDING"}}, is_reusable=True)
        with pytest.raises(QTimeout):
            client().actions.wait_for_approval("ap1", timeout_s=0.05, poll_s=0.04)

    def test_cancel_approval_unwraps_data(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"data": {"status": "CANCELLED"}})
        assert client().actions.cancel_approval("ap1", "changed my mind")["status"] == "CANCELLED"

    def test_create_plan_requires_steps(self) -> None:
        with pytest.raises(ValidationError):
            client().actions.create_plan({"agentId": "a", "sessionId": "s", "steps": []})

    def test_tools_call(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"decision": "EXECUTE", "result": {"delimited": "x"}})
        out = client().tools.call({"artifact": {"kind": "action"}, "tool": {"server": "files", "name": "read"}, "args": {}})
        assert out["decision"] == "EXECUTE"
        with pytest.raises(ValidationError):
            client().tools.call({"artifact": None, "tool": {"server": "a", "name": "b"}, "args": {}})

    def test_delegations(self, httpx_mock: HTTPXMock) -> None:
        for _ in range(3):
            httpx_mock.add_response(json={})
        c = client()
        c.delegations.issue({"issuerAgentId": "a", "issuerSessionId": "s", "subjectAgentId": "b", "classes": ["read"]})
        c.delegations.verify(delegation_id="d1")
        c.delegations.revoke("d1", "why", revoke_agents=True)
        reqs = httpx_mock.get_requests()
        assert json.loads(reqs[1].content) == {"delegationId": "d1"}
        assert json.loads(reqs[2].content) == {"reason": "why", "revokeAgents": True}
        with pytest.raises(ValidationError):
            c.delegations.verify()
        with pytest.raises(ValidationError):
            c.delegations.issue({"issuerAgentId": "a", "issuerSessionId": "s", "subjectAgentId": "b", "classes": []})


class TestAsync:
    @pytest.mark.asyncio
    async def test_async_authorize_and_wait(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=202, json={"status": "pending", "data": {"approvalId": "ap1"}})
        httpx_mock.add_response(json={"data": {"status": "APPROVED"}})
        httpx_mock.add_response(json={"artifact": {"kind": "action"}})
        async with aclient() as c:
            out = await c.actions.authorize_and_wait(ACTION, timeout_s=5, poll_s=0.01)
        assert out["artifact"]["kind"] == "action"

    @pytest.mark.asyncio
    async def test_async_admin_calls_and_revoke(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"data": {}})
        httpx_mock.add_response(json={"data": {"agents": []}})
        async with aclient() as c:
            await c.agents.revoke("a1", "t1")
            await c.agents.list("t1")
        reqs = httpx_mock.get_requests()
        assert reqs[0].method == "PATCH" and reqs[1].method == "GET"

    @pytest.mark.asyncio
    async def test_async_validation_raises(self) -> None:
        async with aclient() as c:
            with pytest.raises(ValidationError):
                await c.tools.call({"artifact": {}, "tool": {"server": "", "name": "x"}, "args": {}})
