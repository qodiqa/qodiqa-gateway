"""Tests for CertificationResource and AsyncCertificationResource."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import AuthenticationError, ValidationError

BASE_URL = "http://test.local"
VALID_KEY = "ok_" + "c" * 64

MOCK_ARTIFACT = {"expiry": 9999999999, "signature": "sig123"}
CERT_RECORD = {
    "id": "cert-001",
    "decision": "EXECUTE",
    "reason": "OK",
    "timestamp": "2024-01-01T00:00:00Z",
}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestCertificationEvaluate:
    def test_returns_result(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        result = make_client(api_key=VALID_KEY).certification.evaluate([MOCK_ARTIFACT])
        assert result["id"] == "cert-001"

    def test_posts_to_evaluate_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        make_client(api_key=VALID_KEY).certification.evaluate([MOCK_ARTIFACT])
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/certification/evaluate")

    def test_sends_artifacts_as_array(self, httpx_mock: HTTPXMock) -> None:
        # Real (server-strict-validated) shape is {artifacts: [...]}, not a
        # single {artifact} — confirmed live during's SDK-accuracy sweep.
        httpx_mock.add_response(json=CERT_RECORD)
        make_client(api_key=VALID_KEY).certification.evaluate([MOCK_ARTIFACT])
        import json as _json
        req = httpx_mock.get_requests()[0]
        body = _json.loads(req.content)
        assert body["artifacts"] == [MOCK_ARTIFACT]

    def test_forwards_extra_kwargs(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        make_client(api_key=VALID_KEY).certification.evaluate([MOCK_ARTIFACT], context="prod")
        import json as _json
        req = httpx_mock.get_requests()[0]
        body = _json.loads(req.content)
        assert body["context"] == "prod"


class TestCertificationEvaluateAuth:
    """/v1/certification/evaluate is mounted on the admin router — the ops key is required."""

    def test_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().certification.evaluate([MOCK_ARTIFACT])

    def test_sends_authorization_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        make_client(api_key=VALID_KEY).certification.evaluate([MOCK_ARTIFACT])
        assert httpx_mock.get_requests()[0].headers["authorization"].startswith("Bearer ok_")


class TestCertificationGet:
    def test_returns_record(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        result = make_client().certification.get("cert-001")
        assert result["id"] == "cert-001"

    def test_fetches_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        make_client().certification.get("cert-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/certification/cert-001" in str(req.url)

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().certification.get("")


class TestCertificationGetSummary:
    def test_returns_summary(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"summary": "ok"})
        result = make_client().certification.get_summary("cert-001")
        assert result["summary"] == "ok"

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().certification.get_summary("")


class TestCertificationOpsEndpoints:
    def test_submit_batch_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().certification.submit_batch(
                "default", [{"subjectId": "subj-1", "artifacts": [MOCK_ARTIFACT]}]
            )

    def test_submit_batch_posts_to_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"batchId": "batch-001"})
        make_client(api_key=VALID_KEY).certification.submit_batch(
            "default", [{"subjectId": "subj-1", "artifacts": [MOCK_ARTIFACT]}]
        )
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/certifications/batch")

    def test_submit_batch_sends_framework_id_and_subject_id(self, httpx_mock: HTTPXMock) -> None:
        # Real (server-validated) shape requires frameworkId + items[].subjectId
        # — confirmed live during's SDK-accuracy sweep.
        httpx_mock.add_response(json={"batchId": "batch-001"})
        make_client(api_key=VALID_KEY).certification.submit_batch(
            "default", [{"subjectId": "subj-1", "artifacts": [MOCK_ARTIFACT]}]
        )
        import json as _json
        req = httpx_mock.get_requests()[0]
        body = _json.loads(req.content)
        assert body["frameworkId"] == "default"
        assert body["items"][0]["subjectId"] == "subj-1"

    def test_get_batch_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).certification.get_batch("")

    def test_get_batch_fetches_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"batchId": "batch-001", "status": "pending"})
        make_client(api_key=VALID_KEY).certification.get_batch("batch-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/certifications/batch/batch-001" in str(req.url)

    def test_get_batch_results_fetches_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": []})
        make_client(api_key=VALID_KEY).certification.get_batch_results("batch-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/certifications/batch/batch-001/results" in str(req.url)

    def test_cancel_batch_posts_to_cancel_route(self, httpx_mock: HTTPXMock) -> None:
        # Real route is POST /v1/certifications/batch/:id/cancel, NOT
        # DELETE /v1/certifications/batch/:id — confirmed live during
        #'s SDK-accuracy sweep (the DELETE route doesn't exist, 405s).
        httpx_mock.add_response(json={"cancelled": True})
        result = make_client(api_key=VALID_KEY).certification.cancel_batch("batch-001")
        assert result["cancelled"] is True
        req = httpx_mock.get_requests()[0]
        assert req.method == "POST"
        assert str(req.url).endswith("/v1/certifications/batch/batch-001/cancel")

    def test_list_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().certification.list()

    def test_stats_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().certification.stats()

    def test_stats_fetches_correct_url(self, httpx_mock: HTTPXMock) -> None:
        # Real route is the singular /v1/certification/admin/stats, NOT
        # plural /v1/certifications/stats (which doesn't exist, 405s) —
        # confirmed live during's SDK-accuracy sweep.
        httpx_mock.add_response(json={"total": 99})
        make_client(api_key=VALID_KEY).certification.stats()
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/certification/admin/stats")


class TestAsyncCertificationResource:
    async def test_evaluate(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CERT_RECORD)
        async with make_async_client(api_key=VALID_KEY) as client:
            result = await client.certification.evaluate([MOCK_ARTIFACT])
        assert result["id"] == "cert-001"

    async def test_get_raises_on_empty_id(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                await client.certification.get("")

    async def test_stats(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"total": 5})
        async with make_async_client(api_key=VALID_KEY) as client:
            result = await client.certification.stats()
        assert result["total"] == 5
