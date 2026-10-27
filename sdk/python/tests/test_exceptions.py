"""Tests for the QODIQA exception hierarchy."""

from __future__ import annotations

import pytest

from qodiqa.exceptions import (
    AuthenticationError,
    AuthorizationError,
    CryptoKeyError,
    NetworkError,
    NotFoundError,
    QodiqaError,
    RateLimitError,
    SerializationError,
    ServerError,
    SigningError,
    TimeoutError,
    UnknownError,
    ValidationError,
    VerificationError,
    create_error,
)


class TestInheritance:
    @pytest.mark.parametrize(
        "exc",
        [
            AuthenticationError("auth"),
            AuthorizationError("authz"),
            ValidationError("val"),
            VerificationError("ver"),
            NotFoundError("nf"),
            RateLimitError("rl"),
            ServerError("srv"),
            NetworkError("net"),
            TimeoutError("to"),
            UnknownError("unk"),
            SigningError("sign"),
            SerializationError("ser"),
            CryptoKeyError("key"),
        ],
    )
    def test_all_inherit_from_qodiqa_error(self, exc: QodiqaError) -> None:
        assert isinstance(exc, QodiqaError)
        assert isinstance(exc, Exception)

    @pytest.mark.parametrize(
        "cls,name",
        [
            (AuthenticationError, "AuthenticationError"),
            (AuthorizationError, "AuthorizationError"),
            (ValidationError, "ValidationError"),
            (VerificationError, "VerificationError"),
            (NotFoundError, "NotFoundError"),
            (RateLimitError, "RateLimitError"),
            (ServerError, "ServerError"),
            (NetworkError, "NetworkError"),
            (TimeoutError, "TimeoutError"),
            (UnknownError, "UnknownError"),
        ],
    )
    def test_class_name(self, cls: type, name: str) -> None:
        assert cls.__name__ == name


class TestProperties:
    def test_message_stored(self) -> None:
        err = QodiqaError("hello world")
        assert err.message == "hello world"
        assert str(err) == "hello world"

    def test_status_stored(self) -> None:
        err = AuthenticationError("msg", status=401)
        assert err.status == 401

    def test_request_id_stored(self) -> None:
        err = NotFoundError("not found", request_id="req-123")
        assert err.request_id == "req-123"

    def test_details_stored(self) -> None:
        err = ValidationError("bad", details={"field": "email"})
        assert err.details == {"field": "email"}

    def test_details_defaults_to_empty(self) -> None:
        err = QodiqaError("no details")
        assert err.details == {}

    def test_authentication_error_default_status(self) -> None:
        assert AuthenticationError("x").status == 401

    def test_authorization_error_default_status(self) -> None:
        assert AuthorizationError("x").status == 403

    def test_validation_error_default_status(self) -> None:
        assert ValidationError("x").status == 400

    def test_verification_error_default_status(self) -> None:
        assert VerificationError("x").status == 400

    def test_not_found_error_default_status(self) -> None:
        assert NotFoundError("x").status == 404

    def test_rate_limit_error_default_status(self) -> None:
        assert RateLimitError("x").status == 429

    def test_rate_limit_error_retry_after(self) -> None:
        err = RateLimitError("slow", retry_after=30.0)
        assert err.retry_after == 30.0

    def test_rate_limit_error_retry_after_none(self) -> None:
        err = RateLimitError("slow")
        assert err.retry_after is None

    def test_server_error_default_status(self) -> None:
        assert ServerError("x").status == 500

    def test_repr_contains_class_name(self) -> None:
        err = NotFoundError("missing", request_id="r1")
        r = repr(err)
        assert "NotFoundError" in r
        assert "missing" in r


class TestCreateError:
    def test_maps_401_to_authentication_error(self) -> None:
        assert isinstance(create_error(401, "UNAUTHORIZED", "msg"), AuthenticationError)

    def test_maps_unauthorized_reason_to_authentication_error(self) -> None:
        assert isinstance(create_error(200, "UNAUTHORIZED", "msg"), AuthenticationError)

    def test_maps_unauthenticated_reason(self) -> None:
        assert isinstance(create_error(200, "UNAUTHENTICATED", "msg"), AuthenticationError)

    def test_maps_403_to_authorization_error(self) -> None:
        assert isinstance(create_error(403, "FORBIDDEN", "msg"), AuthorizationError)

    # (SDK half): reason-code is now checked before the blanket
    # status==403 branch. Every VerificationError reason maps to HTTP 403
    # server-side (src/errors/catalog.js) — previously this exact case
    # (status 403 + a VerificationError reason) always fell into
    # AuthorizationError instead, because the status check ran first.
    def test_status_403_with_request_mismatch_reason_maps_to_verification_error(self) -> None:
        err = create_error(403, "REQUEST_MISMATCH", "Request content does not match signed hash")
        assert isinstance(err, VerificationError)
        assert not isinstance(err, AuthorizationError)

    def test_status_403_with_forbidden_reason_still_maps_to_authorization_error(self) -> None:
        err = create_error(403, "FORBIDDEN", "No access")
        assert isinstance(err, AuthorizationError)
        assert not isinstance(err, VerificationError)

    def test_status_401_unaffected_by_reorder(self) -> None:
        err = create_error(401, "UNAUTHORIZED", "Not authorized")
        assert isinstance(err, AuthenticationError)
        assert not isinstance(err, VerificationError)

    def test_maps_404_to_not_found(self) -> None:
        assert isinstance(create_error(404, "NOT_FOUND", "msg"), NotFoundError)

    def test_maps_429_to_rate_limit(self) -> None:
        assert isinstance(create_error(429, "RATE_LIMITED", "msg"), RateLimitError)

    def test_maps_rate_limit_exceeded_reason(self) -> None:
        assert isinstance(create_error(200, "RATE_LIMIT_EXCEEDED", "msg"), RateLimitError)

    def test_maps_invalid_signature_to_verification_error(self) -> None:
        assert isinstance(create_error(400, "INVALID_SIGNATURE", "bad sig"), VerificationError)

    def test_maps_expired_to_verification_error(self) -> None:
        assert isinstance(create_error(400, "EXPIRED", "expired"), VerificationError)

    def test_maps_key_not_found_to_verification_error(self) -> None:
        assert isinstance(create_error(400, "KEY_NOT_FOUND", "unregistered"), VerificationError)

    def test_maps_request_mismatch_to_verification_error(self) -> None:
        assert isinstance(create_error(400, "REQUEST_MISMATCH", "mismatch"), VerificationError)

    def test_maps_replay_detected_to_verification_error(self) -> None:
        assert isinstance(create_error(400, "REPLAY_DETECTED", "replayed"), VerificationError)

    def test_maps_invalid_artifact_to_verification_error(self) -> None:
        assert isinstance(create_error(400, "INVALID_ARTIFACT", "invalid"), VerificationError)

    def test_maps_400_to_validation_error(self) -> None:
        assert isinstance(create_error(400, "VALIDATION_ERROR", "bad"), ValidationError)

    def test_maps_422_to_validation_error(self) -> None:
        assert isinstance(create_error(422, "INVALID_REQUEST", "unproc"), ValidationError)

    def test_maps_500_to_server_error(self) -> None:
        assert isinstance(create_error(500, "INTERNAL_ERROR", "boom"), ServerError)

    def test_maps_502_to_server_error(self) -> None:
        assert isinstance(create_error(502, "BAD_GATEWAY", "bad gw"), ServerError)

    def test_maps_503_to_server_error(self) -> None:
        assert isinstance(create_error(503, "SERVICE_UNAVAILABLE", "down"), ServerError)

    def test_maps_unknown_to_unknown_error(self) -> None:
        assert isinstance(create_error(418, "IM_A_TEAPOT", "tea"), UnknownError)

    def test_populates_request_id(self) -> None:
        err = create_error(404, "NOT_FOUND", "missing", "req-xyz")
        assert err.request_id == "req-xyz"

    def test_populates_details(self) -> None:
        err = create_error(400, "VALIDATION_ERROR", "bad", details={"field": "prompt"})
        assert err.details == {"field": "prompt"}

    def test_rate_limit_retry_after_from_details(self) -> None:
        err = create_error(429, "RATE_LIMITED", "slow", details={"retryAfter": 60.0})
        assert isinstance(err, RateLimitError)
        assert err.retry_after == 60.0
