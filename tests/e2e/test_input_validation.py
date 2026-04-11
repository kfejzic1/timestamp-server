"""Input-validation tests for the FROST Timestamping Authority gateway.

These tests confirm that malformed or out-of-contract requests are rejected
with appropriate HTTP error codes (422 Unprocessable Entity from Pydantic, or
500 when the error surfaces inside the orchestrator).
"""
from __future__ import annotations

import hashlib

import pytest

import httpx

GATEWAY_URL = "http://localhost:8000"

_ERROR_CODES = (400, 422, 500)


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _good_token(gateway: httpx.Client) -> dict:
    """Return a valid timestamp token to use as a base for tampering."""
    doc_hash = _sha256("input-validation-base")
    r = gateway.post("/api/timestamp", json={"document_hash": doc_hash})
    assert r.status_code == 200
    return r.json()


# ---------------------------------------------------------------------------
# POST /api/timestamp — invalid document_hash values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_hash,description", [
    ("not-hex-at-all",          "non-hex characters"),
    ("deadbeef",                "too short (4 bytes instead of 32)"),
    ("abc",                     "odd-length hex string"),
    ("",                        "empty string"),
    ("ZZ" * 32,                 "out-of-range hex characters"),
])
def test_timestamp_rejects_invalid_hash(
    cluster_ready: None, gateway: httpx.Client, bad_hash: str, description: str
) -> None:
    """POST /api/timestamp with a malformed hash returns a client or server error."""
    r = gateway.post("/api/timestamp", json={"document_hash": bad_hash})
    assert r.status_code in _ERROR_CODES, (
        f"Expected error for {description!r}, got {r.status_code}: {r.text}"
    )


def test_timestamp_rejects_missing_hash(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/timestamp with no body returns 422."""
    r = gateway.post("/api/timestamp", json={})
    assert r.status_code == 422


def test_timestamp_rejects_wrong_type_for_hash(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/timestamp with a non-string document_hash returns 422."""
    r = gateway.post("/api/timestamp", json={"document_hash": 12345})
    assert r.status_code == 422


def test_timestamp_rejects_null_hash(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/timestamp with null document_hash returns 422."""
    r = gateway.post("/api/timestamp", json={"document_hash": None})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/verify — malformed token payloads
# ---------------------------------------------------------------------------


def test_verify_rejects_empty_body(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/verify with no body returns 422."""
    r = gateway.post("/api/verify", json={})
    assert r.status_code == 422


def test_verify_rejects_missing_token(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/verify with document_hash but no token returns 422."""
    r = gateway.post("/api/verify", json={"document_hash": _sha256("x")})
    assert r.status_code == 422


def test_verify_rejects_missing_document_hash(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/verify with token but no document_hash returns 422."""
    token = _good_token(gateway)
    r = gateway.post("/api/verify", json={"token": token})
    assert r.status_code == 422


@pytest.mark.parametrize("drop_field", [
    "signature",
    "verification_key",
    "timestamp",
    "serial_number",
    "participants",
])
def test_verify_rejects_token_missing_required_field(
    cluster_ready: None, gateway: httpx.Client, drop_field: str
) -> None:
    """POST /api/verify with a token missing a required field returns 422."""
    doc_hash = _sha256("missing-field-test")
    token = _good_token(gateway)
    token.pop(drop_field)

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    assert r.status_code == 422, (
        f"Expected 422 when {drop_field!r} is absent, got {r.status_code}"
    )


def test_verify_rejects_non_hex_signature(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/verify with a non-hex signature string returns an error."""
    doc_hash = _sha256("non-hex-sig")
    token = _good_token(gateway)
    token["signature"] = "not-valid-hex!"

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    assert r.status_code in _ERROR_CODES


def test_verify_rejects_wrong_participants_type(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/verify with participants as a string instead of list returns 422."""
    doc_hash = _sha256("wrong-type-participants")
    token = _good_token(gateway)
    token["participants"] = "not-a-list"

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/dkg/start — precondition errors
# ---------------------------------------------------------------------------


def test_dkg_start_returns_200_when_already_complete(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/dkg/start after DKG is done must succeed (not error)."""
    r = gateway.post("/api/dkg/start")
    assert r.status_code == 200
    assert r.json()["status"] == "already_complete"
