"""End-to-end tests for the FROST Trusted Timestamping Authority.

These tests exercise the full happy-path and key error cases of the public
gateway API against a running Docker Compose cluster.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import httpx
import pytest

GATEWAY_URL = "http://localhost:8000"

# Expected ISO-8601 format produced by the gateway: 2026-04-11T10:30:45.123Z
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _timestamp_token(gateway: httpx.Client, label: str) -> dict:
    """Create a timestamp token for a labelled document."""
    r = gateway.post("/api/timestamp", json={"document_hash": _sha256(label)})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Infrastructure / readiness
# ---------------------------------------------------------------------------


def test_status_endpoint_shape(gateway: httpx.Client) -> None:
    """GET /api/status returns expected fields with reasonable values."""
    r = gateway.get("/api/status")
    assert r.status_code == 200
    body = r.json()

    for field in ("phase", "registered_signers", "expected_signers", "dkg_complete",
                  "threshold", "max_signers"):
        assert field in body, f"Missing field: {field}"

    assert body["threshold"] > 0
    assert body["max_signers"] >= body["threshold"]
    assert body["registered_signers"] <= body["max_signers"]


def test_cluster_becomes_ready(cluster_ready: None, gateway: httpx.Client) -> None:
    """Cluster reaches the 'ready' phase after DKG completes."""
    status = gateway.get("/api/status").json()
    assert status["dkg_complete"] is True
    assert status["phase"] == "ready"
    assert status["verification_key"] != ""


def test_dkg_start_idempotent(cluster_ready: None, gateway: httpx.Client) -> None:
    """Calling /api/dkg/start after DKG is complete returns already_complete."""
    r = gateway.post("/api/dkg/start")
    assert r.status_code == 200
    assert r.json()["status"] == "already_complete"


def test_openapi_schema_lists_all_endpoints(gateway: httpx.Client) -> None:
    """OpenAPI schema is reachable and declares all public endpoints."""
    r = gateway.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    for path in ("/api/status", "/api/dkg/start", "/api/timestamp", "/api/verify"):
        assert path in paths, f"Missing path in OpenAPI schema: {path}"


def test_docs_ui_is_served(gateway: httpx.Client) -> None:
    """GET /docs returns the interactive API documentation page."""
    r = gateway.get("/docs", follow_redirects=True)
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# Timestamp creation — field shapes
# ---------------------------------------------------------------------------


def test_create_timestamp_returns_valid_token(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """POST /api/timestamp returns a well-formed TimestampToken."""
    doc_hash = _sha256("Hello, FROST!")
    r = gateway.post("/api/timestamp", json={"document_hash": doc_hash})
    assert r.status_code == 200
    token = r.json()

    assert token["document_hash"] == doc_hash
    assert token["version"] == 1
    assert token["hash_algorithm"] == "SHA-256"
    assert token["ciphersuite"] == "FROST-RISTRETTO255-SHA512"
    assert token["signature"] != ""
    assert token["verification_key"] != ""
    assert token["timestamp"] != ""
    assert token["serial_number"] != ""
    assert len(token["participants"]) == token["threshold"]


def test_token_timestamp_is_iso8601(cluster_ready: None, gateway: httpx.Client) -> None:
    """Token timestamp is formatted as ISO-8601 UTC and is a plausible recent time."""
    token = _timestamp_token(gateway, "iso8601-check")
    ts_str = token["timestamp"]

    assert _TS_RE.match(ts_str), f"Unexpected timestamp format: {ts_str!r}"

    # Parsed value must be a valid datetime
    parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    delta = abs((now - parsed).total_seconds())
    assert delta < 60, f"Timestamp is more than 60 s from now: {ts_str}"


def test_token_serial_is_uuid(cluster_ready: None, gateway: httpx.Client) -> None:
    """Token serial_number is a valid UUID."""
    token = _timestamp_token(gateway, "uuid-check")
    try:
        uuid.UUID(token["serial_number"])
    except ValueError:
        pytest.fail(f"serial_number is not a valid UUID: {token['serial_number']!r}")


def test_token_participant_ids_in_range(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Every participant ID in the token is within [1, max_signers]."""
    token = _timestamp_token(gateway, "participant-range-check")
    max_s = token["max_signers"]
    for pid in token["participants"]:
        assert 1 <= pid <= max_s, f"Participant ID out of range: {pid}"


def test_token_threshold_matches_cluster(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Token threshold matches what the cluster reports."""
    status = gateway.get("/api/status").json()
    token = _timestamp_token(gateway, "threshold-check")
    assert token["threshold"] == status["threshold"]
    assert token["max_signers"] == status["max_signers"]


def test_verification_key_is_stable(cluster_ready: None, gateway: httpx.Client) -> None:
    """All tokens share the same group verification key (it never changes post-DKG)."""
    tokens = [_timestamp_token(gateway, f"vkey-stability-{i}") for i in range(3)]
    vkeys = {t["verification_key"] for t in tokens}
    assert len(vkeys) == 1, f"Verification key changed between tokens: {vkeys}"

    # Must also match what /api/status reports
    status_vkey = gateway.get("/api/status").json()["verification_key"]
    assert list(vkeys)[0] == status_vkey


# ---------------------------------------------------------------------------
# Timestamp verification
# ---------------------------------------------------------------------------


def test_verify_valid_token(cluster_ready: None, gateway: httpx.Client) -> None:
    """A freshly created token verifies successfully."""
    doc_hash = _sha256("Verify me, FROST!")
    r = gateway.post("/api/timestamp", json={"document_hash": doc_hash})
    assert r.status_code == 200
    token = r.json()

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    assert r.status_code == 200
    result = r.json()
    assert result["valid"] is True
    assert result["document_hash"] == doc_hash
    assert result["timestamp"] == token["timestamp"]


def test_verify_response_echoes_metadata(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Verify response echoes document_hash and timestamp from the token."""
    doc_hash = _sha256("metadata-echo-check")
    token = _timestamp_token(gateway, "metadata-echo-check")

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    assert r.status_code == 200
    result = r.json()
    assert result["document_hash"] == doc_hash
    assert result["timestamp"] == token["timestamp"]


def test_verify_tampered_hash_invalid(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Verifying a token with a different document hash must not succeed."""
    doc_hash = _sha256("Original document")
    wrong_hash = _sha256("Tampered document")

    token = _timestamp_token(gateway, "Original document")

    r = gateway.post("/api/verify", json={"document_hash": wrong_hash, "token": token})
    if r.status_code == 200:
        assert r.json()["valid"] is False
    else:
        assert r.status_code in (400, 422, 500)


def test_verify_tampered_signature_invalid(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """A token whose signature has been altered must not verify."""
    doc_hash = _sha256("signature-tamper-test")
    token = _timestamp_token(gateway, "signature-tamper-test")

    # Flip the first byte of the hex-encoded signature
    sig = token["signature"]
    first_byte = int(sig[:2], 16) ^ 0xFF
    token["signature"] = f"{first_byte:02x}{sig[2:]}"

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    if r.status_code == 200:
        assert r.json()["valid"] is False
    else:
        assert r.status_code in (400, 422, 500)


def test_verify_tampered_timestamp_field_invalid(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Changing the timestamp field in a token breaks the signature."""
    doc_hash = _sha256("timestamp-tamper-test")
    token = _timestamp_token(gateway, "timestamp-tamper-test")

    # Alter the timestamp by one second
    original = token["timestamp"]
    token["timestamp"] = original.replace("T", "T00:").split("T")[0] + "T00:00:00.000Z"

    r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
    if r.status_code == 200:
        assert r.json()["valid"] is False
    else:
        assert r.status_code in (400, 422, 500)


# ---------------------------------------------------------------------------
# Multiple independent timestamps
# ---------------------------------------------------------------------------


def test_multiple_timestamps_are_independent(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Multiple timestamps produce unique serial numbers and all verify."""
    documents = [f"Document {i}" for i in range(3)]
    pairs: list[tuple[str, dict]] = []

    for doc in documents:
        doc_hash = _sha256(doc)
        r = gateway.post("/api/timestamp", json={"document_hash": doc_hash})
        assert r.status_code == 200
        pairs.append((doc_hash, r.json()))

    serials = [token["serial_number"] for _, token in pairs]
    assert len(set(serials)) == len(serials), "Serial numbers must be unique"

    for doc_hash, token in pairs:
        r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
        assert r.status_code == 200
        assert r.json()["valid"] is True


def test_token_not_reusable_for_different_document(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """A token issued for document A must not validate as document B."""
    hash_a = _sha256("document-a")
    hash_b = _sha256("document-b")

    token_a = _timestamp_token(gateway, "document-a")

    r = gateway.post("/api/verify", json={"document_hash": hash_b, "token": token_a})
    if r.status_code == 200:
        assert r.json()["valid"] is False
    else:
        assert r.status_code in (400, 422, 500)


def test_same_hash_twice_gives_different_serials(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Timestamping the same document hash twice gives two distinct tokens."""
    doc_hash = _sha256("repeated-document")

    token1 = _timestamp_token(gateway, "repeated-document")
    token2 = _timestamp_token(gateway, "repeated-document")

    assert token1["serial_number"] != token2["serial_number"]
    assert token1["timestamp"] <= token2["timestamp"]  # monotonically non-decreasing

    # Both tokens must independently verify
    for token in (token1, token2):
        r = gateway.post("/api/verify", json={"document_hash": doc_hash, "token": token})
        assert r.status_code == 200
        assert r.json()["valid"] is True


# ---------------------------------------------------------------------------
# Concurrent requests
# ---------------------------------------------------------------------------


def test_concurrent_timestamps_all_succeed(
    cluster_ready: None, gateway: httpx.Client
) -> None:
    """Issuing several timestamp requests in parallel all return valid tokens."""
    labels = [f"concurrent-doc-{i}" for i in range(5)]

    def stamp(label: str) -> dict:
        r = httpx.post(
            f"{GATEWAY_URL}/api/timestamp",
            json={"document_hash": _sha256(label)},
            timeout=30,
        )
        assert r.status_code == 200, f"Failed for {label!r}: {r.text}"
        return r.json()

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(stamp, label): label for label in labels}
        tokens = {label: f.result() for f, label in
                  ((f, futures[f]) for f in as_completed(futures))}

    serials = [t["serial_number"] for t in tokens.values()]
    assert len(set(serials)) == len(serials), "Concurrent tokens share serial numbers"

    for label, token in tokens.items():
        r = gateway.post(
            "/api/verify",
            json={"document_hash": _sha256(label), "token": token},
        )
        assert r.status_code == 200
        assert r.json()["valid"] is True


# ---------------------------------------------------------------------------
# Frontend / static assets
# ---------------------------------------------------------------------------


def test_frontend_is_served() -> None:
    """GET / returns the HTML frontend."""
    r = httpx.get(f"{GATEWAY_URL}/", timeout=10, follow_redirects=True)
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


def test_static_index_html_is_served() -> None:
    """GET /static/index.html is directly accessible."""
    r = httpx.get(f"{GATEWAY_URL}/static/index.html", timeout=10)
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
