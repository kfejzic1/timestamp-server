"""Shared fixtures for end-to-end tests."""
from __future__ import annotations

import time

import httpx
import pytest

GATEWAY_URL = "http://localhost:8000"
_POLL_INTERVAL = 2.0


def _poll(condition, *, timeout: int, label: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if condition():
                return
        except Exception:
            pass
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"Timed out waiting for: {label}")


@pytest.fixture(scope="session")
def gateway() -> httpx.Client:
    """Return an httpx.Client pointed at the gateway, waiting until it is up."""
    _poll(
        lambda: httpx.get(f"{GATEWAY_URL}/api/status", timeout=5).status_code == 200,
        timeout=120,
        label="gateway to become reachable",
    )
    with httpx.Client(base_url=GATEWAY_URL, timeout=30) as client:
        yield client


@pytest.fixture(scope="session")
def cluster_ready(gateway: httpx.Client) -> None:
    """Wait for all signers to register, trigger DKG, and wait for it to complete."""

    def all_registered() -> bool:
        status = gateway.get("/api/status").json()
        return status["registered_signers"] >= status["expected_signers"]

    _poll(all_registered, timeout=120, label="all signers to register")

    status = gateway.get("/api/status").json()
    if not status["dkg_complete"]:
        resp = gateway.post("/api/dkg/start")
        assert resp.status_code == 200, f"DKG start failed: {resp.text}"

    _poll(
        lambda: gateway.get("/api/status").json()["dkg_complete"],
        timeout=120,
        label="DKG to complete",
    )
