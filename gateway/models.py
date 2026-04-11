from __future__ import annotations

import struct
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class SessionState(str, Enum):
    CREATED = "created"
    COMMITTING = "committing"
    SIGNING = "signing"
    AGGREGATING = "aggregating"
    COMPLETE = "complete"
    FAILED = "failed"


class TimestampToken(BaseModel):
    version: int = 1
    hash_algorithm: str = "SHA-256"
    document_hash: str
    timestamp: str
    serial_number: str
    ciphersuite: str = "FROST-RISTRETTO255-SHA512"
    verification_key: str
    signature: str
    participants: list[int]
    threshold: int
    max_signers: int


class SigningSession(BaseModel):
    session_id: str
    state: SessionState = SessionState.CREATED
    document_hash: str = ""
    timestamp: str = ""
    serial_number: str = ""
    canonical_message: str = ""
    selected_signers: list[int] = Field(default_factory=list)
    commitments: dict[int, str] = Field(default_factory=dict)
    commitment_list_hex: str = ""
    signature_shares: dict[int, str] = Field(default_factory=dict)
    result: Optional[TimestampToken] = None
    error: Optional[str] = None


class SignerInfo(BaseModel):
    participant_id: int
    callback_url: str
    x25519_pub_key: str
    public_key_share: str = ""


class ClusterStatus(BaseModel):
    phase: str = "initializing"
    registered_signers: int = 0
    expected_signers: int = 0
    dkg_complete: bool = False
    verification_key: str = ""
    threshold: int = 0
    max_signers: int = 0


CIPHERSUITE_ID = 1  # Ristretto255


def build_canonical_message(
    ciphersuite_id: int,
    hash_algo: str,
    doc_hash: bytes,
    timestamp: str,
    serial: str,
) -> bytes:
    """Build the deterministic length-prefixed binary message.

    Must produce byte-identical output to the Go implementation in message.go.
    """
    buf = struct.pack(">H", ciphersuite_id)

    algo_bytes = hash_algo.encode("utf-8")
    buf += struct.pack(">B", len(algo_bytes)) + algo_bytes

    buf += struct.pack(">I", len(doc_hash)) + doc_hash

    ts_bytes = timestamp.encode("utf-8")
    buf += struct.pack(">I", len(ts_bytes)) + ts_bytes

    sr_bytes = serial.encode("utf-8")
    buf += struct.pack(">I", len(sr_bytes)) + sr_bytes

    return buf
