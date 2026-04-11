from __future__ import annotations

import asyncio
import logging
import random
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from models import (
    CIPHERSUITE_ID,
    ClusterStatus,
    SessionState,
    SignerInfo,
    TimestampToken,
    build_canonical_message,
)
from session import SessionStore

logger = logging.getLogger(__name__)

CERT_DIR = Path("/certs")
REQUEST_TIMEOUT = 15.0


def _build_ssl_context() -> ssl.SSLContext | bool:
    """Build mTLS SSL context for outbound requests to signers/aggregator."""
    try:
        ctx = ssl.create_default_context(cafile=str(CERT_DIR / "ca.crt"))
        ctx.check_hostname = False
        ctx.load_cert_chain(
            certfile=str(CERT_DIR / "gateway.crt"),
            keyfile=str(CERT_DIR / "gateway.key"),
        )
        return ctx
    except Exception:
        logger.warning("mTLS certs not found — using plain HTTP")
        return False


class Orchestrator:
    def __init__(self, threshold: int, max_signers: int, aggregator_url: str) -> None:
        self.threshold = threshold
        self.max_signers = max_signers
        self.aggregator_url = aggregator_url

        self.signers: dict[int, SignerInfo] = {}
        self._next_id = 1
        self.registration_complete = False

        self.dkg_complete = False
        self.verification_key = ""
        self.public_key_shares: list[str] = []

        self.sessions = SessionStore()

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            verify=_build_ssl_context(),
        )

    # ── Registration ──

    def register_signer(self, callback_url: str, x25519_pub_key: str) -> int:
        pid = self._next_id
        self._next_id += 1

        self.signers[pid] = SignerInfo(
            participant_id=pid,
            callback_url=callback_url,
            x25519_pub_key=x25519_pub_key,
        )

        if len(self.signers) >= self.max_signers:
            self.registration_complete = True
            logger.info(
                f"All {self.max_signers} signers registered — ready for DKG"
            )

        return pid

    # ── DKG ──

    async def run_dkg(self) -> dict[str, Any]:
        """Execute the full 3-round DKG protocol."""
        async with self._client() as client:
            peer_keys: dict[int, str] = {
                pid: info.x25519_pub_key for pid, info in self.signers.items()
            }
            peer_keys_payload = {str(k): v for k, v in peer_keys.items()}

            # Round 1: Start — parallel requests
            logger.info("DKG Round 1: collecting round1 data from all signers")

            async def dkg_start(pid: int, info: SignerInfo) -> tuple[int, str]:
                resp = await client.post(
                    f"{info.callback_url}/dkg/start",
                    json={"peer_e2e_keys": peer_keys_payload},
                )
                resp.raise_for_status()
                return pid, resp.json()["round1_data"]

            results = await asyncio.gather(
                *(dkg_start(pid, info) for pid, info in self.signers.items())
            )
            round1_responses = dict(results)
            all_round1 = [round1_responses[pid] for pid in sorted(round1_responses)]

            # Round 2: Continue — parallel requests
            logger.info("DKG Round 2: exchanging encrypted shares")

            async def dkg_continue(pid: int, info: SignerInfo) -> tuple[int, dict[int, str]]:
                resp = await client.post(
                    f"{info.callback_url}/dkg/continue",
                    json={"round1_data_all": all_round1},
                )
                resp.raise_for_status()
                data = resp.json()["round2_data"]
                return pid, {int(k): v for k, v in data.items()}

            results = await asyncio.gather(
                *(dkg_continue(pid, info) for pid, info in self.signers.items())
            )
            all_round2 = dict(results)

            # Route round2 data to recipients
            round2_for: dict[int, dict[int, str]] = {
                pid: {} for pid in self.signers
            }
            for sender_id, recipients in all_round2.items():
                for recipient_id, enc_data in recipients.items():
                    if recipient_id in round2_for:
                        round2_for[recipient_id][sender_id] = enc_data

            # Round 3: Finalize — parallel requests
            logger.info("DKG Round 3: finalizing key shares")

            async def dkg_finalize(pid: int, info: SignerInfo) -> tuple[int, dict]:
                r2_for_me = {str(k): v for k, v in round2_for[pid].items()}
                resp = await client.post(
                    f"{info.callback_url}/dkg/finalize",
                    json={"round2_data_for_me": r2_for_me},
                )
                resp.raise_for_status()
                return pid, resp.json()

            results = await asyncio.gather(
                *(dkg_finalize(pid, info) for pid, info in self.signers.items())
            )

            pub_key_shares: dict[int, str] = {}
            verification_key = ""
            for pid, body in results:
                pub_key_shares[pid] = body["public_key_share"]
                self.signers[pid].public_key_share = body["public_key_share"]
                verification_key = body["verification_key"]

            self.verification_key = verification_key
            self.public_key_shares = [
                pub_key_shares[pid] for pid in sorted(pub_key_shares)
            ]

            # Configure aggregator
            logger.info("Configuring aggregator with FROST parameters")
            resp = await client.post(
                f"{self.aggregator_url}/config",
                json={
                    "verification_key": verification_key,
                    "public_key_shares": self.public_key_shares,
                    "threshold": self.threshold,
                    "max_signers": self.max_signers,
                },
            )
            resp.raise_for_status()

            # Configure each signer's FROST instance — parallel
            logger.info("Configuring FROST signing on each signer")

            async def frost_config(info: SignerInfo) -> None:
                resp = await client.post(
                    f"{info.callback_url}/frost/config",
                    json={
                        "verification_key": verification_key,
                        "public_key_shares": self.public_key_shares,
                    },
                )
                resp.raise_for_status()

            await asyncio.gather(
                *(frost_config(info) for info in self.signers.values())
            )

            self.dkg_complete = True
            logger.info("DKG complete — cluster ready for signing")

            return {
                "verification_key": verification_key,
                "signers": len(self.signers),
            }

    # ── Signing ──

    async def create_timestamp(self, document_hash: str) -> TimestampToken:
        """Full two-round FROST signing session."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        serial = str(uuid.uuid4())

        doc_hash_bytes = bytes.fromhex(document_hash)
        canonical_msg = build_canonical_message(
            CIPHERSUITE_ID, "SHA-256", doc_hash_bytes, timestamp, serial
        )
        canonical_msg_hex = canonical_msg.hex()

        available = list(self.signers.keys())
        selected = sorted(random.sample(available, self.threshold))

        session = self.sessions.create(
            session_id=session_id,
            document_hash=document_hash,
            timestamp=timestamp,
            serial_number=serial,
            canonical_message=canonical_msg_hex,
            selected_signers=selected,
        )

        logger.info(
            f"Signing session {session_id}: signers={selected}, hash={document_hash[:16]}..."
        )

        async with self._client() as client:
            # Round 1: Collect commitments — parallel
            self.sessions.transition(session_id, SessionState.COMMITTING)

            async def get_commitment(pid: int) -> tuple[int, str]:
                info = self.signers[pid]
                resp = await client.post(
                    f"{info.callback_url}/sign/commit",
                    json={"session_id": session_id},
                )
                resp.raise_for_status()
                return pid, resp.json()["commitment"]

            results = await asyncio.gather(
                *(get_commitment(pid) for pid in selected)
            )
            commitments = dict(results)

            self.sessions.update(session_id, commitments=commitments)
            self.sessions.transition(session_id, SessionState.SIGNING)

            # Build sorted commitment list
            sorted_pids = sorted(commitments.keys())
            commitment_entries = []
            for pid in sorted_pids:
                commitment_entries.append(bytes.fromhex(commitments[pid]))

            # CommitmentList wire format: [1 byte: group ID][2 bytes: count LE][entries...]
            count = len(commitment_entries)
            commitment_list_bytes = bytes([CIPHERSUITE_ID]) + count.to_bytes(2, "little")
            for entry in commitment_entries:
                commitment_list_bytes += entry

            commitment_list_hex = commitment_list_bytes.hex()
            self.sessions.update(session_id, commitment_list_hex=commitment_list_hex)

            # Round 2: Collect signature shares — parallel
            async def get_sig_share(pid: int) -> tuple[int, str]:
                info = self.signers[pid]
                resp = await client.post(
                    f"{info.callback_url}/sign/sign",
                    json={
                        "session_id": session_id,
                        "canonical_message": canonical_msg_hex,
                        "commitment_list": commitment_list_hex,
                    },
                )
                resp.raise_for_status()
                return pid, resp.json()["signature_share"]

            results = await asyncio.gather(
                *(get_sig_share(pid) for pid in selected)
            )
            sig_shares = dict(results)

            self.sessions.update(session_id, signature_shares=sig_shares)
            self.sessions.transition(session_id, SessionState.AGGREGATING)

            # Aggregate
            sig_share_list = [sig_shares[pid] for pid in sorted(sig_shares.keys())]
            resp = await client.post(
                f"{self.aggregator_url}/aggregate",
                json={
                    "message": canonical_msg_hex,
                    "signature_shares": sig_share_list,
                    "commitment_list": commitment_list_hex,
                },
            )
            resp.raise_for_status()
            signature_hex = resp.json()["signature"]

            self.sessions.transition(session_id, SessionState.COMPLETE)

            token = TimestampToken(
                document_hash=document_hash,
                timestamp=timestamp,
                serial_number=serial,
                verification_key=self.verification_key,
                signature=signature_hex,
                participants=selected,
                threshold=self.threshold,
                max_signers=self.max_signers,
            )

            self.sessions.update(session_id, result=token)
            logger.info(f"Timestamp token issued for session {session_id}")
            return token

    # ── Verification ──

    async def verify_token(
        self, document_hash: str, token: TimestampToken
    ) -> dict[str, Any]:
        doc_hash_bytes = bytes.fromhex(document_hash)
        canonical_msg = build_canonical_message(
            CIPHERSUITE_ID,
            token.hash_algorithm,
            doc_hash_bytes,
            token.timestamp,
            token.serial_number,
        )

        async with self._client() as client:
            resp = await client.post(
                f"{self.aggregator_url}/verify",
                json={
                    "message": canonical_msg.hex(),
                    "signature": token.signature,
                },
            )
            resp.raise_for_status()
            result = resp.json()

        return {
            "valid": result["valid"],
            "detail": result.get("detail", ""),
            "document_hash": document_hash,
            "timestamp": token.timestamp,
        }

    # ── Status ──

    def get_status(self) -> ClusterStatus:
        return ClusterStatus(
            phase="ready" if self.dkg_complete else (
                "dkg_pending" if self.registration_complete else "registering"
            ),
            registered_signers=len(self.signers),
            expected_signers=self.max_signers,
            dkg_complete=self.dkg_complete,
            verification_key=self.verification_key,
            threshold=self.threshold,
            max_signers=self.max_signers,
        )
