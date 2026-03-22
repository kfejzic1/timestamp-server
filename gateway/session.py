from __future__ import annotations

import time
import threading
from typing import Optional

from models import SigningSession, SessionState

SESSION_TTL_SECONDS = 30.0


class SessionStore:
    """In-memory signing session store with expiration."""

    def __init__(self) -> None:
        self._sessions: dict[str, SigningSession] = {}
        self._timestamps: dict[str, float] = {}
        self._lock = threading.Lock()

    def create(self, session_id: str, document_hash: str, timestamp: str,
               serial_number: str, canonical_message: str,
               selected_signers: list[int]) -> SigningSession:
        session = SigningSession(
            session_id=session_id,
            state=SessionState.CREATED,
            document_hash=document_hash,
            timestamp=timestamp,
            serial_number=serial_number,
            canonical_message=canonical_message,
            selected_signers=selected_signers,
        )
        with self._lock:
            self._sessions[session_id] = session
            self._timestamps[session_id] = time.time()
        return session

    def get(self, session_id: str) -> Optional[SigningSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            created = self._timestamps.get(session_id, 0)
            if time.time() - created > SESSION_TTL_SECONDS:
                session.state = SessionState.FAILED
                session.error = "session expired"
            return session

    def transition(self, session_id: str, new_state: SessionState) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.state = new_state
            return True

    def update(self, session_id: str, **kwargs) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            for key, value in kwargs.items():
                setattr(session, key, value)
            return True

    def cleanup_expired(self) -> int:
        now = time.time()
        removed = 0
        with self._lock:
            expired = [
                sid for sid, ts in self._timestamps.items()
                if now - ts > SESSION_TTL_SECONDS * 3
            ]
            for sid in expired:
                del self._sessions[sid]
                del self._timestamps[sid]
                removed += 1
        return removed
