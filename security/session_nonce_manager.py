"""
Session and Nonce Lifecycle Management with Replay Attack Prevention.
Tracks 3-party session bindings, nonces, and single-use signature resources.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import secrets
from typing import Dict, Optional, Set
import uuid


class SessionState(str, Enum):
    INITIALIZED = "INITIALIZED"
    RESOURCE_DISTRIBUTED = "RESOURCE_DISTRIBUTED"
    TELEPORTATION_COMPLETED = "TELEPORTATION_COMPLETED"
    VERIFIED = "VERIFIED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    BLOCKED_REPLAY = "BLOCKED_REPLAY"
    INVALID = "INVALID"


@dataclass
class SessionBinding:
    session_id: str
    signer_id: str
    recipient_id: str
    message_digest: str
    signature_resource_id: str
    nonce: str
    timestamp: str
    expiry: str
    protocol_version: str = "teleportation-qds-v1.0"
    threshold_policy_version: str = "policy-v1.2"
    ml_kem_ciphertext: str = ""
    state: SessionState = SessionState.INITIALIZED
    consumed_at: Optional[str] = None
    consumed_resources: Set[str] = field(default_factory=set)


class SessionNonceManager:
    """Manages active sessions, prevents replay attacks, and enforces TTL."""

    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl = default_ttl_seconds
        self._sessions: Dict[str, SessionBinding] = {}
        self._consumed_nonces: Set[str] = set()
        self._consumed_resources: Set[str] = set()

    def create_session(
        self,
        signer_id: str,
        recipient_id: str,
        message_digest: str,
        ttl_seconds: Optional[int] = None
    ) -> SessionBinding:
        """Creates and registers a cryptographically bound 3-party session."""
        now = datetime.now(timezone.utc)
        ttl = ttl_seconds or self.default_ttl
        expiry = now + timedelta(seconds=ttl)

        session_id = str(uuid.uuid4())
        resource_id = str(uuid.uuid4())
        nonce = secrets.token_hex(32)  # 256-bit CSPRNG nonce

        binding = SessionBinding(
            session_id=session_id,
            signer_id=signer_id,
            recipient_id=recipient_id,
            message_digest=message_digest,
            signature_resource_id=resource_id,
            nonce=nonce,
            timestamp=now.isoformat(),
            expiry=expiry.isoformat(),
            state=SessionState.INITIALIZED
        )

        self._sessions[session_id] = binding
        return binding

    def get_session(self, session_id: str) -> Optional[SessionBinding]:
        return self._sessions.get(session_id)

    def is_session_valid(self, session_id: str) -> bool:
        """Checks whether session exists, is unconsumed, and within TTL."""
        session = self.get_session(session_id)
        if not session:
            return False

        if session.state in (SessionState.CONSUMED, SessionState.EXPIRED, SessionState.BLOCKED_REPLAY):
            return False

        now = datetime.now(timezone.utc)
        expiry_dt = datetime.fromisoformat(session.expiry)
        if now > expiry_dt:
            session.state = SessionState.EXPIRED
            return False

        return True

    def validate_and_consume(
        self,
        session_id: str,
        nonce: str,
        resource_id: str
    ) -> bool:
        """
        Validates nonce & resource freshness. If valid, consumes both.
        Returns False if replay attack detected.
        """
        # 1. Check if nonce has already been seen
        if nonce in self._consumed_nonces:
            if session_id in self._sessions:
                self._sessions[session_id].state = SessionState.BLOCKED_REPLAY
            return False

        # 2. Check if resource_id has already been consumed
        if resource_id in self._consumed_resources:
            if session_id in self._sessions:
                self._sessions[session_id].state = SessionState.BLOCKED_REPLAY
            return False

        # 3. Check session validity
        session = self.get_session(session_id)
        if not session or not self.is_session_valid(session_id):
            return False

        # 4. Check binding consistency
        if session.nonce != nonce or session.signature_resource_id != resource_id:
            session.state = SessionState.INVALID
            return False

        # 5. Successfully consume
        self._consumed_nonces.add(nonce)
        self._consumed_resources.add(resource_id)
        session.consumed_resources.add(resource_id)
        session.state = SessionState.CONSUMED
        session.consumed_at = datetime.now(timezone.utc).isoformat()
        return True
