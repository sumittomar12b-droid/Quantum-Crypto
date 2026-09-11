"""
Tamper-Evident SHA3-256 Hash-Chained Audit Logging System.
Provides immutable JSONL event records for forensic analysis and compliance.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from typing import Any, Dict, List, Optional


class AuditEventType(str, Enum):
    SESSION_CREATED = "SESSION_CREATED"
    SIGNATURE_GENERATED = "SIGNATURE_GENERATED"
    BELL_DISTRIBUTED = "BELL_DISTRIBUTED"
    TELEPORTATION_EXECUTED = "TELEPORTATION_EXECUTED"
    VERIFICATION_ATTEMPTED = "VERIFICATION_ATTEMPTED"
    VERIFICATION_ACCEPTED = "VERIFICATION_ACCEPTED"
    VERIFICATION_REJECTED = "VERIFICATION_REJECTED"
    ATTACK_DETECTED = "ATTACK_DETECTED"
    RESOURCE_CONSUMED = "RESOURCE_CONSUMED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    REPLAY_BLOCKED = "REPLAY_BLOCKED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    QBER_ALERT = "QBER_ALERT"
    BELL_DISRUPTION_ALERT = "BELL_DISRUPTION_ALERT"


@dataclass
class AuditEvent:
    sequence_number: int
    timestamp: str
    event_type: AuditEventType
    session_id: str
    actor: str
    details: Dict[str, Any]
    prev_hash: str
    event_hash: str = ""


class AuditLogger:
    """Manages append-only, cryptographic hash-chained audit trails."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_filepath: Optional[str] = None):
        self.log_filepath = log_filepath
        self.events: List[AuditEvent] = []
        self._last_hash = self.GENESIS_HASH
        self._seq = 0

        if log_filepath and os.path.exists(log_filepath):
            self._load_and_verify_log(log_filepath)

    def _compute_hash(self, prev_hash: str, payload_dict: Dict[str, Any]) -> str:
        serialized = json.dumps(payload_dict, sort_keys=True)
        raw_str = f"{prev_hash}:{serialized}"
        return hashlib.sha3_256(raw_str.encode("utf-8")).hexdigest()

    def log_event(
        self,
        event_type: AuditEventType,
        session_id: str,
        actor: str,
        details: Dict[str, Any]
    ) -> AuditEvent:
        """Appends and cryptographically binds a new audit event."""
        self._seq += 1
        now = datetime.now(timezone.utc).isoformat()

        payload = {
            "sequence_number": self._seq,
            "timestamp": now,
            "event_type": event_type.value,
            "session_id": session_id,
            "actor": actor,
            "details": details
        }

        current_hash = self._compute_hash(self._last_hash, payload)

        event = AuditEvent(
            sequence_number=self._seq,
            timestamp=now,
            event_type=event_type,
            session_id=session_id,
            actor=actor,
            details=details,
            prev_hash=self._last_hash,
            event_hash=current_hash
        )

        self._last_hash = current_hash
        self.events.append(event)

        if self.log_filepath:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_filepath)), exist_ok=True)
            with open(self.log_filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")

        return event

    def _load_and_verify_log(self, filepath: str) -> None:
        """Loads and verifies existing log file on startup."""
        self.events = []
        self._last_hash = self.GENESIS_HASH
        self._seq = 0

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                event = AuditEvent(
                    sequence_number=data["sequence_number"],
                    timestamp=data["timestamp"],
                    event_type=AuditEventType(data["event_type"]),
                    session_id=data["session_id"],
                    actor=data["actor"],
                    details=data["details"],
                    prev_hash=data["prev_hash"],
                    event_hash=data["event_hash"]
                )
                self.events.append(event)
                self._last_hash = event.event_hash
                self._seq = event.sequence_number

        self.verify_chain_integrity()

    def verify_chain_integrity(self) -> bool:
        """Verifies full hash chain validity from genesis to the latest entry."""
        current_prev = self.GENESIS_HASH
        for event in self.events:
            if event.prev_hash != current_prev:
                return False

            payload = {
                "sequence_number": event.sequence_number,
                "timestamp": event.timestamp,
                "event_type": event.event_type.value,
                "session_id": event.session_id,
                "actor": event.actor,
                "details": event.details
            }
            expected_hash = self._compute_hash(event.prev_hash, payload)
            if event.event_hash != expected_hash:
                return False

            current_prev = event.event_hash

        return True
