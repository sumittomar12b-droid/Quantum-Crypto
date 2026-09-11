"""
Attack 4: Replay Attack Simulation.
Attacker captures a valid session transcript and re-submits old nonce and resource ID.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from security.session_nonce_manager import SessionNonceManager


class ReplayAttack(BaseAttack):
    def __init__(self):
        super().__init__(attack_id="ATTACK-04", attack_name="Session & Transcript Replay")

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        manager = SessionNonceManager()

        # Legitimate initial session
        session = manager.create_session(
            signer_id="ALICE",
            recipient_id="BOB",
            message_digest="valid_digest"
        )
        nonce = session.nonce
        resource_id = session.signature_resource_id
        session_id = session.session_id

        # First consumption by Bob (Legitimate)
        consumed_first = manager.validate_and_consume(session_id, nonce, resource_id)
        if not consumed_first:
            return False

        # Attacker replays exact same session, nonce, and resource ID
        replayed_success = manager.validate_and_consume(session_id, nonce, resource_id)

        # Attack successfully mitigated if second consumption fails
        return not replayed_success

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        manager = SessionNonceManager()

        session = manager.create_session(
            signer_id="ALICE",
            recipient_id="BOB",
            message_digest="fresh_digest"
        )
        nonce = session.nonce
        resource_id = session.signature_resource_id
        session_id = session.session_id

        # Honest one-time consumption
        consumed = manager.validate_and_consume(session_id, nonce, resource_id)
        # False alert if honest session was rejected
        return not consumed
