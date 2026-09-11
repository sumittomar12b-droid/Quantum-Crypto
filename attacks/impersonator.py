"""
Attack 3: Signer Impersonation Simulation.
Mallory attempts to initiate a quantum signing session without authenticated credentials.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from security.identity_policy import IdentityPolicyEngine, UserRole
from security.session_nonce_manager import SessionNonceManager


class SignerImpersonationAttack(BaseAttack):
    def __init__(self):
        super().__init__(attack_id="ATTACK-03", attack_name="Signer Impersonation")

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        policy_engine = IdentityPolicyEngine()
        manager = SessionNonceManager()

        attacker_identity = "MALLORY"  # Not registered as SIGNER
        can_sign = policy_engine.can_sign(attacker_identity)

        if not can_sign:
            # Policy engine blocks before quantum stage
            return True

        # If it reached here, attempt session creation
        session = manager.create_session(
            signer_id=attacker_identity,
            recipient_id="BOB",
            message_digest="fake_digest"
        )
        return False

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        policy_engine = IdentityPolicyEngine()
        manager = SessionNonceManager()

        honest_identity = "ALICE"
        can_sign = policy_engine.can_sign(honest_identity)

        if not can_sign:
            # False positive: Alice was wrongly denied
            return True

        session = manager.create_session(
            signer_id=honest_identity,
            recipient_id="BOB",
            message_digest="valid_digest"
        )
        # False alert if session creation failed
        return not manager.is_session_valid(session.session_id)
