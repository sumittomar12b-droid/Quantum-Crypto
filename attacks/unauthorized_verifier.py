"""
Attack 5: Unauthorized Verification Attempt.
Unregistered recipient or unauthorized role attempts to invoke signature verification.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from security.identity_policy import IdentityPolicyEngine, UserRole


class UnauthorizedVerifierAttack(BaseAttack):
    def __init__(self):
        super().__init__(attack_id="ATTACK-05", attack_name="Unauthorized Verification")

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        policy_engine = IdentityPolicyEngine()
        unauthorized_actor = "EVE_SNOOPER"

        can_verify = policy_engine.can_verify(unauthorized_actor)
        # Blocked if role check returns False
        return not can_verify

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        policy_engine = IdentityPolicyEngine()
        authorized_verifier = "BOB"

        can_verify = policy_engine.can_verify(authorized_verifier)
        # False alert if Bob is denied verification permission
        return not can_verify
