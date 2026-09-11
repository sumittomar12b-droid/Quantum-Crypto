"""
Identity, Role-Based Access Control (RBAC), and Policy Enforcement Engine.
Validates participant credentials and enforces permissions before quantum state processing.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class UserRole(str, Enum):
    SIGNER = "SIGNER"
    VERIFIER = "VERIFIER"
    ARBITRATOR = "ARBITRATOR"
    UNAUTHORIZED = "UNAUTHORIZED"


@dataclass
class RolePolicy:
    role_name: UserRole
    can_sign: bool
    can_verify: bool
    can_arbitrate: bool


class IdentityPolicyEngine:
    """Manages role-based policies and authorizes protocol actions."""

    DEFAULT_POLICIES: Dict[str, RolePolicy] = {
        "ALICE": RolePolicy(UserRole.SIGNER, can_sign=True, can_verify=False, can_arbitrate=False),
        "BOB": RolePolicy(UserRole.VERIFIER, can_sign=False, can_verify=True, can_arbitrate=False),
        "CHARLIE": RolePolicy(UserRole.ARBITRATOR, can_sign=False, can_verify=True, can_arbitrate=True),
    }

    def __init__(self, custom_policies: Optional[Dict[str, RolePolicy]] = None):
        self.policies = custom_policies or self.DEFAULT_POLICIES.copy()

    def get_role(self, identity: str) -> UserRole:
        policy = self.policies.get(identity.upper())
        return policy.role_name if policy else UserRole.UNAUTHORIZED

    def can_sign(self, identity: str) -> bool:
        policy = self.policies.get(identity.upper())
        return bool(policy and policy.can_sign)

    def can_verify(self, identity: str) -> bool:
        policy = self.policies.get(identity.upper())
        return bool(policy and policy.can_verify)

    def can_arbitrate(self, identity: str) -> bool:
        policy = self.policies.get(identity.upper())
        return bool(policy and policy.can_arbitrate)

    def authorize_action(self, identity: str, action: str) -> bool:
        """
        Validates whether identity is authorized for action ('sign', 'verify', 'arbitrate').
        """
        act = action.lower()
        if act == "sign":
            return self.can_sign(identity)
        elif act == "verify":
            return self.can_verify(identity)
        elif act == "arbitrate":
            return self.can_arbitrate(identity)
        return False
