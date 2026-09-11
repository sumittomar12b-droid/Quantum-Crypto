"""
Comprehensive Attack Simulation and Adversary Injection Suite.
10 Quantum and Classical Attack Scenarios testing Layer 3 Non-AI Detectors.
"""

from .base_attack import BaseAttack, AttackEvaluationResult
from .random_forger import RandomForgerAttack
from .informed_forger import InformedForgerAttack
from .impersonator import SignerImpersonationAttack
from .replay_attacker import ReplayAttack
from .unauthorized_verifier import UnauthorizedVerifierAttack
from .pauli_tamperer import PauliTamperingAttack
from .channel_disturbance import ChannelDisturbanceAttack
from .intercept_resend import InterceptResendAttack
from .entanglement_disruptor import EntanglementDisruptionAttack
from .dos_simulator import DoSSimulatorAttack

__all__ = [
    "BaseAttack",
    "AttackEvaluationResult",
    "RandomForgerAttack",
    "InformedForgerAttack",
    "SignerImpersonationAttack",
    "ReplayAttack",
    "UnauthorizedVerifierAttack",
    "PauliTamperingAttack",
    "ChannelDisturbanceAttack",
    "InterceptResendAttack",
    "EntanglementDisruptionAttack",
    "DoSSimulatorAttack",
]
