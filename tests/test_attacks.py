"""
Automated Test Runner for All 10 Adversary Injection Scenarios (Layer 4 & Deliverable D6).
Verifies that each attack achieves >= 95% Detection Rate and <= 5% False Alert Rate.
"""

import pytest
from attacks.random_forger import RandomForgerAttack
from attacks.informed_forger import InformedForgerAttack
from attacks.impersonator import SignerImpersonationAttack
from attacks.replay_attacker import ReplayAttack
from attacks.unauthorized_verifier import UnauthorizedVerifierAttack
from attacks.pauli_tamperer import PauliTamperingAttack
from attacks.channel_disturbance import ChannelDisturbanceAttack
from attacks.intercept_resend import InterceptResendAttack
from attacks.entanglement_disruptor import EntanglementDisruptionAttack
from attacks.dos_simulator import DoSSimulatorAttack


@pytest.mark.parametrize("attack_cls", [
    RandomForgerAttack,
    InformedForgerAttack,
    SignerImpersonationAttack,
    ReplayAttack,
    UnauthorizedVerifierAttack,
    PauliTamperingAttack,
    ChannelDisturbanceAttack,
    InterceptResendAttack,
    EntanglementDisruptionAttack,
    DoSSimulatorAttack,
])
def test_individual_attack_mitigation(attack_cls):
    """Verifies that each attack scenario satisfies the >= 95% detection and <= 5% false positive criteria."""
    attack_instance = attack_cls()
    result = attack_instance.run_benchmark(L=200, noise=0.05, n_trials=200, seed=42)

    assert result.detection_rate >= 0.95, (
        f"Attack '{result.attack_name}' failed detection threshold: {result.detection_rate*100:.2f}% < 95%"
    )
    assert result.false_positive_rate <= 0.05, (
        f"Attack '{result.attack_name}' exceeded false alert threshold: {result.false_positive_rate*100:.2f}% > 5%"
    )
    assert result.passed_success_criterion is True
