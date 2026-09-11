"""
Attack 9: Entanglement Disruption Simulation.
Attacker substitutes Bell pairs (|Phi+> -> |Phi-> or mixed state), reducing Bell fidelity below threshold.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from protocol.bell_pair_generation import BellPairGenerator, BellPairType
from detection.correlation_checker import CorrelationChecker


class EntanglementDisruptionAttack(BaseAttack):
    def __init__(self, corrupted_fidelity: float = 0.60, honest_fidelity: float = 0.99):
        super().__init__(attack_id="ATTACK-09", attack_name="Entanglement Disruption")
        self.corrupted_fidelity = corrupted_fidelity
        self.honest_fidelity = honest_fidelity

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # Attacker injects degraded or substituted Bell pairs
        test_pairs = BellPairGenerator.generate_session_pairs(
            num_pairs=min(L, 20),
            pair_type=BellPairType.PHI_PLUS,
            fidelity=self.corrupted_fidelity
        )

        result = CorrelationChecker.evaluate_channel_correlations(
            bell_pairs=test_pairs,
            basis_disagreement_count=0,
            total_basis_tests=0,
            min_fidelity_threshold=0.85
        )
        return not result.entanglement_valid

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # Honest high-fidelity Bell pairs
        test_pairs = BellPairGenerator.generate_session_pairs(
            num_pairs=min(L, 20),
            pair_type=BellPairType.PHI_PLUS,
            fidelity=self.honest_fidelity
        )

        result = CorrelationChecker.evaluate_channel_correlations(
            bell_pairs=test_pairs,
            basis_disagreement_count=0,
            total_basis_tests=0,
            min_fidelity_threshold=0.85
        )
        return not result.entanglement_valid
