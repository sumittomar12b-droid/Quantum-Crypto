"""
Attack 8: Intercept-Resend Eavesdropping Simulation.
Eve measures quantum states in a randomly chosen basis and re-prepares them.
Due to quantum no-cloning, this introduces an expected 25% basis disagreement rate.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from detection.correlation_checker import CorrelationChecker


class InterceptResendAttack(BaseAttack):
    def __init__(self, eve_measurement_rate: float = 1.0):
        super().__init__(attack_id="ATTACK-08", attack_name="Intercept-Resend Eavesdropping")
        self.eve_measurement_rate = eve_measurement_rate

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # Under full intercept-resend, basis mismatch probability is 25%
        disagreement_prob = 0.25 * self.eve_measurement_rate
        disagreements = int(rng.binomial(L, disagreement_prob))

        result = CorrelationChecker.evaluate_channel_correlations(
            bell_pairs=[],
            basis_disagreement_count=disagreements,
            total_basis_tests=L,
            basis_disagreement_threshold=0.15
        )
        return result.intercept_resend_detected

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # Honest channel baseline disagreement (due to small channel noise ~ 2%)
        disagreements = int(rng.binomial(L, 0.02))

        result = CorrelationChecker.evaluate_channel_correlations(
            bell_pairs=[],
            basis_disagreement_count=disagreements,
            total_basis_tests=L,
            basis_disagreement_threshold=0.15
        )
        return result.intercept_resend_detected
