"""
Attack 7: Quantum Channel Disturbance and MITM Noise Injection.
Adversary injects depolarizing errors into the quantum channel, elevating QBER above threshold.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from detection.qber_monitor import QBERMonitor


class ChannelDisturbanceAttack(BaseAttack):
    def __init__(self, attack_noise: float = 0.25, honest_noise: float = 0.02):
        super().__init__(attack_id="ATTACK-07", attack_name="Channel Disturbance / Noise Injection")
        self.attack_noise = attack_noise
        self.honest_noise = honest_noise

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        errors = int(rng.binomial(L, self.attack_noise))
        assessment = QBERMonitor.evaluate_qber(
            error_count=errors,
            total_samples=L,
            threshold_epsilon_max=0.12,
            confidence=0.99
        )
        return assessment.quarantine_alert

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        errors = int(rng.binomial(L, self.honest_noise))
        assessment = QBERMonitor.evaluate_qber(
            error_count=errors,
            total_samples=L,
            threshold_epsilon_max=0.12,
            confidence=0.99
        )
        return assessment.quarantine_alert
