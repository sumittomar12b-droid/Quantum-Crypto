"""
Attack 10: Denial of Service (DoS) and Request Flooding Simulation.
Adversary floods verification endpoints or delays responses, exceeding rate limits.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from detection.threshold_evaluator import ThresholdEvaluator


class DoSSimulatorAttack(BaseAttack):
    def __init__(self, flood_rpm: int = 250, honest_rpm: int = 40):
        super().__init__(attack_id="ATTACK-10", attack_name="Denial of Service (DoS) Flood")
        self.flood_rpm = flood_rpm
        self.honest_rpm = honest_rpm

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # High-frequency burst
        burst_rpm = int(rng.normal(self.flood_rpm, 20))
        simulated_latency = float(rng.uniform(1600.0, 3000.0))

        threat = ThresholdEvaluator.evaluate_dos_activity(
            requests_per_minute=burst_rpm,
            latency_ms=simulated_latency,
            max_rpm=120,
            max_latency_ms=1500.0
        )
        return threat.detected

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # Normal operational throughput
        normal_rpm = int(rng.normal(self.honest_rpm, 10))
        simulated_latency = float(rng.uniform(20.0, 150.0))

        threat = ThresholdEvaluator.evaluate_dos_activity(
            requests_per_minute=normal_rpm,
            latency_ms=simulated_latency,
            max_rpm=120,
            max_latency_ms=1500.0
        )
        return threat.detected
