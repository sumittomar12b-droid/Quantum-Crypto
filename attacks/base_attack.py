"""
Base Attack Simulation Framework.
Provides trial execution, statistical evaluation, and benchmark harness for all 10 attacks.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
import time
from typing import Any, Dict, List, Optional
import numpy as np


@dataclass
class AttackEvaluationResult:
    attack_name: str
    attack_id: str
    total_trials: int
    successful_detections: int
    false_positives: int
    detection_rate: float
    false_positive_rate: float
    passed_success_criterion: bool
    summary: str
    metrics: Dict[str, Any]


class BaseAttack(ABC):
    """Abstract Base Class for Adversary Injection Scenarios."""

    def __init__(self, attack_id: str, attack_name: str):
        self.attack_id = attack_id
        self.attack_name = attack_name

    @abstractmethod
    def execute_single_attack(
        self,
        L: int,
        noise: float,
        rng: np.random.Generator
    ) -> bool:
        """
        Executes one attack trial.
        Returns: True if the detector successfully caught and mitigated the attack, False otherwise.
        """
        pass

    @abstractmethod
    def execute_single_honest(
        self,
        L: int,
        noise: float,
        rng: np.random.Generator
    ) -> bool:
        """
        Executes one honest trial.
        Returns: True if the detector wrongly flagged an honest session (False Positive), False otherwise.
        """
        pass

    def run_benchmark(
        self,
        L: int = 200,
        noise: float = 0.05,
        n_trials: int = 1000,
        seed: int = 42
    ) -> AttackEvaluationResult:
        """
        Executes n_trials of attack and honest scenarios to compute detection and false positive rates.
        """
        rng = np.random.default_rng(seed)
        detections = 0
        false_positives = 0

        t0 = time.perf_counter()

        # Run attack trials
        for _ in range(n_trials):
            caught = self.execute_single_attack(L, noise, rng)
            if caught:
                detections += 1

        # Run honest baseline trials for false alert measurement
        for _ in range(n_trials):
            false_alert = self.execute_single_honest(L, noise, rng)
            if false_alert:
                false_positives += 1

        t1 = time.perf_counter()
        elapsed_total = (t1 - t0) * 1000.0  # ms
        avg_latency_ms = elapsed_total / (2 * n_trials)

        detection_rate = float(detections / n_trials)
        false_positive_rate = float(false_positives / n_trials)

        # Success criteria: Detection rate >= 95% and False Positive rate <= 5%
        passed = (detection_rate >= 0.95) and (false_positive_rate <= 0.05)

        summary = (
            f"[{self.attack_id}] {self.attack_name}: "
            f"Detection Rate = {detection_rate * 100:.2f}%, "
            f"False Positive Rate = {false_positive_rate * 100:.2f}% "
            f"({'PASSED' if passed else 'FAILED'})"
        )

        return AttackEvaluationResult(
            attack_name=self.attack_name,
            attack_id=self.attack_id,
            total_trials=n_trials,
            successful_detections=detections,
            false_positives=false_positives,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            passed_success_criterion=passed,
            summary=summary,
            metrics={
                "avg_latency_ms": avg_latency_ms,
                "L": L,
                "noise": noise,
                "seed": seed
            }
        )
