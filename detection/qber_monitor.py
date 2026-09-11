"""
Quantum Bit Error Rate (QBER) Monitoring and Wilson Score Confidence Interval Engine.
Provides rigorous statistical boundaries to detect channel tampering and MITM attacks.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import numpy as np
from scipy.stats import norm


@dataclass
class QBERAssessment:
    sample_qber: float
    total_samples: int
    error_count: int
    confidence_level: float
    wilson_lower_bound: float
    wilson_upper_bound: float
    threshold_epsilon_max: float
    quarantine_alert: bool
    status_summary: str


class QBERMonitor:
    """Computes sample QBER and Wilson score upper confidence bounds."""

    @staticmethod
    def compute_wilson_interval(
        error_count: int,
        total_samples: int,
        confidence: float = 0.99
    ) -> tuple[float, float]:
        """
        Calculates the Wilson score confidence interval:
        (p_hat + z^2/(2n) +- z * sqrt(p_hat*(1-p_hat)/n + z^2/(4n^2))) / (1 + z^2/n)
        """
        if total_samples <= 0:
            return 0.0, 1.0

        p_hat = error_count / total_samples
        alpha = 1.0 - confidence
        z = float(norm.ppf(1.0 - alpha / 2.0))
        z2 = z ** 2
        n = total_samples

        denominator = 1.0 + z2 / n
        center = p_hat + z2 / (2.0 * n)
        margin = z * np.sqrt((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * (n ** 2))))

        lower = max(0.0, (center - margin) / denominator)
        upper = min(1.0, (center + margin) / denominator)

        return float(lower), float(upper)

    @classmethod
    def evaluate_qber(
        cls,
        error_count: int,
        total_samples: int,
        threshold_epsilon_max: float = 0.11,
        confidence: float = 0.99
    ) -> QBERAssessment:
        """
        Assesses QBER against threshold epsilon_max.
        Triggers quarantine alert if the 99% upper confidence bound exceeds epsilon_max.
        """
        if total_samples <= 0:
            sample_qber = 0.0
            lower, upper = 0.0, 1.0
        else:
            sample_qber = float(error_count / total_samples)
            lower, upper = cls.compute_wilson_interval(error_count, total_samples, confidence)

        quarantine = (upper > threshold_epsilon_max)

        if quarantine:
            status = (
                f"CHANNEL QUARANTINE: QBER 99% UCB ({upper:.4f}) exceeds threshold ({threshold_epsilon_max:.4f}). "
                f"Sample QBER = {sample_qber:.4f} ({error_count}/{total_samples})."
            )
        else:
            status = (
                f"CHANNEL HEALTHY: QBER 99% UCB ({upper:.4f}) <= threshold ({threshold_epsilon_max:.4f}). "
                f"Sample QBER = {sample_qber:.4f} ({error_count}/{total_samples})."
            )

        return QBERAssessment(
            sample_qber=sample_qber,
            total_samples=total_samples,
            error_count=error_count,
            confidence_level=confidence,
            wilson_lower_bound=lower,
            wilson_upper_bound=upper,
            threshold_epsilon_max=threshold_epsilon_max,
            quarantine_alert=quarantine,
            status_summary=status
        )
