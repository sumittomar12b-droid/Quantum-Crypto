"""
Exact Binomial Threat Model and Statistical Security Bounds Engine.
Computes P_forge, P_false_reject, and optimal acceptance threshold t*(L, q_honest, q_adv).
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple
import numpy as np
from scipy.stats import binom


@dataclass
class ThreatModelMetrics:
    signature_length_L: int
    threshold_t: int
    q_honest: float
    q_adv: float
    p_forge: float
    p_false_reject: float
    p_false_accept: float
    security_parameter_bits: float  # -log2(P_forge)


class BinomialThreatEngine:
    """Exact statistical threat computation without machine learning or heuristics."""

    @classmethod
    def compute_p_forge(cls, L: int, t: int, q_adv: float = 0.35) -> float:
        """
        Computes probability that an adversary with error rate q_adv produces <= t mismatches:
        P_forge = sum_{k=0}^{t} C(L, k) * (q_adv)^k * (1 - q_adv)^(L - k)
        """
        if t < 0:
            return 0.0
        if t >= L:
            return 1.0
        return float(binom.cdf(t, L, q_adv))

    @classmethod
    def compute_p_false_reject(cls, L: int, t: int, q_honest: float = 0.05) -> float:
        """
        Computes probability that an honest signer with noise q_honest exceeds threshold t:
        P_false_reject = 1 - sum_{k=0}^{t} C(L, k) * (q_honest)^k * (1 - q_honest)^(L - k)
        """
        if t < 0:
            return 1.0
        if t >= L:
            return 0.0
        return float(binom.sf(t, L, q_honest))

    @classmethod
    def evaluate_security_parameters(
        cls,
        L: int,
        t: int,
        q_honest: float = 0.05,
        q_adv: float = 0.35
    ) -> ThreatModelMetrics:
        p_forge = cls.compute_p_forge(L, t, q_adv)
        p_false_reject = cls.compute_p_false_reject(L, t, q_honest)

        # Security bits = -log2(P_forge)
        if p_forge > 0:
            sec_bits = -float(np.log2(p_forge))
        else:
            sec_bits = float("inf")

        return ThreatModelMetrics(
            signature_length_L=L,
            threshold_t=t,
            q_honest=q_honest,
            q_adv=q_adv,
            p_forge=p_forge,
            p_false_reject=p_false_reject,
            p_false_accept=p_forge,
            security_parameter_bits=sec_bits
        )

    @classmethod
    def find_optimal_threshold(
        cls,
        L: int,
        q_honest: float = 0.05,
        q_adv: float = 0.35,
        target_p_forge: float = 1e-6,
        max_p_false_reject: float = 0.01
    ) -> Tuple[int, ThreatModelMetrics]:
        """
        Finds optimal integer threshold t that satisfies both P_forge <= target and P_false_reject <= max.
        If both cannot be satisfied simultaneously, chooses t that minimizes (P_forge + P_false_reject).
        """
        best_t = int(L * (q_honest + q_adv) / 2.0)
        best_metrics = cls.evaluate_security_parameters(L, best_t, q_honest, q_adv)
        min_total_error = float("inf")

        for candidate_t in range(0, L + 1):
            metrics = cls.evaluate_security_parameters(L, candidate_t, q_honest, q_adv)
            
            # Check ideal constraint
            if metrics.p_forge <= target_p_forge and metrics.p_false_reject <= max_p_false_reject:
                return candidate_t, metrics

            total_err = metrics.p_forge + metrics.p_false_reject
            if total_err < min_total_error:
                min_total_error = total_err
                best_t = candidate_t
                best_metrics = metrics

        return best_t, best_metrics

    @classmethod
    def generate_parameter_curves(
        cls,
        L_values: List[int],
        q_adv_values: List[float],
        q_honest: float = 0.05
    ) -> Dict[str, Any]:
        """Generates scaling curves of P_forge vs L for various adversarial error rates."""
        results: Dict[str, Any] = {}
        for q_adv in q_adv_values:
            curve_data = []
            for L in L_values:
                # Use threshold t = 0.15 * L
                t = int(L * 0.15)
                p_forge = cls.compute_p_forge(L, t, q_adv)
                p_fr = cls.compute_p_false_reject(L, t, q_honest)
                curve_data.append({
                    "L": L,
                    "t": t,
                    "p_forge": p_forge,
                    "p_false_reject": p_fr
                })
            results[f"q_adv_{q_adv}"] = curve_data
        return results
