"""
Bell State Correlation and Intercept-Resend Basis Disagreement Detection.
Validates entanglement fidelity and detects active measurement disturbances.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import numpy as np

from protocol.bell_pair_generation import BellPair, BellPairType, BellPairGenerator
from protocol.state_preparation import StatePreparation


@dataclass
class BellCorrelationResult:
    measured_fidelity: float
    fidelity_threshold: float
    entanglement_valid: bool
    basis_disagreement_rate: float
    basis_disagreement_threshold: float
    intercept_resend_detected: bool
    summary: str


class CorrelationChecker:
    """Evaluates entanglement fidelity and quantum channel disturbance."""

    @classmethod
    def verify_bell_state_fidelity(
        cls,
        bell_pair: BellPair,
        min_fidelity_threshold: float = 0.85
    ) -> float:
        """
        Computes quantum state fidelity F = |<ideal|actual>|^2.
        """
        ideal_vec = BellPairGenerator.get_ideal_statevector(bell_pair.pair_type)
        fidelity = StatePreparation.calculate_overlap(ideal_vec, bell_pair.statevector)
        return fidelity

    @classmethod
    def evaluate_channel_correlations(
        cls,
        bell_pairs: List[BellPair],
        basis_disagreement_count: int,
        total_basis_tests: int,
        min_fidelity_threshold: float = 0.85,
        basis_disagreement_threshold: float = 0.20
    ) -> BellCorrelationResult:
        """
        Performs joint evaluation of Bell fidelity and basis disagreement rate.
        """
        if not bell_pairs:
            avg_fidelity = 1.0
        else:
            fidelities = [cls.verify_bell_state_fidelity(bp, min_fidelity_threshold) for bp in bell_pairs]
            avg_fidelity = float(np.mean(fidelities))

        entanglement_valid = (avg_fidelity >= min_fidelity_threshold)

        if total_basis_tests > 0:
            basis_disagree_rate = float(basis_disagreement_count / total_basis_tests)
        else:
            basis_disagree_rate = 0.0

        intercept_resend = (basis_disagree_rate > basis_disagreement_threshold)

        flags = []
        if not entanglement_valid:
            flags.append(f"ENTANGLEMENT DISRUPTED: Avg Fidelity ({avg_fidelity:.4f}) < {min_fidelity_threshold:.4f}")
        if intercept_resend:
            flags.append(
                f"INTERCEPT-RESEND DETECTED: Basis Disagreement ({basis_disagree_rate:.4f}) > {basis_disagreement_threshold:.4f}"
            )

        summary = " | ".join(flags) if flags else f"CORRELATIONS VALID: Fidelity={avg_fidelity:.4f}, Disagreement={basis_disagree_rate:.4f}"

        return BellCorrelationResult(
            measured_fidelity=avg_fidelity,
            fidelity_threshold=min_fidelity_threshold,
            entanglement_valid=entanglement_valid,
            basis_disagreement_rate=basis_disagree_rate,
            basis_disagreement_threshold=basis_disagreement_threshold,
            intercept_resend_detected=intercept_resend,
            summary=summary
        )
