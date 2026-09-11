"""
Quantum Digital Signature Verification and Transferability Checking.
Performs projective measurements, counts mismatches, and evaluates transferability across verifiers.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import numpy as np

from .state_preparation import PauliBasis, PauliEigenstate, StatePreparation
from .signature_generation import QuantumSignature


@dataclass
class VerificationOutcome:
    verifier_id: str
    signature_id: str
    total_elements: int
    mismatch_count: int
    mismatch_rate: float
    threshold_t: int
    accepted: bool
    measured_outcomes: List[int]
    match_flags: List[bool]
    p_forge_bound: float = 0.0
    p_false_reject_bound: float = 0.0
    transferable: Optional[bool] = None
    reason: str = ""


class QDSSignatureVerifier:
    """Performs signature verification via projective measurement and threshold testing."""

    @classmethod
    def verify_teleported_signature(
        cls,
        verifier_id: str,
        received_statevectors: List[np.ndarray],
        expected_signature: QuantumSignature,
        threshold_t: int = 30,
        rng: Optional[np.random.Generator] = None
    ) -> VerificationOutcome:
        """
        Verifies received quantum states against expected Pauli basis and bit expectations.
        """
        if rng is None:
            rng = np.random.default_rng()

        L = expected_signature.signature_length
        if len(received_statevectors) != L:
            raise ValueError(f"Statevector count ({len(received_statevectors)}) does not match expected L ({L})")

        measured_outcomes: List[int] = []
        match_flags: List[bool] = []
        mismatches = 0

        for i in range(L):
            target_basis = expected_signature.bases[i]
            expected_bit = expected_signature.bit_values[i]
            received_vec = received_statevectors[i]

            # Projective measurement in expected basis
            bit_outcome, _ = StatePreparation.measure_projective(
                received_vec, target_basis, rng=rng
            )
            measured_outcomes.append(bit_outcome)

            is_match = (bit_outcome == expected_bit)
            match_flags.append(is_match)
            if not is_match:
                mismatches += 1

        accepted = (mismatches <= threshold_t)
        mismatch_rate = float(mismatches / L) if L > 0 else 0.0

        reason = (
            f"Signature accepted: {mismatches} mismatches <= threshold {threshold_t}"
            if accepted
            else f"Signature rejected: {mismatches} mismatches > threshold {threshold_t}"
        )

        return VerificationOutcome(
            verifier_id=verifier_id,
            signature_id=expected_signature.signature_id,
            total_elements=L,
            mismatch_count=mismatches,
            mismatch_rate=mismatch_rate,
            threshold_t=threshold_t,
            accepted=accepted,
            measured_outcomes=measured_outcomes,
            match_flags=match_flags,
            reason=reason
        )

    @classmethod
    def verify_transferability(
        cls,
        bob_outcome: VerificationOutcome,
        charlie_outcome: VerificationOutcome,
        delta_threshold: int = 20
    ) -> bool:
        """
        Ensures signature is non-repudiable and transferable from Bob to Charlie.
        Bob and Charlie's mismatch count must not differ by more than Delta.
        """
        diff = abs(bob_outcome.mismatch_count - charlie_outcome.mismatch_count)
        return diff <= delta_threshold
