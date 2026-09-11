"""
Pauli Correction Consistency Checker.
Validates received classical teleportation syndromes (m1, m2) against Alice's encrypted transcript.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class PauliVerificationResult:
    total_checks: int
    inconsistencies: int
    is_valid: bool
    tampered_indices: List[int]
    summary: str


class PauliConsistencyChecker:
    """Verifies that applied Pauli corrections match authentic Bell measurement outcomes."""

    @classmethod
    def verify_corrections(
        cls,
        alice_measured_syndromes: List[Tuple[int, int]],
        bob_applied_syndromes: List[Tuple[int, int]]
    ) -> PauliVerificationResult:
        """
        Detects tampering in the classical teleportation bits (m1, m2).
        """
        if len(alice_measured_syndromes) != len(bob_applied_syndromes):
            return PauliVerificationResult(
                total_checks=len(bob_applied_syndromes),
                inconsistencies=len(bob_applied_syndromes),
                is_valid=False,
                tampered_indices=list(range(len(bob_applied_syndromes))),
                summary=f"Syndrome length mismatch: Alice ({len(alice_measured_syndromes)}) vs Bob ({len(bob_applied_syndromes)})"
            )

        tampered_indices = []
        for idx, (alice_bits, bob_bits) in enumerate(zip(alice_measured_syndromes, bob_applied_syndromes)):
            if alice_bits != bob_bits:
                tampered_indices.append(idx)

        inconsistencies = len(tampered_indices)
        is_valid = (inconsistencies == 0)

        if is_valid:
            summary = f"PAULI CONSISTENCY VERIFIED: All {len(bob_applied_syndromes)} syndrome pairs match exactly."
        else:
            summary = (
                f"PAULI TAMPERING DETECTED: {inconsistencies}/{len(bob_applied_syndromes)} syndromes tampered. "
                f"Indices: {tampered_indices[:10]}"
            )

        return PauliVerificationResult(
            total_checks=len(bob_applied_syndromes),
            inconsistencies=inconsistencies,
            is_valid=is_valid,
            tampered_indices=tampered_indices,
            summary=summary
        )
