"""
Single-qubit Pauli Eigenstate Preparation and Measurement for QDS.
Supports Computational (Z), Hadamard (X), and Circular/Phase (Y) bases.
"""

from __future__ import annotations
from enum import Enum
from typing import Tuple
import numpy as np


class PauliBasis(str, Enum):
    Z = "Z"  # Computational basis: {|0>, |1>}
    X = "X"  # Diagonal/Hadamard basis: {|+>, |->}
    Y = "Y"  # Circular/Phase basis: {|i+>, |i->}


class PauliEigenstate(str, Enum):
    ZERO = "|0>"
    ONE = "|1>"
    PLUS = "|+>"
    MINUS = "|->"
    PLUS_I = "|i+>"
    MINUS_I = "|i->"

    @property
    def basis(self) -> PauliBasis:
        if self in (PauliEigenstate.ZERO, PauliEigenstate.ONE):
            return PauliBasis.Z
        elif self in (PauliEigenstate.PLUS, PauliEigenstate.MINUS):
            return PauliBasis.X
        else:
            return PauliBasis.Y

    @property
    def eigenvalue(self) -> int:
        """Returns +1 for positive eigenstate, -1 for negative eigenstate."""
        if self in (PauliEigenstate.ZERO, PauliEigenstate.PLUS, PauliEigenstate.PLUS_I):
            return 1
        return -1

    @property
    def bit_value(self) -> int:
        """Binary representation: 0 for positive eigenvalue, 1 for negative eigenvalue."""
        return 0 if self.eigenvalue == 1 else 1

    @property
    def statevector(self) -> np.ndarray:
        """Returns 2x1 complex statevector."""
        inv_sqrt2 = 1.0 / np.sqrt(2.0)
        if self == PauliEigenstate.ZERO:
            return np.array([1.0, 0.0], dtype=complex)
        elif self == PauliEigenstate.ONE:
            return np.array([0.0, 1.0], dtype=complex)
        elif self == PauliEigenstate.PLUS:
            return np.array([inv_sqrt2, inv_sqrt2], dtype=complex)
        elif self == PauliEigenstate.MINUS:
            return np.array([inv_sqrt2, -inv_sqrt2], dtype=complex)
        elif self == PauliEigenstate.PLUS_I:
            return np.array([inv_sqrt2, 1j * inv_sqrt2], dtype=complex)
        elif self == PauliEigenstate.MINUS_I:
            return np.array([inv_sqrt2, -1j * inv_sqrt2], dtype=complex)
        raise ValueError(f"Unknown state {self}")


class StatePreparation:
    """Utilities for preparing quantum states, basis transformations, and projective measurement."""

    @staticmethod
    def from_basis_and_bit(basis: PauliBasis, bit: int) -> PauliEigenstate:
        if basis == PauliBasis.Z:
            return PauliEigenstate.ZERO if bit == 0 else PauliEigenstate.ONE
        elif basis == PauliBasis.X:
            return PauliEigenstate.PLUS if bit == 0 else PauliEigenstate.MINUS
        elif basis == PauliBasis.Y:
            return PauliEigenstate.PLUS_I if bit == 0 else PauliEigenstate.MINUS_I
        raise ValueError(f"Invalid basis: {basis}")

    @staticmethod
    def measure_projective(
        state: np.ndarray,
        measurement_basis: PauliBasis,
        rng: np.random.Generator | None = None
    ) -> Tuple[int, PauliEigenstate]:
        """
        Performs projective measurement of a 1-qubit statevector in the specified Pauli basis.
        Returns: (bit_outcome: 0 or 1, resulting_eigenstate)
        """
        if rng is None:
            rng = np.random.default_rng()

        state = state / np.linalg.norm(state)
        e0 = StatePreparation.from_basis_and_bit(measurement_basis, 0).statevector
        
        # Born rule probability: P(outcome=0) = |<e0|state>|^2
        prob_0 = float(np.abs(np.vdot(e0, state)) ** 2)
        prob_0 = np.clip(prob_0, 0.0, 1.0)
        
        outcome_bit = 0 if rng.random() < prob_0 else 1
        collapsed_state = StatePreparation.from_basis_and_bit(measurement_basis, outcome_bit)
        return outcome_bit, collapsed_state

    @staticmethod
    def calculate_overlap(state1: np.ndarray, state2: np.ndarray) -> float:
        """Returns quantum fidelity / state overlap |<state1|state2>|^2."""
        s1 = state1 / np.linalg.norm(state1)
        s2 = state2 / np.linalg.norm(state2)
        return float(np.abs(np.vdot(s1, s2)) ** 2)
