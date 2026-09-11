"""
Quantum Teleportation Protocol Implementation.
Performs joint Bell-basis measurement and unitary Pauli corrections.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional
import numpy as np

from .state_preparation import PauliBasis, PauliEigenstate, StatePreparation
from .bell_pair_generation import BellPair, BellPairType, BellPairGenerator

try:
    from qiskit import QuantumCircuit
except ImportError:
    QuantumCircuit = None


@dataclass
class TeleportationResult:
    m1: int  # Classical measurement bit 1 (Z-syndrome)
    m2: int  # Classical measurement bit 2 (X-syndrome)
    bob_statevector: np.ndarray  # Statevector at Bob after Pauli correction
    qubit_index: int = 0
    channel_noise_applied: float = 0.0
    pauli_tampered: bool = False


class QuantumTeleporter:
    """Simulates quantum teleportation of arbitrary single-qubit states."""

    # Pauli matrices
    I_GATE = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=complex)
    X_GATE = np.array([[0.0, 1.0], [1.0, 0.0]], dtype=complex)
    Y_GATE = np.array([[0.0, -1j], [1j, 0.0]], dtype=complex)
    Z_GATE = np.array([[1.0, 0.0], [0.0, -1.0]], dtype=complex)

    @staticmethod
    def get_pauli_correction_matrix(m1: int, m2: int) -> np.ndarray:
        """
        Returns Pauli correction unitary matrix sigma(m1, m2) = (Z^m1) * (X^m2).
        m1=0, m2=0 -> I
        m1=0, m2=1 -> X
        m1=1, m2=0 -> Z
        m1=1, m2=1 -> Z * X = -iY (equivalent to X then Z up to global phase)
        """
        corr = np.eye(2, dtype=complex)
        if m2 == 1:
            corr = QuantumTeleporter.X_GATE @ corr
        if m1 == 1:
            corr = QuantumTeleporter.Z_GATE @ corr
        return corr

    @classmethod
    def teleport_state(
        cls,
        input_state: PauliEigenstate | np.ndarray,
        bell_pair: BellPair,
        noise_epsilon: float = 0.0,
        tamper_bits: Optional[Tuple[int, int]] = None,
        rng: Optional[np.random.Generator] = None
    ) -> TeleportationResult:
        """
        Executes quantum teleportation from Alice to Bob.
        
        Args:
            input_state: Qubit statevector or PauliEigenstate to teleport.
            bell_pair: Entangled pair instance (default |Phi+>).
            noise_epsilon: Depolarizing channel noise level (0.0 to 1.0).
            tamper_bits: Overrides m1, m2 if an adversary tampered with classical bits.
            rng: Random number generator.
        """
        if rng is None:
            rng = np.random.default_rng()

        if isinstance(input_state, PauliEigenstate):
            psi = input_state.statevector
        else:
            psi = input_state / np.linalg.norm(input_state)

        # 1. Alice performs Bell Measurement on (psi, Alice's EPR qubit)
        # For an ideal |Phi+> Bell pair, the 4 outcomes (m1, m2) occur with equal probability 1/4.
        m1_actual = int(rng.integers(0, 2))
        m2_actual = int(rng.integers(0, 2))

        # Bob's qubit state prior to correction is Z^m1 X^m2 |psi>
        uncorrected_bob = cls.get_pauli_correction_matrix(m1_actual, m2_actual) @ psi

        # Apply channel noise on Bob's qubit if present
        if noise_epsilon > 0.0:
            rand_val = rng.random()
            if rand_val < noise_epsilon:
                # Apply random Pauli error (X, Y, or Z with equal probability)
                error_choice = rng.integers(0, 3)
                if error_choice == 0:
                    uncorrected_bob = cls.X_GATE @ uncorrected_bob
                elif error_choice == 1:
                    uncorrected_bob = cls.Y_GATE @ uncorrected_bob
                else:
                    uncorrected_bob = cls.Z_GATE @ uncorrected_bob

        # Classical bits received by Bob (potentially tampered)
        if tamper_bits is not None:
            m1_received, m2_received = tamper_bits
            pauli_tampered = (m1_received != m1_actual) or (m2_received != m2_actual)
        else:
            m1_received, m2_received = m1_actual, m2_actual
            pauli_tampered = False

        # 2. Bob applies Pauli correction based on received classical bits
        correction_matrix = cls.get_pauli_correction_matrix(m1_received, m2_received)
        corrected_bob = correction_matrix @ uncorrected_bob
        corrected_bob = corrected_bob / np.linalg.norm(corrected_bob)

        # Mark Bell pair as consumed
        bell_pair.consumed = True

        return TeleportationResult(
            m1=m1_received,
            m2=m2_received,
            bob_statevector=corrected_bob,
            channel_noise_applied=noise_epsilon,
            pauli_tampered=pauli_tampered
        )
