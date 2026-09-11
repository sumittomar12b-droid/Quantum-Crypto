"""
Bell-Pair Generation and Entanglement Distribution for QDS.
Supports EPR pairs (|Phi+>, |Phi->, |Psi+>, |Psi->) with configurable noise and fidelity.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import uuid
from typing import List, Optional
import numpy as np

try:
    from qiskit import QuantumCircuit
except ImportError:
    QuantumCircuit = None  # Fallback handled natively


class BellPairType(str, Enum):
    PHI_PLUS = "phi_plus"    # (|00> + |11>) / sqrt(2)
    PHI_MINUS = "phi_minus"  # (|00> - |11>) / sqrt(2)
    PSI_PLUS = "psi_plus"    # (|01> + |10>) / sqrt(2)
    PSI_MINUS = "psi_minus"  # (|01> - |10>) / sqrt(2)


@dataclass
class BellPair:
    pair_id: str
    pair_type: BellPairType
    statevector: np.ndarray
    nominal_fidelity: float = 1.0
    consumed: bool = False
    qubit_alice_id: str = ""
    qubit_bob_id: str = ""

    def is_valid(self) -> bool:
        return not self.consumed and self.nominal_fidelity > 0.0


class BellPairGenerator:
    """Generates entangled Bell pairs and builds Qiskit circuits."""

    @staticmethod
    def get_ideal_statevector(pair_type: BellPairType) -> np.ndarray:
        inv_sqrt2 = 1.0 / np.sqrt(2.0)
        if pair_type == BellPairType.PHI_PLUS:
            return np.array([inv_sqrt2, 0.0, 0.0, inv_sqrt2], dtype=complex)
        elif pair_type == BellPairType.PHI_MINUS:
            return np.array([inv_sqrt2, 0.0, 0.0, -inv_sqrt2], dtype=complex)
        elif pair_type == BellPairType.PSI_PLUS:
            return np.array([0.0, inv_sqrt2, inv_sqrt2, 0.0], dtype=complex)
        elif pair_type == BellPairType.PSI_MINUS:
            return np.array([0.0, inv_sqrt2, -inv_sqrt2, 0.0], dtype=complex)
        raise ValueError(f"Unknown Bell pair type: {pair_type}")

    @staticmethod
    def build_qiskit_circuit(pair_type: BellPairType) -> Optional[QuantumCircuit]:
        if QuantumCircuit is None:
            return None
        qc = QuantumCircuit(2, 2, name=f"bell_pair_{pair_type.value}")
        qc.h(0)
        qc.cx(0, 1)
        if pair_type == BellPairType.PHI_MINUS:
            qc.z(0)
        elif pair_type == BellPairType.PSI_PLUS:
            qc.x(1)
        elif pair_type == BellPairType.PSI_MINUS:
            qc.z(0)
            qc.x(1)
        return qc

    @classmethod
    def generate_single_pair(
        cls,
        pair_type: BellPairType = BellPairType.PHI_PLUS,
        fidelity: float = 1.0,
        rng: Optional[np.random.Generator] = None
    ) -> BellPair:
        if rng is None:
            rng = np.random.default_rng()

        ideal_vec = cls.get_ideal_statevector(pair_type)
        pair_id = str(uuid.uuid4())

        if fidelity < 1.0:
            # Add state depolarization/noise mixture
            noise_vec = rng.normal(size=4) + 1j * rng.normal(size=4)
            noise_vec /= np.linalg.norm(noise_vec)
            # Convex mixture to simulate target fidelity
            mixed_vec = np.sqrt(fidelity) * ideal_vec + np.sqrt(1.0 - fidelity) * noise_vec
            mixed_vec /= np.linalg.norm(mixed_vec)
            actual_vec = mixed_vec
        else:
            actual_vec = ideal_vec

        return BellPair(
            pair_id=pair_id,
            pair_type=pair_type,
            statevector=actual_vec,
            nominal_fidelity=fidelity,
            consumed=False,
            qubit_alice_id=f"{pair_id}-alice",
            qubit_bob_id=f"{pair_id}-bob"
        )

    @classmethod
    def generate_session_pairs(
        cls,
        num_pairs: int,
        pair_type: BellPairType = BellPairType.PHI_PLUS,
        fidelity: float = 0.99,
        seed: Optional[int] = None
    ) -> List[BellPair]:
        rng = np.random.default_rng(seed)
        return [
            cls.generate_single_pair(pair_type=pair_type, fidelity=fidelity, rng=rng)
            for _ in range(num_pairs)
        ]
