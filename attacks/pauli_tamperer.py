"""
Attack 6: Pauli Correction Tampering Simulation.
Attacker tampers with classical bits (m1, m2), causing Bob to apply wrong unitary corrections.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from detection.pauli_consistency import PauliConsistencyChecker


class PauliTamperingAttack(BaseAttack):
    def __init__(self, tamper_rate: float = 0.20):
        super().__init__(attack_id="ATTACK-06", attack_name="Pauli-Op Syndrome Tampering")
        self.tamper_rate = tamper_rate

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        # Generate authentic Alice syndromes
        alice_syndromes = [(int(rng.integers(0, 2)), int(rng.integers(0, 2))) for _ in range(L)]
        bob_syndromes = []

        # Adversary flips classical bits on channel
        for m1, m2 in alice_syndromes:
            if rng.random() < self.tamper_rate:
                # Flip m1 or m2
                tampered_m1 = 1 - m1 if rng.random() < 0.5 else m1
                tampered_m2 = 1 - m2 if tampered_m1 == m1 else m2
                bob_syndromes.append((tampered_m1, tampered_m2))
            else:
                bob_syndromes.append((m1, m2))

        result = PauliConsistencyChecker.verify_corrections(alice_syndromes, bob_syndromes)
        # Mitigated if tampering detected
        return not result.is_valid

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        alice_syndromes = [(int(rng.integers(0, 2)), int(rng.integers(0, 2))) for _ in range(L)]
        bob_syndromes = list(alice_syndromes)  # Authentic channel transfer

        result = PauliConsistencyChecker.verify_corrections(alice_syndromes, bob_syndromes)
        # False alert if honest matching syndromes are flagged
        return not result.is_valid
