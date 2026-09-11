"""
Attack 2: Informed Forgery Simulation.
Attacker possesses partial knowledge (e.g. 30% of basis choices) but still fails binomial threshold.
"""

from __future__ import annotations
import numpy as np

from .base_attack import BaseAttack
from protocol.state_preparation import PauliBasis, PauliEigenstate, StatePreparation
from protocol.signature_generation import QDSSignatureGenerator
from protocol.signature_verification import QDSSignatureVerifier
from detection.threshold_evaluator import ThresholdEvaluator


class InformedForgerAttack(BaseAttack):
    def __init__(self, partial_knowledge_ratio: float = 0.30):
        super().__init__(attack_id="ATTACK-02", attack_name="Informed Forgery (Partial Knowledge)")
        self.knowledge_ratio = partial_knowledge_ratio

    def execute_single_attack(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        secret_key = b"honest_alice_secret_key_32bytes"
        expected_sig = QDSSignatureGenerator.generate_signature("Valid Message", secret_key, L)
        threshold_t = int(L * 0.15)

        basis_choices = [PauliBasis.Z, PauliBasis.X, PauliBasis.Y]
        forged_statevectors = []

        for i in range(L):
            if rng.random() < self.knowledge_ratio:
                # Attacker correctly guesses basis and bit for this element
                st = expected_sig.states[i].statevector
            else:
                # Guesses randomly for remaining elements
                rnd_basis = basis_choices[rng.integers(0, 3)]
                rnd_bit = int(rng.integers(0, 2))
                st = StatePreparation.from_basis_and_bit(rnd_basis, rnd_bit).statevector
            forged_statevectors.append(st)

        outcome = QDSSignatureVerifier.verify_teleported_signature(
            verifier_id="BOB",
            received_statevectors=forged_statevectors,
            expected_signature=expected_sig,
            threshold_t=threshold_t,
            rng=rng
        )

        threat = ThresholdEvaluator.evaluate_signature_verification(outcome)
        return not outcome.accepted and threat.detected

    def execute_single_honest(self, L: int, noise: float, rng: np.random.Generator) -> bool:
        secret_key = b"honest_alice_secret_key_32bytes"
        expected_sig = QDSSignatureGenerator.generate_signature("Valid Message", secret_key, L)
        threshold_t = int(L * 0.15)

        honest_statevectors = [st.statevector for st in expected_sig.states]

        outcome = QDSSignatureVerifier.verify_teleported_signature(
            verifier_id="BOB",
            received_statevectors=honest_statevectors,
            expected_signature=expected_sig,
            threshold_t=threshold_t,
            rng=rng
        )

        threat = ThresholdEvaluator.evaluate_signature_verification(outcome)
        return not outcome.accepted or threat.detected
