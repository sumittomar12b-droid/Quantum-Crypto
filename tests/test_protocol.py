"""
Unit and Integration Tests for Quantum Protocol Modules (Layer 2).
"""

import numpy as np
import pytest

from protocol.state_preparation import PauliBasis, PauliEigenstate, StatePreparation
from protocol.bell_pair_generation import BellPairGenerator, BellPairType
from protocol.teleportation import QuantumTeleporter
from protocol.signature_generation import QDSSignatureGenerator
from protocol.signature_verification import QDSSignatureVerifier


def test_pauli_eigenstate_orthogonality():
    """Validates orthogonality of Pauli eigenstates in computational, Hadamard, and Phase bases."""
    # Z basis
    overlap_z = StatePreparation.calculate_overlap(
        PauliEigenstate.ZERO.statevector, PauliEigenstate.ONE.statevector
    )
    assert pytest.approx(overlap_z, abs=1e-6) == 0.0

    # X basis
    overlap_x = StatePreparation.calculate_overlap(
        PauliEigenstate.PLUS.statevector, PauliEigenstate.MINUS.statevector
    )
    assert pytest.approx(overlap_x, abs=1e-6) == 0.0

    # Y basis
    overlap_y = StatePreparation.calculate_overlap(
        PauliEigenstate.PLUS_I.statevector, PauliEigenstate.MINUS_I.statevector
    )
    assert pytest.approx(overlap_y, abs=1e-6) == 0.0


def test_bell_pair_generation():
    """Tests EPR Bell-state generation and fidelity calculations."""
    pair = BellPairGenerator.generate_single_pair(BellPairType.PHI_PLUS, fidelity=1.0)
    assert pair.is_valid()
    assert pair.pair_type == BellPairType.PHI_PLUS
    assert len(pair.statevector) == 4

    ideal = BellPairGenerator.get_ideal_statevector(BellPairType.PHI_PLUS)
    fidelity = StatePreparation.calculate_overlap(ideal, pair.statevector)
    assert pytest.approx(fidelity, abs=1e-4) == 1.0


def test_quantum_teleportation_perfect_fidelity():
    """Tests that noise-free teleportation reconstructs input Pauli eigenstate exactly."""
    rng = np.random.default_rng(42)
    test_states = [
        PauliEigenstate.ZERO,
        PauliEigenstate.ONE,
        PauliEigenstate.PLUS,
        PauliEigenstate.MINUS,
        PauliEigenstate.PLUS_I,
        PauliEigenstate.MINUS_I
    ]

    for state in test_states:
        bell_pair = BellPairGenerator.generate_single_pair(BellPairType.PHI_PLUS, fidelity=1.0, rng=rng)
        res = QuantumTeleporter.teleport_state(state, bell_pair, noise_epsilon=0.0, rng=rng)
        
        overlap = StatePreparation.calculate_overlap(state.statevector, res.bob_statevector)
        assert pytest.approx(overlap, abs=1e-4) == 1.0
        assert bell_pair.consumed is True


def test_qds_signature_generation_and_honest_verification():
    """Tests end-to-end honest signature generation and projective measurement verification."""
    secret_key = b"test_alice_qds_secret_key_32b_!"
    message = "SIH-2026-TEST-PAYLOAD"
    L = 100
    threshold_t = 15

    sig = QDSSignatureGenerator.generate_signature(message, secret_key, L)
    assert sig.signature_length == L
    assert len(sig.states) == L

    # Simulate ideal transmission
    statevectors = [st.statevector for st in sig.states]

    outcome = QDSSignatureVerifier.verify_teleported_signature(
        verifier_id="BOB",
        received_statevectors=statevectors,
        expected_signature=sig,
        threshold_t=threshold_t
    )

    assert outcome.accepted is True
    assert outcome.mismatch_count == 0
    assert outcome.mismatch_rate == 0.0
