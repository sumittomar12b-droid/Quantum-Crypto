"""
Unit and Integration Tests for Non-AI Statistical Threat Detectors (Layer 3).
"""

import pytest

from detection.statistical_engine import BinomialThreatEngine
from detection.qber_monitor import QBERMonitor
from detection.correlation_checker import CorrelationChecker
from detection.pauli_consistency import PauliConsistencyChecker
from detection.threshold_evaluator import ThresholdEvaluator


def test_binomial_p_forge_and_false_reject_bounds():
    """Tests exact Binomial CDF bounds for forgery and false rejection."""
    L = 200
    t = 30
    q_adv = 0.35
    q_honest = 0.05

    p_forge = BinomialThreatEngine.compute_p_forge(L, t, q_adv)
    p_false_reject = BinomialThreatEngine.compute_p_false_reject(L, t, q_honest)

    # For L=200, t=30, q_adv=0.35: P_forge must be <= 10^-6
    assert p_forge <= 1e-6
    # Honest rejection probability must be small (< 1%)
    assert p_false_reject <= 0.01


def test_wilson_score_qber_monitoring():
    """Tests Wilson score 99% upper confidence bounds for channel assessment."""
    # Scenario A: Healthy channel (3 errors out of 200)
    eval_healthy = QBERMonitor.evaluate_qber(error_count=3, total_samples=200, threshold_epsilon_max=0.11)
    assert eval_healthy.sample_qber == 0.015
    assert eval_healthy.quarantine_alert is False
    assert eval_healthy.wilson_upper_bound < 0.11

    # Scenario B: Disturbed channel under attack (35 errors out of 200)
    eval_attack = QBERMonitor.evaluate_qber(error_count=35, total_samples=200, threshold_epsilon_max=0.11)
    assert eval_attack.sample_qber == 0.175
    assert eval_attack.quarantine_alert is True
    assert eval_attack.wilson_upper_bound > 0.11


def test_pauli_consistency_checker():
    """Tests detection of tampered classical syndrome bits."""
    alice_syndromes = [(0, 0), (1, 0), (0, 1), (1, 1)]
    bob_syndromes_clean = [(0, 0), (1, 0), (0, 1), (1, 1)]
    bob_syndromes_tampered = [(0, 0), (1, 1), (0, 1), (1, 1)]  # Index 1 flipped

    res_clean = PauliConsistencyChecker.verify_corrections(alice_syndromes, bob_syndromes_clean)
    assert res_clean.is_valid is True
    assert res_clean.inconsistencies == 0

    res_tampered = PauliConsistencyChecker.verify_corrections(alice_syndromes, bob_syndromes_tampered)
    assert res_tampered.is_valid is False
    assert res_tampered.inconsistencies == 1
    assert 1 in res_tampered.tampered_indices
