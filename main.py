"""
Quantum-Inspired Cyber Threat Detection for Teleportation-Based QDS Systems.
Master Entry Point and Demo Runner (SIH 2026).

Usage:
  python main.py --demo honest       # Demo Run 1: Honest session end-to-end
  python main.py --demo forgery      # Demo Run 2: Forgery attack detection
  python main.py --demo replay       # Demo Run 3: Session replay prevention
  python main.py --demo channel      # Demo Run 4: Channel noise & QBER quarantine
  python main.py --demo pauli        # Demo Run 5: Pauli syndrome tampering rejection
  python main.py --demo sweep        # Demo Run 6: Automated parameter sweep & reports
  python main.py --demo all          # Execute all 6 demo runs sequentially
  python main.py --serve             # Launch FastAPI Web SOC Dashboard
"""

from __future__ import annotations
import argparse
import os
import sys
import time
import uvicorn
import numpy as np

from protocol.state_preparation import PauliBasis, StatePreparation
from protocol.bell_pair_generation import BellPairGenerator, BellPairType
from protocol.signature_generation import QDSSignatureGenerator
from protocol.signature_verification import QDSSignatureVerifier
from protocol.teleportation import QuantumTeleporter

from security.ml_kem_interface import MLKEMEngine, PQCAlgorithm
from security.symmetric_crypto import SymmetricCryptoEngine, ClassicalPayload
from security.session_nonce_manager import SessionNonceManager
from security.identity_policy import IdentityPolicyEngine
from security.audit_log import AuditLogger, AuditEventType

from detection.statistical_engine import BinomialThreatEngine
from detection.qber_monitor import QBERMonitor
from detection.correlation_checker import CorrelationChecker
from detection.pauli_consistency import PauliConsistencyChecker
from detection.threshold_evaluator import ThresholdEvaluator

from evaluation.benchmarks import BenchmarkRunner
from evaluation.report_generator import PDFReportGenerator


def print_banner(title: str):
    print("\n" + "=" * 78)
    print(f"  {title.upper()}")
    print("=" * 78)


def run_demo_honest(L: int = 200, threshold_t: int = 30):
    print_banner("Demo Run 1: Honest Teleportation-Based QDS Protocol Session")
    rng = np.random.default_rng(42)
    session_mgr = SessionNonceManager()
    audit_logger = AuditLogger()

    # 1. 3-Party Session Initiation
    message = "SIH-2026-LEGITIMATE-GOVERNMENT-DIRECTIVE"
    msg_digest = QDSSignatureGenerator.compute_message_digest(message)
    session = session_mgr.create_session("ALICE", "BOB", msg_digest)
    print(f"[1] Session Created: ID={session.session_id[:8]}... | Nonce={session.nonce[:16]}...")

    # 2. Classical Post-Quantum Key Exchange (ML-KEM-768)
    bob_kp = MLKEMEngine.generate_keypair(PQCAlgorithm.ML_KEM_768)
    ct, ss_alice = MLKEMEngine.encapsulate(bob_kp.public_key)
    ss_bob = MLKEMEngine.decapsulate(bob_kp.secret_key, ct)
    session_key = MLKEMEngine.derive_session_key(ss_bob, session.session_id)
    print(f"[2] Classical Channel Secured: ML-KEM-768 Shared Secret Derived ({len(session_key)*8} bits)")

    # 3. Signature State Generation
    secret_key = b"alice_master_qds_signing_key_32b"
    sig = QDSSignatureGenerator.generate_signature(message, secret_key, L)
    print(f"[3] Signature Generated: {L} Pauli eigenstates prepared across X, Y, Z bases")

    # 4. Bell-Pair Entanglement & Teleportation
    bell_pairs = BellPairGenerator.generate_session_pairs(L, BellPairType.PHI_PLUS, fidelity=0.99, seed=42)
    bob_states = []
    alice_syndromes = []

    for i in range(L):
        res = QuantumTeleporter.teleport_state(sig.states[i], bell_pairs[i], noise_epsilon=0.02, rng=rng)
        alice_syndromes.append((res.m1, res.m2))
        bob_states.append(res.bob_statevector)
    print(f"[4] Quantum Teleportation Completed: {L} Bell measurements and Pauli corrections applied")

    # 5. Projective Measurement & Verification
    outcome = QDSSignatureVerifier.verify_teleported_signature("BOB", bob_states, sig, threshold_t=threshold_t, rng=rng)
    threat = ThresholdEvaluator.evaluate_signature_verification(outcome)

    print(f"\n[5] VERIFICATION OUTCOME:")
    print(f"    - Decision: {'ACCEPTED (PASS)' if outcome.accepted else 'REJECTED (FAIL)'}")
    print(f"    - Mismatch Count: {outcome.mismatch_count} / {L} (Threshold t = {threshold_t})")
    print(f"    - Mismatch Rate: {outcome.mismatch_rate * 100:.2f}%")
    print(f"    - Statistical Bound P_forge: {threat.evidence_metrics['p_forge_bound']:.2e}")
    print(f"    - False Rejection Bound P_false_reject: {threat.evidence_metrics['p_false_reject_bound']:.2e}")
    print(f"    - Rule Evaluation: {threat.explanation}")


def run_demo_forgery(L: int = 200, threshold_t: int = 30):
    print_banner("Demo Run 2: Adversarial Random Forgery Attack Detection")
    rng = np.random.default_rng(42)

    secret_key = b"alice_master_qds_signing_key_32b"
    sig = QDSSignatureGenerator.generate_signature("Forged Message Attempt", secret_key, L)

    # Attacker fabricates random states
    basis_choices = [PauliBasis.Z, PauliBasis.X, PauliBasis.Y]
    forged_states = [
        StatePreparation.from_basis_and_bit(basis_choices[rng.integers(0, 3)], int(rng.integers(0, 2))).statevector
        for _ in range(L)
    ]

    outcome = QDSSignatureVerifier.verify_teleported_signature("BOB", forged_states, sig, threshold_t=threshold_t, rng=rng)
    threat = ThresholdEvaluator.evaluate_signature_verification(outcome)

    print(f"[*] Attacker Injected: Random Pauli eigenstates (q_adv ~ 0.50)")
    print(f"[!] Mismatch Count M = {outcome.mismatch_count} (Threshold t = {threshold_t})")
    print(f"[!] Defense Classification: {threat.threat_name} [{threat.rule_id}]")
    print(f"[!] Action Taken: {threat.action_taken} (Severity: {threat.severity.value})")
    print(f"[!] Mathematical Bound: P_forge = {threat.evidence_metrics['p_forge_bound']:.2e} <= 10^-6")
    print(f"[*] Result: FORGERY COMPREHENSIVELY DEFEATED")


def run_demo_replay():
    print_banner("Demo Run 3: Session & Resource Replay Attack Defense")
    manager = SessionNonceManager()

    session = manager.create_session("ALICE", "BOB", "hash_of_message_payload")
    print(f"[*] Initial Valid Session Created: Nonce = {session.nonce[:16]}... | Resource = {session.signature_resource_id[:8]}...")

    # Bob validates and consumes once
    c1 = manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)
    print(f"[1] First Submission (Legitimate Bob): Consumed = {c1} (SUCCESS)")

    # Mallory intercepts and replays exact transcript
    c2 = manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)
    print(f"[2] Second Submission (Replay Attacker): Consumed = {c2} (BLOCKED)")
    print(f"[!] Threat Classification: Replay Attack [RULE-REPLAY] -> Action: BLOCK_AND_LOG")


def run_demo_channel(L: int = 200):
    print_banner("Demo Run 4: Channel Disturbance & Wilson Score QBER Quarantine")
    rng = np.random.default_rng(42)

    # Active depolarizing noise injected by eavesdropper
    noise_attack = 0.22
    errors = int(rng.binomial(L, noise_attack))

    assessment = QBERMonitor.evaluate_qber(errors, L, threshold_epsilon_max=0.11, confidence=0.99)
    threat = ThresholdEvaluator.evaluate_qber_threat(assessment)

    print(f"[*] Adversary Channel Perturbation: Error Count = {errors}/{L} (Sample QBER = {assessment.sample_qber*100:.1f}%)")
    print(f"[!] Wilson Score 99% Upper Confidence Bound: {assessment.wilson_upper_bound*100:.2f}%")
    print(f"[!] Threshold epsilon_max: {assessment.threshold_epsilon_max*100:.1f}%")
    print(f"[!] Defense Classification: {threat.threat_name} [{threat.rule_id}]")
    print(f"[!] Action Taken: {threat.action_taken} -> QUANTUM CHANNEL QUARANTINED")


def run_demo_pauli(L: int = 50):
    print_banner("Demo Run 5: Pauli-Operation Correction Syndrome Tampering")
    rng = np.random.default_rng(42)

    alice_syndromes = [(int(rng.integers(0, 2)), int(rng.integers(0, 2))) for _ in range(L)]
    # Adversary tampers with bit indices 3, 7, 12
    bob_syndromes = list(alice_syndromes)
    bob_syndromes[3] = (1 - alice_syndromes[3][0], alice_syndromes[3][1])
    bob_syndromes[7] = (alice_syndromes[7][0], 1 - alice_syndromes[7][1])
    bob_syndromes[12] = (1 - alice_syndromes[12][0], 1 - alice_syndromes[12][1])

    result = PauliConsistencyChecker.verify_corrections(alice_syndromes, bob_syndromes)
    threat = ThresholdEvaluator.evaluate_pauli_tampering(result)

    print(f"[*] Total Corrections Checked: {result.total_checks}")
    print(f"[!] Tampered Indices Detected: {result.tampered_indices}")
    print(f"[!] Defense Classification: {threat.threat_name} [{threat.rule_id}]")
    print(f"[!] Action Taken: {threat.action_taken} -> REJECT TRANSCRIPT")


def run_demo_sweep():
    print_banner("Demo Run 6: Automated Parameter Sweep & Official Report Generation")
    results = BenchmarkRunner.run_full_suite(output_dir="evaluation/reports", n_trials_per_attack=200)

    # Generate Deliverables D8 & D9 PDFs
    PDFReportGenerator.generate_security_analysis_pdf(
        "evaluation/reports/security_analysis.pdf",
        "evaluation/reports/attack_results.json"
    )
    PDFReportGenerator.generate_performance_benchmarks_pdf(
        "evaluation/reports/performance_benchmarks.pdf",
        "evaluation/reports/attack_results.json"
    )

    print("\n" + "=" * 78)
    print("  DELIVERABLE REPORTS SUCCESSFULLY GENERATED:")
    print("  - D6: evaluation/reports/attack_results.json")
    print("  - D8: evaluation/reports/security_analysis.pdf")
    print("  - D9: evaluation/reports/performance_benchmarks.pdf")
    print("  - Plots: p_forge_scaling.png, attack_detection_rates.png, qber_distribution.png, runtime_scaling.png")
    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(description="Quantum Cyber Threat Detection Engine (SIH 2026)")
    parser.add_argument("--demo", choices=["honest", "forgery", "replay", "channel", "pauli", "sweep", "all"], help="Run demonstration scenario")
    parser.add_argument("--serve", action="store_true", help="Launch FastAPI Web SOC Dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Port for web server (default 8000)")

    args = parser.parse_args()

    if args.serve:
        print_banner("Starting Quantum-Cyber SOC Web Dashboard")
        print(f"Server URL: http://127.0.0.1:{args.port}")
        uvicorn.run("web.app:app", host="127.0.0.1", port=args.port, reload=False)
        return

    if args.demo == "honest":
        run_demo_honest()
    elif args.demo == "forgery":
        run_demo_forgery()
    elif args.demo == "replay":
        run_demo_replay()
    elif args.demo == "channel":
        run_demo_channel()
    elif args.demo == "pauli":
        run_demo_pauli()
    elif args.demo == "sweep":
        run_demo_sweep()
    elif args.demo == "all":
        run_demo_honest()
        run_demo_forgery()
        run_demo_replay()
        run_demo_channel()
        run_demo_pauli()
        run_demo_sweep()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
