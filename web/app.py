"""
FastAPI Backend Application for Quantum-Inspired Cyber Threat Detection SOC.
Provides endpoints for protocol simulation, attack injection, audit stream, and PDF reports.
Configured for local hosting and Vercel Serverless deployment.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import numpy as np

from protocol.state_preparation import PauliBasis, StatePreparation
from protocol.bell_pair_generation import BellPairGenerator, BellPairType
from protocol.signature_generation import QDSSignatureGenerator
from protocol.signature_verification import QDSSignatureVerifier
from protocol.teleportation import QuantumTeleporter

from security.ml_kem_interface import MLKEMEngine, PQCAlgorithm
from security.symmetric_crypto import SymmetricCryptoEngine, ClassicalPayload
from security.session_nonce_manager import SessionNonceManager, SessionState
from security.identity_policy import IdentityPolicyEngine
from security.audit_log import AuditLogger, AuditEventType

from detection.statistical_engine import BinomialThreatEngine
from detection.qber_monitor import QBERMonitor
from detection.correlation_checker import CorrelationChecker
from detection.pauli_consistency import PauliConsistencyChecker
from detection.threshold_evaluator import ThresholdEvaluator, ThreatSeverity

from evaluation.benchmarks import BenchmarkRunner
from evaluation.report_generator import PDFReportGenerator


app = FastAPI(
    title="Quantum-Inspired Threat Detection SOC API",
    description="Deterministic Cyber Threat Detection for Teleportation-Based QDS (SIH 2026)",
    version="1.0.0"
)

# Environment detection (Vercel serverless vs Local)
IS_VERCEL = bool(os.environ.get("VERCEL"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
REPORTS_DIR = "/tmp/reports" if IS_VERCEL else os.path.join(os.path.dirname(BASE_DIR), "evaluation", "reports")
LOG_PATH = "/tmp/audit_trail.jsonl" if IS_VERCEL else "logs/audit_trail.jsonl"

os.makedirs(REPORTS_DIR, exist_ok=True)

# Shared in-memory singletons for demo session
session_manager = SessionNonceManager()
policy_engine = IdentityPolicyEngine()
audit_logger = AuditLogger(log_filepath=LOG_PATH)


class ProtocolRunRequest(BaseModel):
    mode: str = Field(default="honest", description="'honest' or attack name ('random_forger', 'replay', etc.)")
    signer_id: str = Field(default="ALICE")
    verifier_id: str = Field(default="BOB")
    message: str = Field(default="SIH-2026-QUANTUM-DIGITAL-SIGNATURE-VERIFICATION")
    signature_length_L: int = Field(default=200, ge=10, le=1000)
    noise_epsilon: float = Field(default=0.03, ge=0.0, le=0.50)
    threshold_t: Optional[int] = Field(default=None)


@app.get("/api/status")
def get_system_status() -> Dict[str, Any]:
    return {
        "status": "ONLINE",
        "system": "Quantum Threat Detection SOC",
        "protocol": "Teleportation-Based QDS (Yin et al.)",
        "pqc_standard": "ML-KEM-768 (FIPS 203)",
        "deployment": "Vercel Serverless" if IS_VERCEL else "Local / Self-Hosted",
        "hash_chain_integrity": audit_logger.verify_chain_integrity(),
        "total_audit_events": len(audit_logger.events)
    }


@app.post("/api/protocol/execute")
def execute_protocol(req: ProtocolRunRequest) -> Dict[str, Any]:
    L = req.signature_length_L
    t = req.threshold_t if req.threshold_t is not None else int(L * 0.15)
    rng = np.random.default_rng()

    # Log session creation event
    msg_digest = QDSSignatureGenerator.compute_message_digest(req.message)
    session = session_manager.create_session(req.signer_id, req.verifier_id, msg_digest)

    audit_logger.log_event(
        AuditEventType.SESSION_CREATED,
        session.session_id,
        req.signer_id,
        {"recipient": req.verifier_id, "message_digest": msg_digest, "L": L, "mode": req.mode}
    )

    # 1. Check Identity Policy (Role-based access)
    if req.mode == "impersonation":
        req.signer_id = "MALLORY_ATTACKER"

    if not policy_engine.can_sign(req.signer_id):
        audit_logger.log_event(
            AuditEventType.POLICY_VIOLATION,
            session.session_id,
            req.signer_id,
            {"action": "SIGN", "error": "Actor unauthorized for SIGN role"}
        )
        return {
            "session_id": session.session_id,
            "mode": req.mode,
            "accepted": False,
            "status": "BLOCKED_PRE_QUANTUM",
            "threat_detected": True,
            "threat_name": "Signer Impersonation",
            "rule_id": "RULE-IMPERSONATION",
            "explanation": f"Unauthorized signer '{req.signer_id}' blocked before quantum resource distribution.",
            "metrics": {}
        }

    if req.mode == "unauthorized_verifier":
        req.verifier_id = "EVE_SNOOPER"

    if not policy_engine.can_verify(req.verifier_id):
        audit_logger.log_event(
            AuditEventType.POLICY_VIOLATION,
            session.session_id,
            req.verifier_id,
            {"action": "VERIFY", "error": "Recipient unauthorized for VERIFY role"}
        )
        return {
            "session_id": session.session_id,
            "mode": req.mode,
            "accepted": False,
            "status": "BLOCKED_PRE_QUANTUM",
            "threat_detected": True,
            "threat_name": "Unauthorized Verification",
            "rule_id": "RULE-UNAUTHORIZED-VERIF",
            "explanation": f"Unauthorized verifier '{req.verifier_id}' blocked by identity policy.",
            "metrics": {}
        }

    # 2. Check Replay Attack
    if req.mode == "replay":
        # Simulate replay by consuming resource first
        session_manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)
        replayed = not session_manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)
        if replayed:
            audit_logger.log_event(
                AuditEventType.REPLAY_BLOCKED,
                session.session_id,
                req.verifier_id,
                {"nonce": session.nonce, "resource_id": session.signature_resource_id}
            )
            return {
                "session_id": session.session_id,
                "mode": req.mode,
                "accepted": False,
                "status": "REPLAY_BLOCKED",
                "threat_detected": True,
                "threat_name": "Replay Attack",
                "rule_id": "RULE-REPLAY",
                "explanation": "Duplicate nonce and signature resource detected. Replay transaction blocked.",
                "metrics": {}
            }

    # 3. Classical Post-Quantum ML-KEM Key Exchange
    bob_keypair = MLKEMEngine.generate_keypair(PQCAlgorithm.ML_KEM_768)
    ct, shared_secret_alice = MLKEMEngine.encapsulate(bob_keypair.public_key)
    shared_secret_bob = MLKEMEngine.decapsulate(bob_keypair.secret_key, ct)
    session_key = MLKEMEngine.derive_session_key(shared_secret_bob, session.session_id)

    # 4. Generate Quantum Signature
    secret_key = b"alice_master_qds_signing_key_32b"
    sig = QDSSignatureGenerator.generate_signature(req.message, secret_key, L)

    audit_logger.log_event(
        AuditEventType.SIGNATURE_GENERATED,
        session.session_id,
        req.signer_id,
        {"signature_id": sig.signature_id, "signature_length": L}
    )

    # 5. Bell Pair Generation & Teleportation
    bell_fidelity = 0.60 if req.mode == "entanglement_disruption" else 0.99
    noise_lvl = 0.25 if req.mode == "channel_disturbance" else req.noise_epsilon

    bell_pairs = BellPairGenerator.generate_session_pairs(L, BellPairType.PHI_PLUS, fidelity=bell_fidelity, seed=42)

    alice_syndromes = []
    bob_states = []

    for i in range(L):
        tamper_bits = None
        if req.mode == "pauli_tamper" and i < 20:
            tamper_bits = (1, 1)

        res = QuantumTeleporter.teleport_state(
            input_state=sig.states[i],
            bell_pair=bell_pairs[i],
            noise_epsilon=noise_lvl,
            tamper_bits=tamper_bits,
            rng=rng
        )
        alice_syndromes.append((res.m1 if not tamper_bits else 0, res.m2 if not tamper_bits else 0))
        bob_states.append(res.bob_statevector)

    # 6. Forgery Injection
    if req.mode == "random_forger":
        basis_choices = [PauliBasis.Z, PauliBasis.X, PauliBasis.Y]
        bob_states = [
            StatePreparation.from_basis_and_bit(
                basis_choices[rng.integers(0, 3)], int(rng.integers(0, 2))
            ).statevector
            for _ in range(L)
        ]
    elif req.mode == "informed_forger":
        basis_choices = [PauliBasis.Z, PauliBasis.X, PauliBasis.Y]
        for i in range(L):
            if rng.random() >= 0.30:  # 70% unknown
                bob_states[i] = StatePreparation.from_basis_and_bit(
                    basis_choices[rng.integers(0, 3)], int(rng.integers(0, 2))
                ).statevector

    # 7. Threat Detectors Evaluation
    outcome = QDSSignatureVerifier.verify_teleported_signature(
        verifier_id=req.verifier_id,
        received_statevectors=bob_states,
        expected_signature=sig,
        threshold_t=t,
        rng=rng
    )
    forgery_threat = ThresholdEvaluator.evaluate_signature_verification(outcome)

    qber_errors = int(outcome.mismatch_count)
    qber_eval = QBERMonitor.evaluate_qber(qber_errors, L, threshold_epsilon_max=0.12)
    qber_threat = ThresholdEvaluator.evaluate_qber_threat(qber_eval)

    basis_disagreements = int(L * 0.25) if req.mode == "intercept_resend" else int(L * 0.02)
    corr_eval = CorrelationChecker.evaluate_channel_correlations(
        bell_pairs=bell_pairs[:20],
        basis_disagreement_count=basis_disagreements,
        total_basis_tests=L,
        min_fidelity_threshold=0.85
    )
    corr_threat = ThresholdEvaluator.evaluate_correlations(corr_eval)

    bob_syndromes = []
    for i in range(min(L, 20)):
        m1, m2 = alice_syndromes[i]
        if req.mode == "pauli_tamper":
            # Tampered bits
            bob_syndromes.append((1 - m1, m2))
        else:
            bob_syndromes.append((m1, m2))

    pauli_eval = PauliConsistencyChecker.verify_corrections(alice_syndromes[:20], bob_syndromes)
    pauli_threat = ThresholdEvaluator.evaluate_pauli_tampering(pauli_eval)

    detected_threats = []
    for th in [forgery_threat, qber_threat, corr_threat, pauli_threat]:
        if th.detected:
            detected_threats.append(th)

    has_threat = len(detected_threats) > 0
    primary_threat = detected_threats[0] if has_threat else None

    audit_logger.log_event(
        AuditEventType.VERIFICATION_ACCEPTED if (outcome.accepted and not has_threat) else AuditEventType.VERIFICATION_REJECTED,
        session.session_id,
        req.verifier_id,
        {
            "accepted": outcome.accepted and not has_threat,
            "mismatches": outcome.mismatch_count,
            "threshold": t,
            "threats_detected": [th.threat_name for th in detected_threats]
        }
    )

    session_manager.validate_and_consume(session.session_id, session.nonce, session.signature_resource_id)

    return {
        "session_id": session.session_id,
        "mode": req.mode,
        "accepted": outcome.accepted and not has_threat,
        "mismatch_count": outcome.mismatch_count,
        "mismatch_rate": outcome.mismatch_rate,
        "threshold_t": t,
        "threat_detected": has_threat,
        "primary_threat": {
            "threat_name": primary_threat.threat_name,
            "rule_id": primary_threat.rule_id,
            "severity": primary_threat.severity.value,
            "action_taken": primary_threat.action_taken,
            "explanation": primary_threat.explanation,
            "mathematical_citation": primary_threat.mathematical_citation
        } if primary_threat else None,
        "all_threats": [
            {
                "threat_name": th.threat_name,
                "rule_id": th.rule_id,
                "severity": th.severity.value,
                "explanation": th.explanation
            }
            for th in detected_threats
        ],
        "qber_assessment": {
            "sample_qber": qber_eval.sample_qber,
            "wilson_upper_bound": qber_eval.wilson_upper_bound,
            "quarantine_alert": qber_eval.quarantine_alert
        },
        "entanglement_fidelity": corr_eval.measured_fidelity,
        "p_forge_bound": forgery_threat.evidence_metrics.get("p_forge_bound", 0.0)
    }


@app.get("/api/audit/logs")
def get_audit_logs(limit: int = 50) -> Dict[str, Any]:
    events = audit_logger.events[-limit:]
    return {
        "integrity_verified": audit_logger.verify_chain_integrity(),
        "total_count": len(audit_logger.events),
        "events": [
            {
                "sequence_number": e.sequence_number,
                "timestamp": e.timestamp,
                "event_type": e.event_type.value,
                "session_id": e.session_id,
                "actor": e.actor,
                "details": e.details,
                "event_hash": e.event_hash[:16] + "..."
            }
            for e in reversed(events)
        ]
    }


@app.post("/api/benchmarks/run")
def run_live_benchmarks() -> Dict[str, Any]:
    res = BenchmarkRunner.run_full_suite(output_dir=REPORTS_DIR, n_trials_per_attack=100)
    
    json_path = os.path.join(REPORTS_DIR, "attack_results.json")
    PDFReportGenerator.generate_security_analysis_pdf(
        os.path.join(REPORTS_DIR, "security_analysis.pdf"),
        json_path,
        plots_dir=REPORTS_DIR
    )
    PDFReportGenerator.generate_performance_benchmarks_pdf(
        os.path.join(REPORTS_DIR, "performance_benchmarks.pdf"),
        json_path,
        plots_dir=REPORTS_DIR
    )
    return {
        "status": "COMPLETED",
        "timestamp": res.timestamp,
        "overall_passed": res.overall_passed,
        "attack_count": len(res.attack_benchmarks)
    }


@app.get("/api/reports/download/{report_type}")
def download_report(report_type: str):
    reports = {
        "security_pdf": os.path.join(REPORTS_DIR, "security_analysis.pdf"),
        "performance_pdf": os.path.join(REPORTS_DIR, "performance_benchmarks.pdf"),
        "attack_json": os.path.join(REPORTS_DIR, "attack_results.json")
    }
    path = reports.get(report_type)
    if not path or not os.path.exists(path):
        # Generate automatically if missing
        run_live_benchmarks()

    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Report '{report_type}' not found.")
    return FileResponse(path, filename=os.path.basename(path))


# Explicit root index route
@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Quantum SOC Online</h1>")


# Mount static assets
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static-root")
