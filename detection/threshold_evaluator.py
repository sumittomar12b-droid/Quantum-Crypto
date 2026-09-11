"""
Deterministic Rule-Based Threat Evaluator and Classifier (Non-AI).
Applies explicit mathematical and protocol logic rules to classify threats with zero machine learning.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from .statistical_engine import BinomialThreatEngine
from .qber_monitor import QBERAssessment
from .correlation_checker import BellCorrelationResult
from .pauli_consistency import PauliVerificationResult
from protocol.signature_verification import VerificationOutcome


class ThreatSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatClassification:
    rule_id: str
    threat_name: str
    severity: ThreatSeverity
    detected: bool
    action_taken: str
    mathematical_citation: str
    evidence_metrics: Dict[str, Any]
    explanation: str


class ThresholdEvaluator:
    """Zero-AI Deterministic Threat Evaluation Engine."""

    @classmethod
    def evaluate_signature_verification(
        cls,
        verification_outcome: VerificationOutcome,
        q_adv: float = 0.35,
        q_honest: float = 0.05
    ) -> ThreatClassification:
        """
        Evaluates RULE-FORGERY via exact binomial bounds.
        """
        L = verification_outcome.total_elements
        t = verification_outcome.threshold_t
        M = verification_outcome.mismatch_count

        p_forge = BinomialThreatEngine.compute_p_forge(L, t, q_adv)
        p_false_reject = BinomialThreatEngine.compute_p_false_reject(L, t, q_honest)

        is_forgery = (M > t)

        if is_forgery:
            action = "REJECT_AND_ALERT"
            severity = ThreatSeverity.CRITICAL
            explanation = (
                f"Mismatch count M={M} exceeds acceptance threshold t={t} (L={L}). "
                f"Statistical forgery probability bound P_forge={p_forge:.2e}."
            )
        else:
            action = "ACCEPT_SIGNATURE"
            severity = ThreatSeverity.INFORMATIONAL
            explanation = (
                f"Mismatch count M={M} within threshold t={t} (L={L}). "
                f"False rejection probability bound P_false_reject={p_false_reject:.2e}."
            )

        return ThreatClassification(
            rule_id="RULE-FORGERY",
            threat_name="Signature Forgery",
            severity=severity,
            detected=is_forgery,
            action_taken=action,
            mathematical_citation="M ~ Binomial(L, q); P_forge = sum_{k=0}^t C(L,k) q_adv^k (1-q_adv)^(L-k)",
            evidence_metrics={
                "signature_length_L": L,
                "threshold_t": t,
                "mismatch_count_M": M,
                "mismatch_rate": verification_outcome.mismatch_rate,
                "p_forge_bound": p_forge,
                "p_false_reject_bound": p_false_reject
            },
            explanation=explanation
        )

    @classmethod
    def evaluate_qber_threat(cls, qber_assessment: QBERAssessment) -> ThreatClassification:
        """Evaluates RULE-CHANNEL-MITM via Wilson score confidence intervals."""
        detected = qber_assessment.quarantine_alert
        severity = ThreatSeverity.HIGH if detected else ThreatSeverity.INFORMATIONAL
        action = "QUARANTINE_CHANNEL" if detected else "CHANNEL_CLEAR"

        return ThreatClassification(
            rule_id="RULE-CHANNEL-MITM",
            threat_name="Quantum Channel Manipulation / MITM",
            severity=severity,
            detected=detected,
            action_taken=action,
            mathematical_citation="Wilson score UCB_{0.99}(p) > epsilon_max",
            evidence_metrics={
                "sample_qber": qber_assessment.sample_qber,
                "wilson_upper_bound": qber_assessment.wilson_upper_bound,
                "threshold_epsilon_max": qber_assessment.threshold_epsilon_max,
                "error_count": qber_assessment.error_count,
                "total_samples": qber_assessment.total_samples
            },
            explanation=qber_assessment.status_summary
        )

    @classmethod
    def evaluate_correlations(cls, correlation_result: BellCorrelationResult) -> ThreatClassification:
        """Evaluates RULE-INTERCEPT-RESEND and RULE-ENTANGLEMENT-DISRUPTION."""
        detected = (not correlation_result.entanglement_valid) or correlation_result.intercept_resend_detected

        if correlation_result.intercept_resend_detected:
            rule_id = "RULE-INTERCEPT-RESEND"
            threat_name = "Intercept-Resend Eavesdropping"
            severity = ThreatSeverity.CRITICAL
            action = "ALERT_COMPROMISE"
            math_cite = "Eve basis measurement disturbance -> Basis Disagreement Rate ~ 0.25 > 0.20"
        elif not correlation_result.entanglement_valid:
            rule_id = "RULE-ENTANGLEMENT-DISRUPTION"
            threat_name = "Entanglement Disruption"
            severity = ThreatSeverity.HIGH
            action = "FLAG_RESOURCE_COMPROMISED"
            math_cite = "Bell-state fidelity F = |<ideal|actual>|^2 < F_min"
        else:
            rule_id = "RULE-CORRELATIONS-OK"
            threat_name = "Quantum Entanglement & Basis Health"
            severity = ThreatSeverity.INFORMATIONAL
            action = "CORRELATIONS_VALID"
            math_cite = "F >= F_min and Disagreement <= 0.20"

        return ThreatClassification(
            rule_id=rule_id,
            threat_name=threat_name,
            severity=severity,
            detected=detected,
            action_taken=action,
            mathematical_citation=math_cite,
            evidence_metrics={
                "measured_fidelity": correlation_result.measured_fidelity,
                "fidelity_threshold": correlation_result.fidelity_threshold,
                "basis_disagreement_rate": correlation_result.basis_disagreement_rate,
                "basis_disagreement_threshold": correlation_result.basis_disagreement_threshold
            },
            explanation=correlation_result.summary
        )

    @classmethod
    def evaluate_pauli_tampering(cls, pauli_result: PauliVerificationResult) -> ThreatClassification:
        """Evaluates RULE-PAULI-TAMPER."""
        detected = not pauli_result.is_valid
        severity = ThreatSeverity.CRITICAL if detected else ThreatSeverity.INFORMATIONAL
        action = "REJECT_TRANSCRIPT" if detected else "PAULI_CORRECTIONS_VALID"

        return ThreatClassification(
            rule_id="RULE-PAULI-TAMPER",
            threat_name="Pauli Correction Syndrome Tampering",
            severity=severity,
            detected=detected,
            action_taken=action,
            mathematical_citation="Transmitted (m1, m2) syndrome checksum != Bob applied correction",
            evidence_metrics={
                "total_checks": pauli_result.total_checks,
                "inconsistencies": pauli_result.inconsistencies,
                "tampered_indices": pauli_result.tampered_indices[:10]
            },
            explanation=pauli_result.summary
        )

    @classmethod
    def evaluate_dos_activity(
        cls,
        requests_per_minute: int,
        latency_ms: float,
        max_rpm: int = 120,
        max_latency_ms: float = 1500.0
    ) -> ThreatClassification:
        """Evaluates RULE-DOS."""
        rate_exceeded = requests_per_minute > max_rpm
        latency_exceeded = latency_ms > max_latency_ms
        detected = rate_exceeded or latency_exceeded

        severity = ThreatSeverity.MEDIUM if detected else ThreatSeverity.INFORMATIONAL
        action = "RATE_LIMIT_AND_CLASSIFY" if detected else "NORMAL_THROUGHPUT"

        return ThreatClassification(
            rule_id="RULE-DOS",
            threat_name="Denial of Service (DoS) / Availability Anomaly",
            severity=severity,
            detected=detected,
            action_taken=action,
            mathematical_citation="Request Rate > R_max or Latency > T_max",
            evidence_metrics={
                "requests_per_minute": requests_per_minute,
                "max_rpm": max_rpm,
                "latency_ms": latency_ms,
                "max_latency_ms": max_latency_ms
            },
            explanation=f"Rate: {requests_per_minute}/{max_rpm} RPM | Latency: {latency_ms:.2f}ms"
        )
