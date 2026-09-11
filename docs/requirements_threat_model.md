# Deliverable D1: Requirements, System Scope & Threat Model Specification
## Quantum-Inspired Cyber Threat Detection for Teleportation-Based QDS Systems
### Project: SIH 2026 — Track: Cyber Security & Post-Quantum Cryptography

---

## 1. System Scope & Objectives

This framework models, simulates, and defends a 3-party **Quantum Digital Signature (QDS)** architecture operating over entanglement-assisted quantum channels and post-quantum classical channels.

### Security Boundary & Assumptions
1. **Endpoint Trust**: The legitimate endpoints (Alice, Bob, Charlie) have authenticated initial credentials and trusted state-preparation devices.
2. **Channel Model**: The quantum channel transmits Bell pairs and signature states subjected to environmental noise (depolarizing, dephasing) and active adversarial manipulation.
3. **Classical Channel**: Secured via NIST Post-Quantum Cryptography standard **ML-KEM-768 (FIPS 203)** with forward-secure session ephemeral keys.
4. **Deterministic Threat Engine**: Threat detection is strictly non-AI and non-heuristic, based entirely on exact quantum mechanics, binomial confidence bounds, and Wilson score intervals.

---

## 2. Threat Classification Matrix

| Threat ID | Threat Name | Layer | Defense Type | Detection Signal / Mechanism |
|---|---|---|---|---|
| **THREAT-01** | Random Forgery | Quantum / Protocol | Detected & Rejected | Mismatch count $M > t$; Binomial bound $P_{\text{forge}} \le 10^{-6}$ |
| **THREAT-02** | Informed Forgery | Quantum / Protocol | Detected & Rejected | Mismatch count $M > t$ for bounded adversary knowledge ($q_{\text{adv}} \approx 0.25 - 0.35$) |
| **THREAT-03** | Signer Impersonation | Classical Control | Prevented & Blocked | Session identity binding failure / pre-quantum role check |
| **THREAT-04** | Replay Attack | Classical Control | Prevented & Blocked | Reused session ID, duplicated nonce, or consumed resource ID |
| **THREAT-05** | Unauthorized Verification | Classical Control | Prevented & Blocked | Role-based ACL mismatch (non-verifier/arbitrator entity) |
| **THREAT-06** | Pauli-Op Tampering | Classical / Quantum | Detected & Rejected | Classical $m_1, m_2$ bit manipulation causing Pauli consistency mismatch |
| **THREAT-07** | Channel Disturbance | Quantum Channel | Detected & Quarantined | QBER 99% Wilson upper confidence bound $> \varepsilon_{\max}$ |
| **THREAT-08** | Intercept-Resend | Quantum Channel | Detected & Alerted | Eve basis measurement disturbance causing basis disagreement rate $\approx 25\%$ |
| **THREAT-09** | Entanglement Disruption | Quantum Channel | Detected & Flagged | Bell-state fidelity $F < F_{\min}$ ($|\Phi^+\rangle \to |\Phi^-\rangle$ / noise) |
| **THREAT-10** | Denial of Service (DoS) | Classical API Layer | Rate-Limited & Logged | Verification request flooding / abnormal session preparation latency |

---

## 3. Threat Model Boundaries (Out of Scope)
- Physical tampering with Alice's local laser / SPDC hardware.
- Cryptanalysis breaking the underlying lattice hardness of ML-KEM-768.
- Classical side-channel power analysis attacks on local hardware CPU.
