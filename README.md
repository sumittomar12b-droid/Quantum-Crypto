# 🔐 Quantum-Inspired Cyber Threat Detection for Teleportation-Based QDS Systems
### Smart India Hackathon (SIH 2026) — Complete Post-Quantum & Quantum Defense Architecture

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![PQC Standard](https://img.shields.io/badge/PQC-ML--KEM--768%20(FIPS%20203)-purple.svg)](https://csrc.nist.gov/)
[![Quantum Simulation](https://img.shields.io/badge/Quantum-Qiskit%20Aer-cyan.svg)](https://qiskit.org/)
[![Threat Detection](https://img.shields.io/badge/Detection-Non--AI%20Deterministic-green.svg)](#layer-3-statistical-threat-detection-engine)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

---

## 📌 Executive Summary

This repository presents a **4-layer quantum-protocol simulator and non-AI statistical threat detection framework** for a 3-party (Alice, Bob, Charlie) teleportation-based Quantum Digital Signature (QDS) architecture. 

The framework is paired with an **ML-KEM-768 secured classical control plane (NIST FIPS 203)**, single-use resource consumption, Wilson-score QBER quarantine boundaries, and a SHA3-256 hash-chained tamper-evident audit trail.

---

## 🏛️ System Architecture (4 Layers)

```
╔══════════════════════════════════════════════════════════════════════════╗
║                     LAYER 1: PROTOCOL CONFIGURATION                     ║
║  Signature length L │ Noise model ε │ Thresholds t │ Policy version      ║
║  Protocol variant   │ Bell-pair fidelity F │ Session parameters          ║
╚═══════════════════════════════╦══════════════════════════════════════════╝
                                ║
╔═══════════════════════════════╩══════════════════════════════════════════╗
║           LAYER 2: TELEPORTATION-BASED QDS PROTOCOL SIMULATOR           ║
║  Alice (Signer) ──► Bell-Pair Distribution ──► Teleportation ──► Bob     ║
║  Eigenstate Encoding (X, Y, Z) ──► ML-KEM Encrypted Corrections (m1,m2)  ║
╚═══════════════════════════════╦══════════════════════════════════════════╝
                                ║
╔═══════════════════════════════╩══════════════════════════════════════════╗
║                   LAYER 3: STATISTICAL THREAT DETECTOR                  ║
║  Exact Binomial Threat Model (P_forge ≤ 10^-6, P_false_reject ≤ 1%)      ║
║  Wilson Score 99% QBER Upper Bound │ Pauli Correction Consistency Engine ║
║  Deterministic Rule Engine (10 Threats, Zero ML / Heuristics)            ║
╚═══════════════════════════════╦══════════════════════════════════════════╝
                                ║
╔═══════════════════════════════╩══════════════════════════════════════════╗
║             LAYER 4: SECURITY CONTROLS, EVIDENCE & REPORTING           ║
║  ML-KEM-768 Key Encapsulation │ AES-256-GCM Classical Channel           ║
║  Session Nonce Replay Defense │ Tamper-Evident SHA3-256 Audit Trail      ║
║  FastAPI Cyber-Quantum SOC Dashboard │ Automated PDF / JSON Reports      ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## 🚀 Quick Start & Installation

### 1. Local Setup
```bash
# Clone the repository and navigate to root
cd "Quantum Crypto"

# Create virtual environment
py -3.13 -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### 2. Deploy to Vercel (1-Click)
This project is pre-configured for instant deployment on [Vercel](https://vercel.com):
```bash
# Using Vercel CLI
npm i -g vercel
vercel --prod
```
See the full [Vercel Deployment Guide](docs/deployment_guide_vercel.md) for GitHub auto-deployment steps.

---

## 🖥️ Demonstration & CLI Commands

You can run each of the 6 required demo scenarios directly via `main.py`:

```bash
# Demo Run 1: Honest session end-to-end (measurement outcomes, mismatch count, P_forge bound)
python main.py --demo honest

# Demo Run 2: Adversarial Random Forgery Attack Detection
python main.py --demo forgery

# Demo Run 3: Session & Nonce Replay Attack Defense
python main.py --demo replay

# Demo Run 4: Channel Disturbance & Wilson Score QBER Quarantine
python main.py --demo channel

# Demo Run 5: Pauli Syndrome Tampering Rejection
python main.py --demo pauli

# Demo Run 6: Automated Parameter Sweep & Official Deliverables Generation
python main.py --demo sweep

# Run All Demos Sequentially
python main.py --demo all
```

---

## 🌐 Interactive Cyber-Quantum SOC Dashboard

Launch the live interactive web dashboard:
```bash
python main.py --serve
```
Open **`http://127.0.0.1:8000`** in any modern web browser to access:
- Live protocol and attack simulation controls
- Real-time teleportation and Pauli correction state visualizer
- Dynamic Binomial and Wilson score QBER metric monitors
- SHA3-256 hash-chained tamper-evident audit feed
- One-click PDF / JSON report downloads

---

## 🧪 Automated Test Suite

Run the full pytest suite covering protocol correctness, classical crypto, statistical bounds, and all 10 attack scenarios:

```bash
pytest tests/ -v
```

All 10 attack scenarios are tested to guarantee:
- **Detection Rate $\ge 95\%$**
- **False Alert Rate $\le 5\%$**

---

## 📦 Deliverables Mapping (D1–D12)

| Deliverable ID | Description | Location / Artifact |
|---|---|---|
| **D1** | Requirements & Threat Model Document | [`docs/requirements_threat_model.md`](docs/requirements_threat_model.md) |
| **D2** | Teleportation-Based QDS Mathematical Model | [`docs/mathematical_spec.md`](docs/mathematical_spec.md) |
| **D3** | Quantum Protocol Simulation Module | [`protocol/`](protocol/) |
| **D4** | QDS Generation & Verification Module | [`protocol/signature_generation.py`](protocol/signature_generation.py), [`protocol/signature_verification.py`](protocol/signature_verification.py) |
| **D5** | Non-AI Threat Detection Engine | [`detection/`](detection/) |
| **D6** | Attack Simulation Suite (10 Scenarios) | [`attacks/`](attacks/), [`evaluation/reports/attack_results.json`](evaluation/reports/attack_results.json) |
| **D7** | Classical Security-Control Layer (ML-KEM) | [`security/`](security/) |
| **D8** | Security Analysis Report | [`evaluation/reports/security_analysis.pdf`](evaluation/reports/security_analysis.pdf) |
| **D9** | Performance Evaluation Report | [`evaluation/reports/performance_benchmarks.pdf`](evaluation/reports/performance_benchmarks.pdf) |
| **D10** | Test Suite & Reproducibility Package | [`tests/`](tests/) |
| **D11** | Technical Documentation & User Guide | [`README.md`](README.md) |
| **D12** | Interactive Demonstration & SOC Dashboard | [`main.py`](main.py), [`web/`](web/) |
