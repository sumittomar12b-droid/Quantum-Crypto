# 🔐 Technical Design Document
## Quantum-Inspired Cyber Threat Detection for Teleportation-Based QDS Systems
### SIH 2026 — Complete Architecture & Phase-by-Phase Specification

---
---

# 📄 PAGE 1 — FULL SYSTEM ARCHITECTURE

---

## System Overview

We build a **quantum-protocol simulator + deterministic statistics-based threat-detection framework** for a selected teleportation-based Quantum Digital Signature (QDS) design, with a **ML-KEM secured classical control plane**.

> **Security boundary**: Information-theoretic security holds only under the protocol's explicit assumptions — authenticated classical comms, trusted endpoints, correct state preparation, bounded noise model, and appropriate thresholds. The software simulator does not itself provide real-world IT-security; it models and validates the protocol.

---

## Complete System Architecture

```
╔══════════════════════════════════════════════════════════════════════════╗
║                     LAYER 1: PROTOCOL CONFIGURATION                     ║
║  Signature length L │ Noise model ε │ Thresholds t │ Policy version      ║
║  Protocol variant   │ Bell-pair fidelity F │ Session parameters          ║
╚═══════════════════════════════╦══════════════════════════════════════════╝
                                ║
╔═══════════════════════════════╩══════════════════════════════════════════╗
║           LAYER 2: TELEPORTATION-BASED QDS PROTOCOL SIMULATOR           ║
║                                                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │ ALICE (Signer)          QUANTUM CHANNEL         BOB / CHARLIE   │    ║
║  │                                                 (Verifiers)     │    ║
║  │  Bell Pair Gen ─────── entangled |Φ+⟩ ────────► Distribution   │    ║
║  │  Eigenstate Prep                                                │    ║
║  │  Signature Gen                                                  │    ║
║  │  Bell Measurement ──── 2 classical bits ──►  ML-KEM encrypt     │    ║
║  │                           m1, m2             │  ↓               │    ║
║  │                                              │  Decrypt m1,m2   │    ║
║  │                                              │  Pauli Correct   │    ║
║  │                                              │  Project. Meas.  │    ║
║  │  ◄───────── Encrypted cipher comms ──────────┘  (ML-KEM)        │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
║                                                                          ║
║   ┌──────────────────────┐         ┌────────────────────────────────┐   ║
║   │  Honest Protocol     │         │   Attack Injection Engine      │   ║
║   │  sign/distribute/    │         │   forge / replay / MITM /      │   ║
║   │  verify              │         │   intercept / tamper / DoS     │   ║
║   └──────────┬───────────┘         └────────────────┬───────────────┘   ║
║              └──────────────────┬──────────────────┘                   ║
╚════════════════════════════════╦═════════════════════════════════════════╝
                                 ║
╔════════════════════════════════╩═════════════════════════════════════════╗
║                   LAYER 3: STATISTICAL THREAT DETECTOR                  ║
║                                                                          ║
║   ┌──────────────────┐  ┌──────────────┐  ┌────────────────────────┐   ║
║   │ Bell Correlation │  │ QBER Monitor │  │  Pauli Consistency     │   ║
║   │ Checker          │  │ + Conf.Bound │  │  Checker               │   ║
║   └────────┬─────────┘  └──────┬───────┘  └──────────┬─────────────┘   ║
║            │                   │                      │                  ║
║   ┌────────▼───────────────────▼──────────────────────▼─────────────┐   ║
║   │              Binomial Threat Model Engine                        │   ║
║   │   M ~ Binomial(L, q)                                             │   ║
║   │   P_forge = Σ C(L,k) · q_adv^k · (1-q_adv)^(L-k), k=0..t       │   ║
║   │   P_false_reject = 1 - Σ C(L,k) · q_hon^k · (1-q_hon)^(L-k)    │   ║
║   └────────────────────────────┬────────────────────────────────────┘   ║
║                                │                                         ║
║   ┌────────────────────────────▼────────────────────────────────────┐   ║
║   │            Threshold Engine + Rule Evaluator                    │   ║
║   │   Forgery │ Impersonation │ Replay │ Unauth. Verif. │ Tamper    │   ║
║   │   Channel MITM │ Intercept-Resend │ Ent. Disruption │ DoS       │   ║
║   └────────────────────────────┬────────────────────────────────────┘   ║
╚════════════════════════════════╦════════════════════════════════════════╝
                                 ║
╔════════════════════════════════╩════════════════════════════════════════╗
║             LAYER 4: SECURITY CONTROLS, EVIDENCE & REPORTING           ║
║                                                                         ║
║  ┌──────────────────┐  ┌─────────────────┐  ┌───────────────────────┐  ║
║  │ ML-KEM-768       │  │ Session / Nonce │  │ Identity & Role       │  ║
║  │ Classical Comms  │  │ Management      │  │ Authorization Policy  │  ║
║  │ (m1, m2, cipher) │  │ Replay Protect  │  │                       │  ║
║  └──────────────────┘  └─────────────────┘  └───────────────────────┘  ║
║                                                                         ║
║  ┌──────────────────────────────────────────────────────────────────┐   ║
║  │  Tamper-Evident Audit Log │ Alert Feed │ Attack Classification   │   ║
║  │  Metrics Engine │ PDF/JSON Reports │ Web Dashboard               │   ║
║  └──────────────────────────────────────────────────────────────────┘   ║
╚═════════════════════════════════════════════════════════════════════════╝
```

---

## ML-KEM Integration in the Classical Channel

```
Alice                                         Bob
  │                                             │
  │  ① Bob publishes ML-KEM-768 public key      │
  │◄────────────────── pk_bob ──────────────────│
  │                                             │
  │  ② Alice encapsulates shared secret         │
  │  (ciphertext, K) = ML-KEM.Encaps(pk_bob)   │
  │  ─────────────── ciphertext ──────────────►│
  │                                             │
  │  ③ Bob decapsulates                         │
  │              K = ML-KEM.Decaps(sk_bob, ct) │
  │                                             │
  │  ④ Derive symmetric key                     │
  │  K_sym = HKDF(K, session_id, "QDS-v1")     │
  │                                             │
  │  ⑤ Encrypt correction bits + metadata      │
  │  enc_m = AES-256-GCM(K_sym, {m1, m2,       │
  │          nonce, timestamp, session_id})     │
  │  ─────────────── enc_m ───────────────────►│
  │                                             │
  │  ⑥ Bob's cipher comms (verification result,│
  │     audit events) also encrypted under K_sym│
  │◄──────────────── enc_reply ─────────────── │
```

**Why ML-KEM here specifically:**
- m1, m2 are the 2 classical bits Alice sends after Bell measurement — essential for Pauli correction
- A quantum adversary intercepting these can manipulate corrections → effectively a Pauli-tampering attack
- ML-KEM (FIPS 203) is quantum-resistant by design — lattice hardness survives Shor's algorithm
- Fresh encapsulation per session → forward secrecy at session level
- Python: `liboqs-python` (Open Quantum Safe) provides ML-KEM-512/768/1024

---

## Three-Party Session Binding Schema

```
session_id          = UUID4 (cryptographically random)
signer_id           = Alice's authenticated identity
recipient_id        = Bob's / Charlie's identity
message_digest      = SHA3-256(message)
signature_resource_id = UUID4 per signing event
nonce               = 256-bit CSPRNG value (one-time)
timestamp           = ISO-8601 with nanosecond precision
expiry              = timestamp + session_TTL
protocol_version    = "teleportation-qds-v1.0"
threshold_policy_version = "policy-v1.2"
ml_kem_ciphertext   = ML-KEM encapsulation of session key
```

---

## Threat Detection at a Glance

| Threat | Detection Signal | Rule |
|---|---|---|
| **Forgery** | Mismatch count M vs threshold t | Reject if M > t; report P_forge bound |
| **Impersonation** | Session/identity binding failure | Reject before quantum stage |
| **Replay** | Reused nonce / session ID / resource | Block + log prior event ref |
| **Unauth. Verification** | Policy violation / expired session | Deny + alert |
| **Channel Manipulation** | QBER upper confidence bound > ε_max | Quarantine session |
| **Pauli Tampering** | Bell outcome ≠ recorded correction | Reject teleportation transcript |
| **Intercept-Resend** | Basis disagreement rate spike | Channel-compromise alert |
| **Entanglement Disruption** | Bell correlation failure | Flag Bell pair as compromised |
| **DoS** | Verification flood / abnormal latency | Rate-limit + classify |

---
---

# 📄 PAGE 2 — PROJECT PHASES OVERVIEW

---

## Phase Map

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   PHASE 1    │   │   PHASE 2    │   │   PHASE 3    │
│ Requirements │──►│ Mathematical │──►│  Simulator + │
│ & Threat     │   │  Protocol    │   │  Security    │
│  Model       │   │    Spec      │   │  Controls    │
└──────────────┘   └──────────────┘   └──────┬───────┘
                                              │
┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐
│   PHASE 6    │   │   PHASE 5    │   │   PHASE 4    │
│  Harden +    │◄──│  Evaluation  │◄──│   Attack     │
│    Demo      │   │  & Benchmarks│   │  Simulation  │
└──────────────┘   └──────────────┘   └──────────────┘
```

| Phase | Focus | Primary Output |
|---|---|---|
| **Phase 1** | Scope, threat model, protocol selection | Threat model doc + parameter table |
| **Phase 2** | Math formulation, pseudocode | Protocol spec document (equations + flow) |
| **Phase 3** | Simulator + ML-KEM classical layer | `protocol/` + `security/` modules, passing tests |
| **Phase 4** | Attack injection suite | `attacks/` module, 10 attack scenarios |
| **Phase 5** | Security + performance sweep | Benchmarks, graphs, security analysis report |
| **Phase 6** | Hardening, reproducibility, final demo | Final codebase, docs, demo recording |

---
---

# 📄 PAGE 3 — PHASE 1: Requirements, Scope & Threat Model

---

## Phase 1 — What It Is

Phase 1 is the **planning + scoping phase**. No code is written. Its output is a set of documents that define the exact problem boundaries. Without this, the implementation will drift or overclaim.

---

## Phase 1 — Part A: Protocol Selection

**Decision to make:** Choose exactly ONE teleportation-based QDS variant.

| Candidate | Key Characteristics | Decision Factors |
|---|---|---|
| **Dunjko et al. 2014** | First practical QDS; well-cited; clear security proofs | Best documented; most implementable |
| **Yin et al.** | Explicitly uses quantum teleportation; 3-party (Alice-Bob-Charlie) | Closest match to statement |
| **Clarke et al. 2012** | Experimental realization; hardware-focused | Less suitable for simulator-first |
| **GV-QDS** | Theoretical foundation; complex | Rigorous but harder to implement cleanly |

**Action:** Read Dunjko et al. 2014 and Yin et al. Confirm:
- Does it use Bell-state entanglement?
- Does it use quantum teleportation explicitly?
- Does it have a 3-party (Alice, Bob, Charlie) structure?
- Are Pauli eigenstates part of the signature scheme?

Select whichever satisfies all four. **Document the choice and citation.**

---

## Phase 1 — Part B: Threat Model Document

**The threat model must explicitly classify every threat:**

```
┌─────────────────────────────────────────────────────────┐
│                   THREAT CLASSIFICATION                 │
├──────────────────────┬──────────────────────────────────┤
│ PREVENTED            │ DETECTED                         │
│ (system blocks it)   │ (system raises alert)            │
├──────────────────────┼──────────────────────────────────┤
│ Replay attacks        │ Forgery attempts                 │
│ (session binding)     │ (statistical mismatch)          │
│ Unauthorized verif.   │ Impersonation                    │
│ (role policy)         │ (session binding failure)        │
│ Pauli-op tampering    │ Channel manipulation (QBER)      │
│ (correction check)    │ Intercept-resend (basis rate)   │
│                       │ Entanglement disruption          │
│                       │ DoS (rate limiting)              │
├──────────────────────┼──────────────────────────────────┤
│ OUT OF SCOPE                                            │
│ Compromised endpoints (Alice's device is trusted)       │
│ Biased randomness source                                │
│ Side-channel attacks on classical hardware              │
│ Fault-tolerant quantum computer breaking ML-KEM         │
│ Physical layer attacks on fiber/free-space channel      │
└─────────────────────────────────────────────────────────┘
```

**Attacker capability model:**

| Attacker Type | Capabilities | What They Can Do |
|---|---|---|
| **Passive eavesdropper** | Intercepts quantum + classical channel | Cannot forge without detectable disturbance |
| **Active MITM** | Intercepts + modifies quantum states | Detected via QBER / correlation check |
| **Informed forger** | Has bounded partial key info | P_forge still bounded by Binomial model |
| **Replay attacker** | Has old valid transcript | Blocked by nonce + session consumption |
| **Insider / Unauth. verifier** | Has network access but wrong role | Blocked by role policy |

**Parameter table (to be filled in Phase 2):**

| Parameter | Symbol | Range to sweep | Notes |
|---|---|---|---|
| Signature length | L | 50–1000 | Determines P_forge |
| Acceptance threshold | t | f(L, q) | Optimize in Phase 5 |
| Honest mismatch prob. | q_honest | 0.01–0.15 | Noise model dependent |
| Adversary mismatch prob. | q_adv | 0.25–0.50 | Protocol-dependent bound |
| QBER threshold | ε_max | 0.11 (BB84 analog) | Configurable |
| Session TTL | — | 60–600 s | Operational requirement |
| ML-KEM level | — | ML-KEM-768 | NIST Level 3 |

---
---

# 📄 PAGE 4 — PHASE 2: Mathematical Protocol Specification

---

## Phase 2 — What It Is

Phase 2 produces **equations and pseudocode for every protocol step before any code is written**. This is the mathematical contract the simulator must implement.

---

## Phase 2 — Part A: Protocol Steps (Full Flow)

### Step 1: Bell-Pair Generation
Alice (or a trusted source) generates entangled Bell pairs:
$$|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$$
Each pair is assigned a `signature_resource_id` and logged.

### Step 2: Signature-State Encoding
Alice encodes message M using Pauli eigenstates chosen per the selected protocol:
- Z-basis: $|0\rangle$, $|1\rangle$
- X-basis: $|+\rangle = \frac{|0\rangle+|1\rangle}{\sqrt{2}}$, $|-\rangle = \frac{|0\rangle-|1\rangle}{\sqrt{2}}$
- Y-basis: $|i+\rangle$, $|i-\rangle$

Signature string: $S = (s_1, s_2, \ldots, s_L)$ where each $s_i \in \{|0\rangle, |1\rangle, |+\rangle, |-\rangle, \ldots\}$

### Step 3: Quantum Resource Distribution
Bob and Charlie each receive one qubit from each entangled pair. Distribution is:
- Recorded in session binding schema
- Authenticated via classical channel (ML-KEM encrypted)

### Step 4: Quantum Teleportation
Alice teleports her signature state to Bob using:
1. Alice performs **Bell-basis measurement** on her qubit + signature qubit
2. Gets 2 classical bits: $m_1, m_2 \in \{0,1\}$
3. Encrypts $(m_1, m_2)$ with ML-KEM session key → sends to Bob
4. Bob decrypts, applies **Pauli correction**:

$$\text{Correction} = \begin{cases} I & m_1=0, m_2=0 \\ X & m_1=0, m_2=1 \\ Z & m_1=1, m_2=0 \\ iY & m_1=1, m_2=1 \end{cases}$$

### Step 5: Projective Measurement
Bob performs projective measurement in the basis matching the expected signature element:
- Measures $|+\rangle$ / $|-\rangle$ → X-basis
- Measures $|0\rangle$ / $|1\rangle$ → Z-basis
- Records outcome + basis + matches expected element?

### Step 6: Threshold Decision
Count mismatches $M$ across all $L$ signature elements:
$$\text{Accept if } M \leq t, \quad \text{Reject if } M > t$$

### Step 7: Resource Consumption
- Mark `signature_resource_id` as consumed
- Write audit event to tamper-evident log
- Expire session

---

## Phase 2 — Part B: Threat Detection Mathematics

### Binomial Threat Model

$$M \sim \text{Binomial}(L, q)$$

**Forgery success probability:**
$$P_{\text{forge}} = \sum_{k=0}^{t} \binom{L}{k} q_{\text{adv}}^k (1 - q_{\text{adv}})^{L-k}$$

**False-rejection probability:**
$$P_{\text{false reject}} = 1 - \sum_{k=0}^{t} \binom{L}{k} q_{\text{honest}}^k (1 - q_{\text{honest}})^{L-k}$$

**Selection criterion:**
$$P_{\text{forge}} \leq 10^{-6}, \quad P_{\text{false reject}} \leq \delta_{\text{ops}}, \quad P_{\text{false accept}} \leq 10^{-6}$$

### QBER Estimation

$$\hat{Q} = \frac{N_{\text{disagree}}}{N_{\text{total test}}}$$

Compute Wilson score upper confidence bound at 99% confidence.
If upper bound $> \varepsilon_{\max}$ → quarantine + alert.

### Pauli Correction Consistency

For each teleportation event, verify:
$$\text{outcome}_{\text{Bob}} \stackrel{?}{=} f(\text{Bell measurement result}, \text{Pauli correction applied})$$

Inconsistency → tampered correction bits → Pauli-tampering alert.

### Complexity

$$\mathcal{O}(L) \text{ per verification} \quad (\text{linear in signature length})$$

---
---

# 📄 PAGE 5 — PHASE 3: Simulator + Security Controls

---

## Phase 3 — What It Is

Phase 3 is the **core build phase**. It implements the mathematical spec from Phase 2 as clean, tested, reproducible Python modules. It also builds the ML-KEM classical security layer.

---

## Phase 3 — Part A: Quantum Simulator Modules

### `protocol/bell_pair_generation.py`
```
Functions:
  generate_bell_pair(type: str) → QuantumCircuit
    types: "phi_plus", "phi_minus", "psi_plus", "psi_minus"
  generate_session_bell_pairs(L: int, session_id: str) → List[BellPair]

Backed by: Qiskit Aer statevector simulator
Output: Quantum circuits + measurement distributions
```

### `protocol/teleportation.py`
```
Functions:
  teleport(qubit: QuantumState, bell_pair: BellPair) → (m1: int, m2: int)
  apply_pauli_correction(state: QuantumState, m1: int, m2: int) → QuantumState

Notes:
  - m1, m2 MUST be passed through ML-KEM encrypted channel
  - Raw bits never travel in plaintext
```

### `protocol/signature_generation.py`
```
Functions:
  generate_signature(message: bytes, key_material: KeyMaterial, L: int) → SignatureString
  encode_as_pauli_eigenstates(sig: SignatureString) → List[QuantumState]
```

### `protocol/signature_verification.py`
```
Functions:
  verify(received_states: List[QuantumState], expected_sig: SignatureString, t: int) 
       → VerificationResult(accepted: bool, mismatch_count: int, p_forge: float)
```

---

## Phase 3 — Part B: ML-KEM Classical Security Layer

### `security/classical_auth_interface.py`
```
Dependencies: liboqs-python (Open Quantum Safe)
Algorithm:   ML-KEM-768 (FIPS 203, NIST Level 3)

Functions:
  generate_keypair() → (pk: bytes, sk: bytes)
  encapsulate(pk: bytes) → (ciphertext: bytes, shared_secret: bytes)
  decapsulate(sk: bytes, ciphertext: bytes) → shared_secret: bytes
  derive_session_key(shared_secret, session_id, label) → AES-256-GCM key
  encrypt_classical_message(key, plaintext, nonce, aad) → ciphertext
  decrypt_classical_message(key, ciphertext, nonce, aad) → plaintext
```

### `security/session_nonce_management.py`
```
Functions:
  create_session(signer_id, recipient_id, message_digest, expiry_secs) → SessionBinding
  consume_resource(session_id, resource_id) → bool  # False = already consumed (replay)
  is_session_valid(session_id) → bool               # Checks expiry + consumption
  get_session(session_id) → SessionBinding
```

### `security/audit_log.py`
```
Format: JSONL — one event per line, append-only
Tamper evidence: Each entry includes SHA3-256(previous_entry || current_entry)
                 (hash chain — detects any tampering or deletion)

Events logged:
  SESSION_CREATED, SIGNATURE_GENERATED, VERIFICATION_ATTEMPTED,
  VERIFICATION_ACCEPTED, VERIFICATION_REJECTED,
  ATTACK_DETECTED, RESOURCE_CONSUMED, SESSION_EXPIRED,
  REPLAY_BLOCKED, POLICY_VIOLATION, QBER_ALERT
```

---
---

# 📄 PAGE 6 — PHASE 4: Attack Simulation Suite

---

## Phase 4 — What It Is

Phase 4 builds the **attack injection engine** — 10 controlled attack scenarios that test every detector in Phase 3. Each attack has a defined injection point, expected measurement signal, and a pre-specified detector rule.

---

## Phase 4 — Part A: Attack Catalog

### Attack 1 — Random Forgery (`attacks/random_forger.py`)
```
What: Attacker fabricates random signature elements
Injection point: Replaces signature states with random Pauli eigenstates
Expected signal: M >> t (mismatch count far exceeds threshold)
Mathematical expectation: q_adv ≈ 0.5 → P_forge ≈ 0 for L ≥ 100
Detector: Binomial threshold check → REJECT
```

### Attack 2 — Informed Forgery (`attacks/informed_forger.py`)
```
What: Attacker has partial information (e.g., knows some eigenstate basis choices)
Injection point: Replaces known-basis elements correctly, guesses others
Expected signal: M > t but lower than random forgery
Expected signal: q_adv ≈ 0.25–0.35
Detector: Binomial bound still holds → REJECT
```

### Attack 3 — Signer Impersonation (`attacks/impersonator.py`)
```
What: Mallory creates a session as if she were Alice
Injection point: Session binding (signer_id field)
Expected signal: Identity/session binding failure
Detector: session_nonce_management.is_session_valid() → REJECT before quantum stage
```

### Attack 4 — Replay Attack (`attacks/replay_attacker.py`)
```
What: Re-submits a previously valid session transcript
Injection point: Re-sends old {session_id, nonce, resource_id, enc_m}
Expected signal: Resource already consumed flag
Detector: consume_resource() returns False → REPLAY_BLOCKED + log prior event ref
```

### Attack 5 — Unauthorized Verification (`attacks/unauthorized_verifier.py`)
```
What: Invalid recipient or unauthorized role attempts verification
Injection point: Verification request from wrong recipient_id
Expected signal: Policy violation
Detector: identity_and_role_policy check → POLICY_VIOLATION alert
```

### Attack 6 — Pauli-Operation Tampering (`attacks/pauli_tamperer.py`)
```
What: Intercepts ML-KEM-encrypted m1,m2 → modifies corrections
Note: ML-KEM protects against this IF keys are uncompromised.
      Simulated by assuming attacker has compromised the key (worst case test)
Injection point: Flips/reorders m1, m2 bits after decryption
Expected signal: Pauli correction inconsistency
Detector: pauli_consistency_checker → REJECT teleportation transcript
```

### Attack 7 — Channel Disturbance (`attacks/channel_disturbance.py`)
```
What: Injects depolarizing noise or Pauli X/Y/Z errors into quantum channel
Injection point: Quantum state during transmission
Expected signal: QBER upper bound > ε_max
Detector: qber_estimation.upper_confidence_bound() > threshold → QBER_ALERT
Noise model: Qiskit Aer depolarizing_error(p) on each qubit
```

### Attack 8 — Intercept-Resend (`attacks/intercept_resend.py`)
```
What: Eve measures and re-prepares quantum states (cannot clone, so errors arise)
Injection point: Quantum channel — measures in random basis, re-sends
Expected signal: Basis disagreement rate ≈ 25% (for random basis choice)
Detector: correlation_analysis.basis_disagreement_rate() > threshold → ALERT
Physics: No-cloning theorem ensures detectable disturbance
```

### Attack 9 — Entanglement Disruption (`attacks/entanglement_disruptor.py`)
```
What: Substitutes or corrupts Bell pairs (e.g., swaps |Φ+⟩ with |Φ-⟩)
Injection point: Bell pair distribution phase
Expected signal: Bell-state correlation check fails
Detector: correlation_analysis.verify_bell_state_fidelity() < threshold → FLAG
```

### Attack 10 — DoS / Availability Degradation (`attacks/dos_simulator.py`)
```
What: Floods verification requests, drops/delays messages
Injection point: API layer + session management
Expected signal: Rate limit exceeded, abnormal latency, preparation failures
Detector: Rate limiter triggers → AVAILABILITY_DEGRADATION classified + logged
```

---

## Phase 4 — Part B: Attack Runner

```python
# experiment harness for all attacks
for attack in [RandomForger, InformedForger, Impersonator, 
               ReplayAttacker, UnauthorizedVerifier, PauliTamperer,
               ChannelDisturbance, InterceptResend, 
               EntanglementDisruptor, DoSSimulator]:
    result = attack.run(L=200, noise=0.05, n_trials=1000, seed=42)
    assert result.detection_rate > 0.95     # Must detect > 95% of attacks
    assert result.false_positive_rate < 0.05 # Must not over-alert
    log_result(result)
```

---
---

# 📄 PAGE 7 — PHASE 5: Security & Performance Evaluation

---

## Phase 5 — What It Is

Phase 5 **sweeps the parameter space**, measures all metrics, and produces the security analysis + performance reports. This is what judges will look at to validate claims.

---

## Phase 5 — Part A: Experiment Parameter Space

| Parameter | Values to Sweep |
|---|---|
| Signature length L | 50, 100, 200, 500, 1000 |
| Noise level ε | 0.01, 0.05, 0.10, 0.15 |
| Attacker knowledge | random, partial (25%), partial (50%) |
| Threshold t | sweep around optimal t*(L, ε) |
| Bell-pair fidelity F | 0.90, 0.95, 0.99, 1.00 |
| Attack rate | 0%, 10%, 25%, 50% attack-injected sessions |
| n_trials per config | 1000 (with fixed seed for reproducibility) |

---

## Phase 5 — Part B: Metrics to Measure

**Security metrics:**
| Metric | Definition | Target |
|---|---|---|
| `P_forge` | Forgery success probability | ≤ 10⁻⁶ |
| `P_false_reject` | Legitimate sig wrongly rejected | ≤ 1% |
| `P_false_accept` | Forged sig wrongly accepted | ≤ 10⁻⁶ |
| `Detection rate` | Fraction of attacks detected | ≥ 95% |
| `False alert rate` | Legitimate sessions flagged | ≤ 5% |
| `QBER under attack` | QBER when channel disturbed | Spike detectable |

**Performance metrics:**
| Metric | Definition | Target |
|---|---|---|
| `Verification runtime` | Time per signature check | O(L) confirmed |
| `Detection latency` | Time from event to alert | < 100ms |
| `Memory consumption` | Peak RAM for L=1000 | < 1 GB |
| `Circuit depth` | Qiskit circuit depth | Logged |
| `Gate count` | Total quantum gates | Logged |
| `Qubit count` | Qubits used per session | Logged |

---

## Phase 5 — Part C: Report Outputs

```
evaluation/reports/
├── security_analysis.pdf     ← P_forge curves, QBER bounds, protocol assumptions
├── performance_benchmarks.pdf ← Scaling plots, latency, memory usage
├── attack_results.json       ← Per-attack detection rates + false alert rates
└── threshold_optimization.pdf ← Optimal t vs L heatmap
```

**Key plots:**
- `P_forge vs L` (for various q_adv) — shows security scales with L
- `P_false_reject vs L` (for various noise ε) — shows reliability
- `QBER distribution: honest vs attacked` — shows separability
- `Detection rate per attack type` — bar chart, all 10 attacks
- `Verification runtime vs L` — confirms O(L) complexity

---
---

# 📄 PAGE 8 — PHASE 6: Hardening, Reproducibility & Demo

---

## Phase 6 — What It Is

Phase 6 **hardens the codebase**, ensures full reproducibility, and prepares the final demonstration and project report.

---

## Phase 6 — Part A: Hardening Checklist

**Code quality:**
- [ ] All inputs validated + config files schema-checked
- [ ] Thresholds and protocol parameters are versioned YAML, not hardcoded
- [ ] No raw secrets or sensitive quantum-state metadata in logs
- [ ] Tamper-evident audit logs (hash chain verified on startup)
- [ ] ML-KEM keys rotated per session, never reused
- [ ] Rate limiter active on all public-facing endpoints

**Testing:**
- [ ] Unit tests: every function in `protocol/` + `detection/` + `security/`
- [ ] Integration tests: honest session end-to-end
- [ ] Attack tests: all 10 attack types, expected detection rate met
- [ ] Regression tests: fixed-seed results match reference outputs

**Documentation:**
- [ ] Architecture doc (this document)
- [ ] API reference (FastAPI auto-docs + Swagger)
- [ ] Installation guide (fresh env → running in < 10 min)
- [ ] Known limitations + assumptions section

---

## Phase 6 — Part B: Demo Script

**Minimum demo required (judges must see all of these):**

```
Demo Run 1: Honest session
  Alice signs message M, Bob verifies → ACCEPTED (within threshold)
  Show: measurement outcomes, mismatch count, P_forge bound

Demo Run 2: Forgery attack
  Eve submits random signature → REJECTED
  Show: mismatch count >> t, alert generated, audit log entry

Demo Run 3: Replay attack
  Old valid session re-submitted → BLOCKED
  Show: nonce/resource already consumed, replay alert logged

Demo Run 4: Channel disturbance
  Depolarizing noise injected → QBER alert → session quarantined
  Show: QBER upper bound > ε_max, session flagged

Demo Run 5: Pauli tampering
  m1/m2 flipped → correction inconsistency → transcript rejected
  Show: Pauli consistency check failure

Demo Run 6: Parameter sweep (automated)
  Sweep L ∈ {50,100,200} with n=1000 trials → P_forge curve plotted live
```

---
---

# 📄 PAGE 9 — DELIVERABLES & SUCCESS CRITERIA

---

## Delivery Table (D1–D12)

| ID | Deliverable | Format |
|---|---|---|
| **D1** | Requirements & Threat Model Document | PDF + threat-model diagram |
| **D2** | Teleportation-Based QDS Mathematical Model | PDF (equations + pseudocode) |
| **D3** | Quantum Protocol Simulation Module | Python (`protocol/`) |
| **D4** | QDS Generation & Verification Module | Python (`protocol/signature_*.py`) |
| **D5** | Non-AI Threat Detection Engine | Python (`detection/`) |
| **D6** | Attack Simulation Suite (10 types) | Python (`attacks/`) |
| **D7** | Classical Security-Control Layer (ML-KEM) | Python (`security/`) |
| **D8** | Security Analysis Report | PDF + plots |
| **D9** | Performance Evaluation Report | PDF + CSV benchmarks |
| **D10** | Test Suite & Reproducibility Package | pytest + YAML configs |
| **D11** | Technical Documentation & User Guide | Markdown + Swagger |
| **D12** | Final Demonstration & Project Report | Recording + PDF + source |

---

## 9 Success Criteria (All Must Pass)

| # | Criterion | How Verified |
|---|---|---|
| 1 | Legitimate signature accepted with bounded probability | Demo Run 1 + P_false_reject curve |
| 2 | Forged signatures rejected with measurable bounded P_forge | Demo Run 2 + security report |
| 3 | Replay attempts fail via session/resource consumption | Demo Run 3 + audit log |
| 4 | Impersonation + unauth. verification blocked before quantum stage | Attack tests 3 + 5 |
| 5 | Intercept-resend, Pauli tampering, channel disturbance produce detectable signals | Demo Runs 4 + 5, Attack tests 6 + 8 |
| 6 | All threshold decisions are explainable from data + math | Each alert cites exact rule + values |
| 7 | Zero ML/AI components in detection pipeline | Code audit — no sklearn/torch/etc. |
| 8 | All experiments reproducible from fixed seeds | Regression test suite passes |
| 9 | Classical control plane uses ML-KEM; supports PQC migration | `security/classical_auth_interface.py` |

---
---

# 📄 PAGE 10 — TECHNOLOGY STACK & OPEN QUESTIONS

---

## Full Technology Stack

| Component | Technology | Version / Notes |
|---|---|---|
| Quantum simulation | Qiskit + Qiskit Aer | `qiskit >= 1.0`, `qiskit-aer >= 0.13` |
| Quantum math | QuTiP | Density matrices, open quantum systems |
| PQC / ML-KEM | `liboqs-python` (Open Quantum Safe) | ML-KEM-768 (FIPS 203) |
| Numerical | NumPy + SciPy | Binomial CDF, confidence intervals |
| Statistics | SciPy stats | Wilson score confidence bounds |
| Backend API | FastAPI + Uvicorn | Async, auto-docs |
| Visualization | Matplotlib + Plotly | Static + interactive plots |
| Dashboard | HTML5 + Vanilla JS | No framework dependency |
| Reporting | ReportLab + Jinja2 | PDF generation |
| Testing | pytest + hypothesis | Property-based + unit |
| Logging | Python logging + custom hash-chain | Tamper-evident JSONL |
| Config | PyYAML + pydantic | Schema-validated configs |
| Language | Python 3.11+ | Type hints throughout |

---

## Open Questions (Action Required)

> [!IMPORTANT]
> **Q1 — Protocol Selection**: Which teleportation-based QDS variant? Recommend reading Dunjko et al. 2014 and Yin et al. before Phase 2 begins. Decision must be documented with citation.

> [!IMPORTANT]
> **Q2 — ML-KEM Key Distribution**: How does Bob get Alice's ML-KEM public key initially? Options: (a) pre-shared via trusted setup, (b) distributed via an authenticated quantum channel bootstrap. This affects the session initialization flow.

> [!NOTE]
> **Q3 — Dashboard scope**: Full interactive web dashboard or CLI + static PDF reports for the demo? Full dashboard takes ~1.5x more time to build.

> [!NOTE]
> **Q4 — Charlie's role depth**: Does Charlie independently run the full verification pipeline, or only receive transferability proofs from Bob? This affects the `verifier.py` module design.
