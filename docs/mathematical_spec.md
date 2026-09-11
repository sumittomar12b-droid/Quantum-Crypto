# Deliverable D2: Teleportation-Based QDS Mathematical Specification

---

## 1. Quantum State Preparation & Quantum Teleportation

### 1.1 Bell State Generation
Entangled Bell pairs $|\Phi^+\rangle$ are shared between Alice and the verifiers (Bob and Charlie):
$$|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$$

Density matrix representation:
$$\rho_{\Phi^+} = |\Phi^+\rangle\langle\Phi^+|$$

### 1.2 Pauli Eigenstate Signature Encoding
For message digest $H = \text{SHA3-256}(M)$, Alice encodes a signature string $S = (s_1, s_2, \ldots, s_L)$ where each element $s_k$ is prepared as a Pauli eigenstate:
- Computational $Z$-basis: $\{|0\rangle, |1\rangle\}$
- Hadamard $X$-basis: $\{|+\rangle = \frac{|0\rangle+|1\rangle}{\sqrt{2}}, |-\rangle = \frac{|0\rangle-|1\rangle}{\sqrt{2}}\}$
- Phase $Y$-basis: $\{|i+\rangle = \frac{|0\rangle+i|1\rangle}{\sqrt{2}}, |i-\rangle = \frac{|0\rangle-i|1\rangle}{\sqrt{2}}\}$

### 1.3 Teleportation Protocol Steps
1. Alice performs a joint **Bell-State Measurement (BSM)** on her signature qubit $|\psi\rangle$ and her half of the Bell pair.
2. The BSM yields two classical measurement bits $(m_1, m_2) \in \{0, 1\}^2$.
3. Classical bits $(m_1, m_2)$ are transmitted over the ML-KEM-768 secured classical channel.
4. Bob applies the unitary Pauli correction $\sigma(m_1, m_2)$:
$$\sigma(m_1, m_2) = Z^{m_1} X^{m_2}$$
   - $(0,0) \implies I$
   - $(0,1) \implies X$
   - $(1,0) \implies Z$
   - $(1,1) \implies Z X = -iY$
5. Bob performs a projective measurement in the expected basis.

---

## 2. Statistical Threat Detection Mathematics

### 2.1 Binomial Threat Model
Let $L$ be the signature length, and $M$ be the total number of mismatched outcomes observed during verification.
Under independent measurements:
$$M \sim \text{Binomial}(L, q)$$

- **Honest Protocol**: $q = q_{\text{honest}} \approx \varepsilon$ (environmental noise error rate).
- **Adversarial Forgery**: $q = q_{\text{adv}} \ge 0.25$ (due to quantum state disturbance and no-cloning theorem).

### 2.2 Forgery Success Probability ($P_{\text{forge}}$)
For an acceptance threshold $t$:
$$P_{\text{forge}} = \sum_{k=0}^{t} \binom{L}{k} q_{\text{adv}}^k (1 - q_{\text{adv}})^{L-k} = I_{1 - q_{\text{adv}}}(L - t, t + 1)$$
where $I_x(a, b)$ is the Regularized Incomplete Beta Function.

### 2.3 False Rejection Probability ($P_{\text{false reject}}$)
$$P_{\text{false reject}} = 1 - \sum_{k=0}^{t} \binom{L}{k} q_{\text{honest}}^k (1 - q_{\text{honest}})^{L-k}$$

### 2.4 Wilson Score Upper Confidence Bound for QBER
Given $k$ bit errors observed across $n$ test pairs, the sample error rate is $\hat{p} = \frac{k}{n}$.
The Wilson score upper confidence bound at confidence level $1 - \alpha$ (standard normal quantile $z = \Phi^{-1}(1 - \alpha/2)$):
$$\text{UCB}_{1-\alpha}(p) = \frac{\hat{p} + \frac{z^2}{2n} + z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
If $\text{UCB}_{0.99}(p) > \varepsilon_{\max}$, the channel is quarantined immediately.

### 2.5 Transferability & Non-Repudiation (3-Party Guarantee)
To guarantee that Bob cannot accept a signature that Charlie would reject (or vice versa):
$$\text{Acceptance Threshold } t_{\text{Bob}} = t_{\text{Charlie}} = t$$
$$\text{Transferability Threshold } t_{\text{trans}} = t + \Delta$$
Where $\Delta = \frac{1}{2}(q_{\text{adv}} - q_{\text{honest}}) L$. If $|M_{\text{Bob}} - M_{\text{Charlie}}| > \Delta$, arbitrator flags an asymmetry attempt.
