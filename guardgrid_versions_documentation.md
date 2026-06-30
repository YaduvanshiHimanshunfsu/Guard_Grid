# GuardGrid Project Architecture & Evolution (V1, V2, V3)

## 1. Topic and Theme
**Topic:** Privacy-Preserving Smart Grid Data Aggregation.  
**Theme:** Evolving theoretical cryptographic models into robust, fault-tolerant, and quantum-resistant architectures for real-world smart grid deployments (specifically targeting the Indian context like the RDSS).

---

## 2. Overview of Versions

### V1: The Research Demo
A direct implementation of the theoretical GuardGrid research paper. It proves that a Multi-Input Functional Encryption (MIFE) scheme combined with Diffie-Hellman (DH) session keys and Linear Homomorphic Hashing (LHH) can aggregate smart meter data securely. The gateway only sees the sum, never the individual readings. 

### V2: Advanced India Implementation
A fault-tolerant, utility-focused upgrade. Real-world grids are messy—meters drop offline, and utilities need 24-hour time-series data for billing and anomaly detection. V2 introduces a functional wrapper around V1 to handle missing meters (via dummy ciphertexts), calculate progressive billing tariffs (DERC), and detect statistical anomalies over time.

### V3: Advanced Security Concept (Proposed)
A next-generation security upgrade designed to address long-term systemic vulnerabilities. It focuses on replacing classical crypto with Post-Quantum Lattice-based cryptography, replacing the single-point-of-failure Trusted Third Party (TTP) with a Distributed Key Generation (DKG) network, injecting Differential Privacy noise to prevent N-1 collusion attacks, and padding traffic to prevent behavioral surveillance.

---

## 3. Pros and Cons of Each Version

| Version | Pros | Cons |
|---------|------|------|
| **V1** | - Mathematically pure to the research paper.<br>- Highly efficient for single-time-slot aggregation.<br>- Strong data confidentiality against honest-but-curious gateways. | - **Extremely fragile:** If one meter drops offline, the entire aggregation crashes.<br>- Lacks real-world utility features (no time-series, no billing).<br>- Vulnerable to quantum computers and N-1 collusion. |
| **V2** | - **Fault-Tolerant:** Can survive offline meters using dummy substitution.<br>- **Practical:** Simulates continuous 24-hour time-series data.<br>- Built-in Indian DERC tariff billing and anomaly detection. | - Still relies on classical cryptography (DH/DLP) which will eventually be broken by quantum computers.<br>- A hacked TTP still compromises the entire network. |
| **V3** | - **Quantum-Resistant:** Safe against "Store Now, Decrypt Later" attacks.<br>- **Privacy-Bound:** Differential privacy prevents individual targeting even if all neighbors collude.<br>- No single point of failure (decentralized TTP). | - **High Overhead:** Lattice cryptography requires more bandwidth and computing power.<br>- Complex to implement on low-power IoT meter hardware.<br>- Regulatory friction due to Differential Privacy noise. |

---

## 4. Why We Made V2 (Main Differences from V1)

**Why V2 was made:** V1 was an academic proof-of-concept. In an Indian smart grid (like RDSS), telecom networks are unreliable and meters frequently lose connection. V1 mathematically cannot function if $N$ ciphertexts are expected but only $N-1$ arrive. V2 was created to bridge the gap between theory and the harsh reality of deployment.

**Main Differences (V2 vs V1):**
1. **Fault Tolerance:** V2 introduces the "Threshold Substitution" concept. If a meter is offline, the Gateway injects a pre-calculated "Dummy Ciphertext" (decrypts to 0). The Control Center dynamically removes that offline meter's session key mask. V1 simply crashes in this scenario.
2. **Temporal Dynamics:** V1 calculates one snapshot in time. V2 runs a continuous time-series loop (e.g., 96 slots of 15 mins).
3. **Utility Logic:** V2 adds practical utility layers: progressive tariff calculation (billing) and rolling z-score anomaly detection.

---

## 5. File Breakdown: V1 vs V2

### Common Files (Core Cryptography - Both V1 & V2)

1. **`crypto/dh.py`**
   - **Working:** Generates 512-bit safe primes and handles Diffie-Hellman (DH) key exchange between meters and the CC.
   - **Concept:** Discrete Logarithm Problem (DLP). 
   - **Why:** Used to create a shared secret symmetric mask ($k_i$) that hides the MIFE ciphertext from the Aggregation Gateway.

2. **`crypto/mife_wrapper.py`**
   - **Working:** Wraps the `FeDamgardMulti` library. Handles Setup, Encrypt, Keygen, and Decrypt.
   - **Concept:** Multi-Input Functional Encryption (Inner Product).
   - **Why:** Allows the Aggregation Gateway to compute the sum of encrypted values without ever decrypting the individual meter values.

3. **`crypto/lhh.py`**
   - **Working:** Calculates homomorphic hashes $h_i = g^{m_i} \pmod p$ and multiplies them together to verify the aggregate.
   - **Concept:** Linear Homomorphic Hashing.
   - **Why:** Prevents a malicious Aggregation Gateway from tampering with the aggregate data. The CC verifies the math.

4. **`crypto/fefq.py`**
   - **Working:** Re-encrypts the decrypted aggregate for cloud storage. Supports evaluating $f(x) = ax + b$ on the ciphertext.
   - **Concept:** Functional Encryption for Function Queries (ElGamal-based).
   - **Why:** Allows the utility company to query the cloud for insights without giving the cloud access to raw power totals.

### Specific Files (V2 Advanced Additions)

1. **`utils/fault_handler.py` & `schemes/fehh_threshold.py`**
   - **Working:** Detects when a meter is offline, pulls a pre-encrypted 0-value "dummy ciphertext", and injects it into the MIFE buffer.
   - **Concept:** Threshold Substitution & Dynamic Mask Re-alignment.
   - **Why:** Solves the V1 fragility problem. Keeps the pipeline running even if Indian telecom networks drop meter packets.

2. **`data/timeseries_loader.py` & `schemes/timeseries_aggregator.py`**
   - **Working:** Feeds data in consecutive 15-minute chunks over a 24-hour loop, buffering state across time.
   - **Concept:** Time-Series Data Pipelines.
   - **Why:** Real grids don't operate on single snapshots. They need continuous daily load curves.

3. **`utils/anomaly_detector.py` & `utils/billing.py`**
   - **Working:** Tracks rolling mean/standard deviation (z-score) of the decrypted neighborhood aggregate. Applies progressive DERC tariff slabs to compute revenue.
   - **Concept:** Statistical Anomaly Detection (Z-Score) & Tiered Financial Logic.
   - **Why:** Proves that encrypted networks can still perform necessary utility operations (finding power theft, generating bills).

4. **`crypto/shamir.py`**
   - **Working:** Splits a secret into $n$ shares where any $t$ shares can reconstruct it.
   - **Concept:** Shamir's $(t, n)$ Secret Sharing.
   - **Why:** Introduced as a primitive to eventually decentralize the Trusted Third Party.

---

## 6. What problem of V1 did we solve in V2? (Summary)
**Problem in V1:** Zero fault tolerance and lack of real-world utility applicability.
**Solved in V2:** Implemented dummy ciphertext injection, allowing the MIFE algorithm to complete its inner product even with missing inputs. We brought the theoretical cryptography into a practical, continuous Indian smart grid context with billing and anomaly monitoring.

---

## 7. The Road to V3: What problems remain?

**Why are we planning V3?** 
V1 and V2 are cryptographically sound *today*, but they have four systemic architectural flaws that will be exploited in the future:
1. **The Quantum Threat:** V1 and V2 use Diffie-Hellman and DLP. A quantum computer running Shor's Algorithm will easily break this in 10-15 years (Store Now, Decrypt Later).
2. **The N-1 Collusion Risk:** If a corrupt Control Center official knows the readings of 9 out of 10 houses in a building, they can just subtract them from the aggregate to violate the privacy of the 10th house.
3. **TTP Single Point of Failure:** If the TTP server is hacked during initial setup, all keys for all millions of meters are compromised forever.
4. **Traffic Analysis:** Even with unbreakable encryption, attackers can watch the *timing* of network packets to know if a family has gone on vacation (behavioral fingerprinting).

### What concepts will we use in V3, and why?

1. **Ring Learning with Errors (RLWE)**
   - **Why:** Replaces classical Diffie-Hellman. It is a NIST-standardized Post-Quantum lattice cryptography method that even future quantum computers cannot break.
2. **Differential Privacy (DP - Laplace Noise)**
   - **Why:** Replaces exact encryption. Meters add a tiny amount of mathematical noise before encrypting. This prevents the N-1 collusion attack because the final number is slightly fuzzed, guaranteeing individual privacy while maintaining neighborhood billing accuracy.
3. **Secure Multi-Party Computation (SMPC/DKG)**
   - **Why:** Replaces the TTP. Multiple utility servers jointly generate the master parameters. A hacker would have to compromise several independent organizations simultaneously to break the system.
4. **Hardware Traffic Padding**
   - **Why:** Replaces standard transmission. Meters constantly send encrypted dummy packets so the network traffic always looks identical, blinding outside observers to household activity.

---

## 8. Detailed Algorithmic Structure & Formulas

The core algorithms of the GuardGrid system follow these distinct mathematical phases:

### Phase 1: Setup & Key Generation (TTP)
**Concept:** Generate safe primes and MIFE bounds.
- **DH Generation:** $p = 2q + 1$ (safe prime), $g$ is a generator. Private key $x$, Public key $Y = g^x \pmod p$.
- **MIFE Setup:** Generates Master Key $MK = (PK, SK, \text{SlotKeys})$.

### Phase 2: Masking & Encryption (Smart Meters)
**Concept:** ElGamal-style blinding mixed with Multi-Input Functional Encryption.
- **Session Key ($k_i$):** Derived via DH. $k_i = (Y_{cc})^{x_{sm}} \pmod p$
- **Masking:** $m_i = x_i + (k_i \pmod{\text{MASK\_BOUND}})$
- **Encryption:** $C_i = \text{MIFE.Enc}(m_i, \text{SlotKey}_i)$
- **Hashing (LHH):** $h_i = g^{m_i} \pmod p$
- **Output:** SM sends $(C_i, h_i)$ to Gateway.

### Phase 3: Aggregation (Gateway)
**Concept:** Compute the sum without decrypting.
- **Inner Product (MIFE):** $C' = \text{MIFE.Dec}(PK, SK_y, [C_1, C_2... C_n])$ 
  - Result: $C' = \sum_{i=1}^{n} m_i = \sum (x_i + k_i)$
- **Homomorphic Hash Eval:** $h^* = \prod_{i=1}^{n} h_i \pmod p$
  - Result: $h^* = g^{m_1} \cdot g^{m_2} \dots = g^{\sum m_i} \pmod p$

### Phase 4: Verification & Unmasking (Control Center)
**Concept:** Verify AG honesty and strip the symmetric mask.
- **Verify:** Is $g^{C'} \pmod p == h^*$ ? (If yes, Gateway is honest).
- **Unmask:** Calculate true aggregate $C = C' - \sum_{i=1}^{n} (k_i \pmod{\text{MASK\_BOUND}})$
- **V2 Fault Tolerance:** If $SM_x$ is offline, Dummy $C_x$ is used (where $x_x = 0$), and $k_x$ is excluded from the CC's unmasking subtraction.

### Phase 5: Function Queries (Cloud)
**Concept:** Allow linear function queries on the encrypted aggregate.
- **Encrypt Aggregate (CC):** $c_1 = g^r \pmod p$, $c_2 = C + H(PK_{cloud}^r \pmod p)$
- **Query Evaluation (Cloud):** Decrypts the mask using $SK_{cloud}$, yielding $C$, then evaluates $f(C) = a \cdot C + b$.
