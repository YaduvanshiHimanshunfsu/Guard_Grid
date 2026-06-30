# GuardGrid – Privacy-Preserving Smart Grid Data Aggregation

A Python implementation of a privacy-preserving smart-meter data aggregation protocol using **Functional Encryption with Homomorphic Hashing (FEHH)** and **Functional Encryption for Function Queries (FEFQ)**.

## Project Structure

* **[`starter.py`](starter.py)** — An interactive, dynamic demonstration script for presentations.
* **[`v1_research_demo/`](v1_research_demo/)** — The foundational implementation validating the theoretical math of the paper.
* **[`v2_advanced_india/`](v2_advanced_india/)** — The production-ready extension featuring fault tolerance and billing. ([Read the V2 Documentation](v2_advanced_india/README.md))
* **[`v3_advanced_security_concept/`](v3_advanced_security_concept/)** — The state-of-the-art implementation featuring Post-Quantum lattice cryptography (ML-KEM-768), Differential Privacy, Zero-Knowledge Proofs, and Decentralized Setup (DKG). ([Read the V3 Architecture Docs](v3_advanced_security_concept/README.md))
* **[`shared/`](shared/)** — Contains the original `smart_grid_stability_augmented.csv` dataset.

```
GuardGrid/
├── shared/                       # Common dataset (14 MB CSV)
│   └── smart_grid_stability_augmented.csv
│
├── v1_research_demo/             # Paper replication – vanilla protocol
│   ├── main.py                   #   Entry point
│   ├── config.py                 #   All tunable constants
│   ├── crypto/                   #   DH, LHH, MIFE, FEFQ primitives
│   ├── schemes/                  #   FEHH + GuardGrid protocol logic
│   ├── entities/                 #   TTP, SM, AG, CC, Cloud actors
│   ├── data/                     #   CSV loader
│   └── benchmark/                #   Timing + plots (Figures 3–7)
│
├── v2_advanced_india/            # Extended version – India-specific
│   ├── main.py                   #   Multi-round simulation with faults
│   ├── config.py                 #   Extended config (RDSS, billing, etc.)
│   ├── crypto/                   #   + Shamir's Secret Sharing
│   ├── schemes/                  #   + Fault-tolerant FEHH, time-series
│   ├── entities/                 #   Modified TTP + AG for fault tolerance
│   ├── data/                     #   + Time-series loader
│   ├── utils/                    #   Billing, anomaly, credit scoring
│   └── benchmark/                #   Extended benchmarks
│
├── .gitignore
└── README.md                     # This file
```

## Quick Start

### Prerequisites
```bash
pip install pymife gmpy2 pandas matplotlib
```

### Run V1 (Paper Demo)
```bash
cd v1_research_demo
python main.py          # Default 10 meters
python main.py 50       # Override to 50 meters
python main.py benchmark  # Generate Figures 3–7
```

### Run V2 (India Advanced)
```bash
cd v2_advanced_india
python main.py              # 1-day sim, 10 meters, no faults
python main.py 20           # 20 meters
python main.py 10 --faults 2  # 10 meters, 2 random offline per round
python main.py benchmark    # V2-specific benchmarks
```

### Run V3 (Advanced Security)
```bash
cd v3_advanced_security_concept
python main.py                  # Full PQ crypto + DP + ZKP simulation (10 meters)
python main.py 20               # 20 meters
python benchmark/measure_v3.py  # V3 cryptography overhead benchmark
```

## The Four-Phase Protocol

| Phase | Actor | Action |
|-------|-------|--------|
| 1. Init | TTP | Generate all crypto params, distribute keys, go offline |
| 2. Collect | Smart Meters | Encrypt readings with DH masking + MIFE + LHH hash |
| 3. Aggregate | AG → CC | AG aggregates ciphertexts; CC verifies + unmasks |
| 4. Query | CC → Cloud | CC encrypts aggregate under FEFQ; Cloud evaluates f(x) |

## V2 Enhancements

| Feature | Description |
|---------|-------------|
| Fault Tolerance | Dummy ciphertexts for offline meters |
| Time-Series | 96-slot daily cycle (15-min intervals, India RDSS spec) |
| Billing | Feeder-level revenue estimation with DERC tariff slabs |
| Anomaly Detection | Rolling-window z-score flagging on decrypted aggregates |
| Credit Scoring | AG reputation tracking (pass/fail per round) |
| Shamir | Threshold secret sharing primitive (standalone) |

## V3 Advancements

| Feature | Description |
|---------|-------------|
| Post-Quantum KEM | Replaces Diffie-Hellman with NIST FIPS 203 (ML-KEM-768) |
| Differential Privacy | Laplace noise injection to mask individual grid activity |
| Zero-Knowledge Proofs | Non-interactive range proofs via Fiat-Shamir heuristic |
| Decentralized Setup | Feldman VSS & Pedersen DKG replace the single-point-of-failure TTP |
| Lattice FE | Replaces DDH-based Functional Encryption with LWE-based Lattice FE for cloud queries |

## Dataset

**Smart Grid Stability Augmented** – 60,000 rows × 14 columns.
Uses the `p1` column (producer power output, +1.58 to +5.86 kW).

## Security Warning

⚠️ **512-bit primes are for simulation only.** Production deployments require ≥2048-bit primes. The current key sizes are deliberately small to keep benchmarks fast.

## License

Academic / Research use.
