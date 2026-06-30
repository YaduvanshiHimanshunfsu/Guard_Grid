#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    benchmark/measure_v3.py
# Purpose: Measures overhead of PQ ML-KEM + DP + ZKP.
# ──────────────────────────────────────────────────────────────────────

import time
from config import N_USERS
from main import run_simulation

def benchmark():
    print("--- GuardGrid V3 Benchmark ---")
    start = time.time()
    run_simulation(N_USERS)
    total = time.time() - start
    print(f"\nTotal execution time for V3 with {N_USERS} meters: {total:.3f}s")
    print("------------------------------")

if __name__ == "__main__":
    benchmark()
