#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    entities/cloud_server_v3.py
# Purpose: Cloud Server entity for V3.
#          Evaluates lattice-based FE queries.
# ──────────────────────────────────────────────────────────────────────

from crypto.lattice_fe import LatticeFE

class CloudServerV3:
    def __init__(self):
        self.lfe = LatticeFE(n_dim=64, q_modulus=16384, sigma=3.2)
        
    def evaluate_query(self, ct, sk_a, a: int, b_const: int) -> int:
        """
        Evaluate f(x) = a*x + b_const on the ciphertext ct.
        """
        return self.lfe.decrypt(ct, sk_a, a, b_const)
