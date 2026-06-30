#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    crypto/pedersen_commitment.py
# Purpose: Pedersen Commitment scheme for Zero-Knowledge Proofs.
#          Information-theoretically hiding, computationally binding.
# ──────────────────────────────────────────────────────────────────────

import gmpy2
import os

class PedersenParams:
    """
    Parameters for the Pedersen Commitment scheme.
    Requires a large safe prime p, and two generators g and h where
    log_g(h) is unknown.
    """
    def __init__(self, p: int, g: int, h: int):
        self.p = p
        self.g = g
        self.h = h
        # p is a safe prime, so q = (p-1)/2 is the order of the subgroup
        self.q = (p - 1) // 2

def generate_pedersen_params(p: int, g: int) -> PedersenParams:
    """
    Generate Pedersen parameters given a safe prime p and generator g.
    We need to find h = g^s mod p for a random unknown s.
    Since we can't reliably pick a random h that generates the same subgroup 
    without knowing its discrete log easily, we just hash g or pick a random s.
    For this simulation, we simulate the 'unknown' discrete log.
    """
    # In a real setup, h is chosen such that nobody knows s where h = g^s mod p.
    # For simulation, we randomly generate s and discard it.
    random_bytes = os.urandom(32)
    s = int.from_bytes(random_bytes, 'big')
    h = int(gmpy2.powmod(g, s, p))
    return PedersenParams(p, g, h)

def commit(x: int, r: int, params: PedersenParams) -> int:
    """
    Compute Pedersen Commitment C = g^x * h^r mod p.
    
    Args:
        x (int): The value to commit to.
        r (int): The blinding factor (randomness).
        params (PedersenParams): The public parameters.
        
    Returns:
        int: The commitment C.
    """
    g_x = gmpy2.powmod(params.g, x, params.p)
    h_r = gmpy2.powmod(params.h, r, params.p)
    return int((g_x * h_r) % params.p)
