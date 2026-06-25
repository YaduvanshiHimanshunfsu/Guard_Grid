#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    crypto/shamir.py
# Purpose: Shamir's (t, n) Secret Sharing over a finite field.
#          A standalone cryptographic primitive included to demonstrate
#          threshold-based trust distribution.
#
# Theory:  To split secret s into n shares with threshold t:
#          1. Construct random polynomial f(x) of degree t-1 where f(0) = s.
#          2. Each share is (i, f(i)) for i = 1…n.
#          3. Any t shares can reconstruct s via Lagrange interpolation.
#          4. Fewer than t shares reveal NOTHING (information-theoretic).
#
# Reference: Adi Shamir, "How to Share a Secret", Communications of
#            the ACM, vol. 22, no. 11, pp. 612–613, November 1979.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import os
import secrets


def _mod_inverse(a: int, p: int) -> int:
    """Modular inverse via Fermat's little theorem:  a^{-1} = a^{p-2} mod p.

    Only works when p is prime — which is always the case for our
    finite field GF(p).
    """
    return pow(a, p - 2, p)


def _lagrange_basis_at_zero(i: int, xs: list[int], prime: int) -> int:
    """Compute Lagrange basis polynomial L_i evaluated at x = 0.

    L_i(0) = ∏_{j ≠ i}  (0 - x_j) / (x_i - x_j)   mod prime.

    This is the weight assigned to share i during reconstruction.
    """
    numerator = 1
    denominator = 1
    x_i = xs[i]

    for j, x_j in enumerate(xs):
        if i == j:
            continue
        numerator = (numerator * (-x_j)) % prime
        denominator = (denominator * (x_i - x_j)) % prime

    return (numerator * _mod_inverse(denominator, prime)) % prime


def shamir_split(secret: int, n: int, t: int, prime: int) -> list[tuple[int, int]]:
    """Split `secret` into `n` shares with threshold `t`.

    Parameters
    ----------
    secret : int – value to split.  Must be in range [0, prime).
    n      : int – total shares to generate.
    t      : int – minimum shares needed for reconstruction (2 ≤ t ≤ n).
    prime  : int – prime modulus defining the finite field GF(prime).

    Returns
    -------
    list[tuple[int, int]] – shares as (index, value) pairs.
                            Indices are 1…n (never 0, since f(0) = secret).

    Raises
    ------
    ValueError – if t < 2, t > n, or secret >= prime.
    """
    if t < 2:
        raise ValueError(f"Threshold t must be >= 2, got {t}")
    if t > n:
        raise ValueError(f"Threshold t ({t}) cannot exceed n ({n})")
    if secret >= prime:
        raise ValueError(f"Secret ({secret}) must be less than prime ({prime})")

    # Build a random polynomial of degree t-1 with constant term = secret.
    # f(x) = secret + a1*x + a2*x^2 + … + a_{t-1}*x^{t-1}
    coefficients = [secret]
    for _ in range(t - 1):
        coefficients.append(secrets.randbelow(prime))

    # Evaluate f(i) for i = 1…n.
    shares = []
    for i in range(1, n + 1):
        y = 0
        for power, coeff in enumerate(coefficients):
            y = (y + coeff * pow(i, power, prime)) % prime
        shares.append((i, y))

    return shares


def shamir_reconstruct(shares: list[tuple[int, int]], prime: int) -> int:
    """Reconstruct the secret from t or more shares.

    Uses Lagrange interpolation evaluated at x = 0 to recover f(0).

    Parameters
    ----------
    shares : list[tuple[int, int]] – at least t shares (index, value).
    prime  : int – same prime used during split.

    Returns
    -------
    int – the reconstructed secret.

    Raises
    ------
    ValueError – if fewer than 2 shares are provided.
    """
    if len(shares) < 2:
        raise ValueError(f"Need at least 2 shares, got {len(shares)}")

    xs = [s[0] for s in shares]
    ys = [s[1] for s in shares]

    secret = 0
    for i in range(len(shares)):
        basis = _lagrange_basis_at_zero(i, xs, prime)
        secret = (secret + ys[i] * basis) % prime

    return secret
