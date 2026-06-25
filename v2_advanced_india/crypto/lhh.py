"""
lhh.py – Linear Homomorphic Hash (Section III-C of the paper).
================================================================

Purpose
-------
The LHH provides *integrity verification* for the aggregation step.
It answers a critical question: "Did the Aggregation Gateway honestly
sum the ciphertexts, or did it tamper with the result?"

Without LHH, a malicious AG could silently add, drop, or modify
ciphertexts and the CC would have no way to detect the fraud.  LHH
catches this by creating a parallel "hash chain" that the CC can
independently verify.

How it works
------------
The scheme exploits the *homomorphic property* of modular exponentiation.

For a single value x:
    h = g^x mod p

For the sum of n values:
    g^{x1+x2+…+xn} mod p  =  (g^x1 · g^x2 · … · g^xn) mod p
                            =  ∏ h_i  mod p

So if the AG computes:
    C' = x1 + x2 + … + xn       (the aggregate of masked values)
    h* = h1 · h2 · … · hn mod p  (the product of individual hashes)

Then the CC can verify:
    g^{C'} mod p  ==  h*  ?

If they match, the AG computed C' correctly.  If they don't match,
the AG tampered with at least one value.

This check works because the discrete logarithm is hard to invert:
the AG cannot find a different C'' ≠ C' such that g^{C''} = h*
without breaking the DLP.

Security assumption
-------------------
Discrete Logarithm Problem (DLP) in the order-q subgroup of Z*_p,
where p is a safe prime.  Same group structure as our DH module.

Why separate group from DH?
----------------------------
The paper uses a *separate* (p, g) pair for LHH even though the
maths is identical.  This is a standard crypto-engineering practice:
if you reuse the same group for key agreement AND hash verification,
a break in one could cascade to the other.  Separate groups provide
domain separation — the LHH group parameters are only used for
hashing, never for key exchange.

Functions exposed
-----------------
    lhh_setup(bits)                       → (p, g)
    lhh_hash(x, g, p)                    → h = g^x mod p
    lhh_eval(hash_list, g, p, coeffs?)   → h* = ∏ h_i^{α_i} mod p
    lhh_verify(C_prime, h_star, g, p)    → True / False
"""

from __future__ import annotations

import gmpy2
from gmpy2 import mpz


def lhh_setup(bits: int = 512) -> tuple[int, int]:
    """Generate LHH group parameters (p, g).

    We reuse the same safe-prime generation from the DH module because
    the mathematical requirements are identical: a prime-order subgroup
    of Z*_p where the DLP is hard.

    Returns
    -------
    tuple[int, int] – (p, g) for the LHH group.
    """
    from crypto.dh import dh_params          # Lazy import to avoid cycles.
    return dh_params(bits)


def lhh_hash(x: int, g: int, p: int) -> int:
    """Hash a single integer value:  h = g^x mod p.

    This is the core one-way function.  Given h, recovering x requires
    solving the discrete logarithm — which is computationally infeasible
    for 512-bit primes and above.

    Parameters
    ----------
    x : int – the value to hash (typically a masked reading mi).
    g : int – generator of the QR subgroup.
    p : int – safe prime modulus.

    Returns
    -------
    int – the hash value h.
    """
    return int(gmpy2.powmod(mpz(g), mpz(x), mpz(p)))


def lhh_eval(hash_list: list[int], g: int, p: int,
             coefficients: list[int] | None = None) -> int:
    """Evaluate the homomorphic hash:  h* = ∏ h_i^{α_i} mod p.

    When all coefficients α_i = 1 (the default), this computes the
    simple product of hashes, which — thanks to the homomorphic
    property — equals g^{Σ x_i} mod p.

    The coefficients parameter exists for generality: weighted sums.
    For the basic aggregation use-case in the paper, we always pass
    all-ones (or None, which defaults to all-ones).

    Parameters
    ----------
    hash_list    : list[int] – individual hashes [h1, …, hn].
    g            : int       – generator (kept for API consistency).
    p            : int       – prime modulus.
    coefficients : list[int] | None
        Per-hash exponents.  None → all 1s (simple product).

    Returns
    -------
    int – the evaluated hash h*.
    """
    p_mpz = mpz(p)
    h_star = mpz(1)

    if coefficients is None:
        coefficients = [1] * len(hash_list)

    for h_i, alpha_i in zip(hash_list, coefficients):
        # h_i^{α_i} mod p
        term = gmpy2.powmod(mpz(h_i), mpz(alpha_i), p_mpz)
        h_star = (h_star * term) % p_mpz

    return int(h_star)


def lhh_verify(C_prime: int, h_star: int, g: int, p: int) -> bool:
    """Verify the aggregate:  g^{C'} mod p  ==  h* ?

    This is the moment of truth.  If the AG was honest, the left side
    (computed by the CC from the reported aggregate) will match the
    right side (the hash product the AG forwarded).

    If they don't match, the AG corrupted the aggregate — either by
    arithmetic error or by deliberate manipulation.

    Parameters
    ----------
    C_prime : int – the masked aggregate reported by the AG.
    h_star  : int – the hash product reported by the AG.
    g       : int – LHH generator.
    p       : int – LHH prime.

    Returns
    -------
    bool – True if honest, False if tampered.
    """
    expected = gmpy2.powmod(mpz(g), mpz(C_prime), mpz(p))
    return int(expected) == h_star
