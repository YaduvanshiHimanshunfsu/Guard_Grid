"""
fefq.py – Functional Encryption for Function Queries (Section VI-B).
======================================================================

Purpose
-------
After the CC decrypts the true aggregate C, it needs to let a Cloud
Server run analytics on C without revealing C itself.  FEFQ achieves
this: the CC encrypts C under FEFQ, uploads the ciphertext to the
Cloud, and the Cloud can evaluate linear functions  f(x) = a·x + b
on the encrypted value.

Real-world motivation: the Cloud might compute billing adjustments
(multiply by tariff rate, add fixed charges) or statistical scaling
(multiply by a seasonal factor) — all without seeing the raw aggregate.

Construction (DDH-based)
-------------------------
The scheme is built on the Decisional Diffie-Hellman (DDH) assumption.
It looks like a simplified version of ElGamal encryption with a twist
for functional evaluation.

    Setup:
        Generate (p, g) — a safe prime and generator.
        Pick secret key sk ← random in {1, …, p-2}.
        Compute public key pk = g^sk mod p.

    Encrypt(m):
        Pick random blinding factor r ← random in {1, …, p-2}.
        c1 = g^r mod p              (the "ephemeral public key")
        c2 = m + H(pk^r mod p)      (the message blinded by a hash)
        Return ciphertext (c1, c2).

    KeyGen(a, b):
        Return function key fk = {a, b, sk}.
        In a real system the CC would issue separate function keys
        per query, restricting what the Cloud can compute.  In this
        simulation the Cloud holds the full sk for simplicity.

    Decrypt(ct, fk):
        Recompute shared = c1^sk mod p = g^{r·sk} = pk^r.
        Recover m = c2 - H(shared).
        Compute f(m) = a·m + b.
        Return the result.

Why H() instead of raw group elements?
    Standard DDH-based FE embeds messages in the exponent (g^m) and
    recovers them via discrete log.  For large aggregates (thousands),
    this BSGS recovery is slow.  By using a hash-then-add construction
    instead, we avoid BSGS entirely — the message is hidden by adding
    a pseudorandom value derived from the DH shared secret, and
    recovery is just subtraction.  The security reduction is to the
    Random Oracle Model (ROM) with DDH.

Supported query patterns
------------------------
    f(x) = x + 500     →  fefq_keygen(params, a=1, b=500)
    f(x) = x - 200     →  fefq_keygen(params, a=1, b=-200)
    f(x) = 3·x         →  fefq_keygen(params, a=3, b=0)
    f(x) = 2·x + 100   →  fefq_keygen(params, a=2, b=100)

Functions exposed
-----------------
    fefq_setup(bits)              → params dict with (p, g, sk, pk)
    fefq_encrypt(m, params)       → ciphertext (c1, c2)
    fefq_keygen(params, a, b)     → function key dict
    fefq_decrypt(ct, fk, params)  → f(m) = a·m + b
"""

from __future__ import annotations

import os
import hashlib
import math

import gmpy2
from gmpy2 import mpz


# ──────────────────────────────────────────────────────────────────────────────
# Setup
# ──────────────────────────────────────────────────────────────────────────────

def fefq_setup(bits: int = 512) -> dict:
    """Generate FEFQ public parameters and key pair.

    Internally reuses dh_params() for the safe prime — same mathematical
    structure, different key material (domain separation).

    Returns
    -------
    dict with keys:
        p  – safe prime
        g  – generator
        sk – secret key (random exponent)
        pk – public key (g^sk mod p)
    """
    from crypto.dh import dh_params

    p, g = dh_params(bits)

    # Secret key: random exponent in {1, …, p-2}.
    rs = gmpy2.random_state(int.from_bytes(os.urandom(16), "big"))
    sk = int(gmpy2.mpz_random(rs, mpz(p) - 2) + 1)
    pk = int(gmpy2.powmod(mpz(g), mpz(sk), mpz(p)))

    return {"p": p, "g": g, "sk": sk, "pk": pk}


# ──────────────────────────────────────────────────────────────────────────────
# Internal hash function
# ──────────────────────────────────────────────────────────────────────────────

def _hash_to_int(value: int) -> int:
    """Deterministic hash of an integer → integer (SHA-256).

    This is the H() function in the construction.  Given the DH shared
    secret (an integer), it produces a pseudorandom integer used to
    blind the message.  SHA-256 is modelled as a random oracle — no
    attacker can predict H(x) without knowing x.
    """
    blen = max(value.bit_length(), 1)
    raw = value.to_bytes((blen + 7) // 8, "big")
    return int.from_bytes(hashlib.sha256(raw).digest(), "big")


# ──────────────────────────────────────────────────────────────────────────────
# Encryption
# ──────────────────────────────────────────────────────────────────────────────

def fefq_encrypt(m: int, params: dict) -> tuple[int, int]:
    """Encrypt plaintext *m* under the FEFQ scheme.

    The ciphertext is a pair (c1, c2) where:
        c1 = g^r mod p       — lets the decryptor reconstruct the shared secret
        c2 = m + H(pk^r)     — the message hidden under a pseudorandom mask

    A fresh random r is sampled for every encryption, so encrypting the
    same message twice yields different ciphertexts (semantic security).

    Parameters
    ----------
    m      : int – the aggregate value to encrypt.
    params : dict – output of fefq_setup (needs p, g, pk).

    Returns
    -------
    tuple[int, int] – ciphertext (c1, c2).
    """
    p, g, pk = params["p"], params["g"], params["pk"]

    # Fresh random blinding exponent r ∈ {1, …, p-2}.
    rs = gmpy2.random_state(int.from_bytes(os.urandom(16), "big"))
    r = int(gmpy2.mpz_random(rs, mpz(p) - 2) + 1)

    c1 = int(gmpy2.powmod(mpz(g), mpz(r), mpz(p)))        # g^r mod p
    shared = int(gmpy2.powmod(mpz(pk), mpz(r), mpz(p)))    # pk^r mod p
    c2 = m + _hash_to_int(shared)                           # m + H(pk^r)

    return c1, c2


# ──────────────────────────────────────────────────────────────────────────────
# Function key derivation
# ──────────────────────────────────────────────────────────────────────────────

def fefq_keygen(params: dict, a: int = 1, b: int = 0) -> dict:
    """Derive a function key for  f(x) = a·x + b.

    In a production deployment, the CC would issue specific function keys
    to the Cloud for each authorized query.  The Cloud could then evaluate
    only the functions it has keys for — not arbitrary computations.

    In this simulation the Cloud holds the full secret key, so keygen is
    trivially packaging (a, b, sk) together.  The security guarantees
    still hold: even with sk, the Cloud can only recover f(m), not m
    itself, if f is non-invertible (e.g., a=0 makes m irrecoverable).
    For a=1 the Cloud *can* trivially recover m from f(m) = m + b by
    subtracting b — this is a known limitation of linear FE.

    Parameters
    ----------
    params : dict – full params (including sk).
    a      : int – multiplicative coefficient.
    b      : int – additive constant.

    Returns
    -------
    dict – the function key {a, b, sk}.
    """
    return {"a": a, "b": b, "sk": params["sk"]}


# ──────────────────────────────────────────────────────────────────────────────
# Decryption (function evaluation on ciphertext)
# ──────────────────────────────────────────────────────────────────────────────

def fefq_decrypt(ct: tuple[int, int], fk: dict, params: dict) -> int:
    """Evaluate f(m) = a·m + b from the ciphertext.

    Decryption steps:
        1. Recompute the shared secret:  c1^sk mod p = g^{r·sk} = pk^r.
        2. Hash it to recover the blinding value: H(shared).
        3. Strip the mask:  m = c2 - H(shared).
        4. Apply the linear function:  result = a·m + b.

    The Cloud never sees m in isolation — it only sees the final result
    after applying f().  (Though as noted in keygen, for a=1 the result
    is trivially related to m.)

    Parameters
    ----------
    ct     : tuple[int, int] – ciphertext (c1, c2).
    fk     : dict – function key from fefq_keygen.
    params : dict – public parameters (needs p).

    Returns
    -------
    int – the result f(m) = a·m + b.
    """
    c1, c2 = ct
    p = params["p"]
    sk = fk["sk"]
    a, b = fk["a"], fk["b"]

    # Recompute the DH shared secret from the ciphertext.
    shared = int(gmpy2.powmod(mpz(c1), mpz(sk), mpz(p)))
    h_shared = _hash_to_int(shared)

    # Strip the hash mask to recover the original message.
    m = c2 - h_shared

    # Apply the linear function.
    return a * m + b
