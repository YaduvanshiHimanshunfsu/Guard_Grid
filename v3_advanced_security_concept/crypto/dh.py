"""
dh.py – Diffie-Hellman Key Agreement (Section III-D of the paper).
====================================================================

Background
----------
Diffie-Hellman (DH) lets two parties — here a Smart Meter (SM) and the
Control Center (CC) — establish a shared secret over an insecure channel
without ever transmitting the secret itself.

The shared secret is used as a *session key* to mask the meter reading
before it enters the MIFE encryption pipeline.  This mask is what
prevents the Aggregation Gateway from learning individual readings even
though it can compute the aggregate of the masked values.

How it works (in brief)
-----------------------
1.  Pick a safe prime  p = 2q + 1  where q is also prime.
    The "safe prime" structure guarantees the quadratic-residue subgroup
    has prime order q, which makes the Decisional Diffie-Hellman (DDH)
    assumption hold — no small subgroup attacks.

2.  Pick a generator g of the order-q subgroup.  We use g = 2² mod p
    (squaring a small candidate to land in the QR subgroup).

3.  Each party picks a random private exponent x ∈ {1, …, p-2} and
    publishes y = g^x mod p.

4.  Both parties compute the same shared secret:
        SM:   (CC_public)^{SM_private} mod p
        CC:   (SM_public)^{CC_private} mod p
    These are equal because  g^{ab} = g^{ba}.

5.  The shared secret is hashed (SHA-256) and reduced mod MASK_BOUND
    to produce the session key  ki  used in FEHH.Enc.

Why MASK_BOUND?
---------------
MIFE internally uses a baby-step giant-step (BSGS) discrete-log solver
to recover the inner product from the ciphertext.  BSGS can only handle
values within a bounded range — by default we set that range to ±10^9.

Each masked value is  mi = xi + ki.  If ki were a full 256-bit hash
output, mi would be enormous and BSGS would fail.  By reducing ki
mod 10,000 we guarantee that even with 500 meters, the total masked
aggregate  C' = Σ mi  stays under  500 × (6000 + 10000) = 8,000,000
— well within the solver's range.

The trade-off: a smaller mask space means the AG could theoretically
brute-force ki if it knew xi.  But the AG does NOT know xi (that is
the whole point of the MIFE encryption), so the reduced mask still
provides adequate hiding.

Functions exposed
-----------------
    dh_params(bits)          → (p, g)           safe prime + generator
    dh_generate(p, g)        → (private, public) key pair
    dh_agree(xi, g_xj, p)   → shared_secret    as an integer
    generate_session_key(…)  → ki               reduced session key
"""

from __future__ import annotations

import os
import hashlib

import gmpy2
from gmpy2 import mpz


# ──────────────────────────────────────────────────────────────────────────────
# Parameter generation
# ──────────────────────────────────────────────────────────────────────────────

def dh_params(bits: int = 512) -> tuple[int, int]:
    """Generate a safe prime *p = 2q + 1* and a generator *g*.

    The algorithm:
        1. Draw a random (bits-1)-bit number, find the next prime q.
        2. Compute p = 2q + 1.
        3. If p is also prime → done (p is a safe prime).
           Otherwise discard and try again.
        4. Compute g = 2² mod p.  Since p is a safe prime, the QR
           subgroup has order q and g = 4 is virtually always a
           generator of that subgroup.  If it collapses to 1 (only
           possible if p = 5, which never happens at 512 bits), we
           fall back to g = 3² mod p.

    Parameters
    ----------
    bits : int
        Desired bit-length of p.  512 for simulation speed,
        2048+ for real-world security.

    Returns
    -------
    tuple[int, int]
        (p, g) — the safe prime and the QR-subgroup generator.
    """
    # Seed gmpy2's random state from OS entropy (urandom).
    random_state = gmpy2.random_state(int.from_bytes(os.urandom(16), "big"))

    while True:
        # Draw a random prime q of exactly (bits-1) bits.
        q = gmpy2.next_prime(gmpy2.mpz_urandomb(random_state, bits - 1))
        if q.bit_length() != bits - 1:
            continue                       # Wrong bit-length, retry.
        p = 2 * q + 1
        if gmpy2.is_prime(p):
            break                          # Found a safe prime.

    # Generator of the QR subgroup: square a small number mod p.
    g = gmpy2.powmod(mpz(2), mpz(2), mpz(p))
    if g == 1:
        # Degenerate edge case — try another base.
        g = gmpy2.powmod(mpz(3), mpz(2), mpz(p))

    return int(p), int(g)


# ──────────────────────────────────────────────────────────────────────────────
# Key generation
# ──────────────────────────────────────────────────────────────────────────────

def dh_generate(p: int, g: int) -> tuple[int, int]:
    """Generate a DH key pair (private_key, public_key).

    private_key  x  ← random in {1, …, p-2}
    public_key   y  = g^x mod p

    Parameters
    ----------
    p : int – safe prime.
    g : int – QR-subgroup generator.

    Returns
    -------
    tuple[int, int]
        (x, y) — the private and public keys.
    """
    p_mpz = mpz(p)
    random_state = gmpy2.random_state(int.from_bytes(os.urandom(16), "big"))

    # x ∈ {1, …, p-2}  (never 0, never p-1)
    x = gmpy2.mpz_random(random_state, p_mpz - 2) + 1
    y = gmpy2.powmod(mpz(g), x, p_mpz)
    return int(x), int(y)


# ──────────────────────────────────────────────────────────────────────────────
# Key agreement
# ──────────────────────────────────────────────────────────────────────────────

def dh_agree(x_i: int, g_xj: int, p: int,
             H=hashlib.sha256) -> int:
    """Compute the shared seed  k_ij = H( (g^{x_j})^{x_i} mod p ).

    Both parties arrive at the same value:
        SM computes:  (CC_public)^{SM_private} mod p  →  g^{ab}
        CC computes:  (SM_public)^{CC_private} mod p  →  g^{ba}

    We hash the raw shared secret to:
        - compress it to a fixed length (256 bits),
        - destroy any algebraic structure an attacker might exploit.

    Parameters
    ----------
    x_i  : int – private key of the caller.
    g_xj : int – public key of the other party.
    p    : int – safe prime.
    H    :     – hash constructor (default SHA-256).

    Returns
    -------
    int – the shared session seed as an integer.
    """
    shared_secret = gmpy2.powmod(mpz(g_xj), mpz(x_i), mpz(p))

    # Serialize the big integer to bytes, then hash.
    bit_len = max(int(shared_secret).bit_length(), 1)
    secret_bytes = int(shared_secret).to_bytes((bit_len + 7) // 8, byteorder="big")
    digest = H(secret_bytes).digest()
    return int.from_bytes(digest, byteorder="big")


# ──────────────────────────────────────────────────────────────────────────────
# Session key derivation (used by SM and CC in FEHH.Enc / FEHH.Dec)
# ──────────────────────────────────────────────────────────────────────────────

# Upper bound for the session key mask.
# See the module docstring for why this is necessary.
MASK_BOUND = 10_000


def generate_session_key(cc_private: int, sm_public: int,
                         p: int, g: int) -> int:
    """Derive the reduced session key ki between the CC and one SM.

    Calls dh_agree() to get the raw shared secret, then reduces it
    modulo MASK_BOUND to keep masked values within MIFE's BSGS range.

    Parameters
    ----------
    cc_private : int – one party's private key.
    sm_public  : int – the other party's public key.
    p          : int – safe prime.
    g          : int – generator (unused but kept for API symmetry).

    Returns
    -------
    int – session key ki ∈ {0, …, MASK_BOUND - 1}.
    """
    k_ij = dh_agree(cc_private, sm_public, p)
    return k_ij % MASK_BOUND
