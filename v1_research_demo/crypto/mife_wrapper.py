"""
mife_wrapper.py – Thin adapter around PyMIFE's FeDamgardMulti.
================================================================

What is MIFE?
-------------
Multi-Input Functional Encryption is the cryptographic engine that
makes private aggregation possible.  It lets n parties independently
encrypt their values, and a designated decryptor can compute a
*function* of those values (in our case, the sum) without learning
any individual input.

Think of it like a ballot box: everyone drops in a sealed vote, and
the election officer can only read the total count — never who voted
for whom.

Paper mapping
-------------
    Paper term          PyMIFE call
    ────────────────────────────────────────────
    MIFE.Setup          FeDamgardMulti.generate
    MIFE.Enc(xi, i)     FeDamgardMulti.encrypt
    MIFE.KeyGen(y)      FeDamgardMulti.keygen
    MIFE.Dec(ct, sk)    FeDamgardMulti.decrypt

The Damgård multi-input FE scheme (reference [23] in the paper)
works over a cyclic group Zmod(p).  Each smart meter occupies one
"slot" in the scheme; the encryption key for slot i is derived from
the master key.  A *functional decryption key* for vector y = [1,…,1]
allows anyone holding it to compute the inner product <x, y> = Σ xi
— exactly the sum we need for aggregation.

Performance hack
----------------
By default PyMIFE calls Crypto.Util.number.getStrongPrime(1024) during
setup.  Strong prime generation at 1024 bits takes multiple minutes on
a typical laptop — completely impractical for a simulation that should
finish in seconds.

Our workaround: generate a regular 512-bit prime via getPrime() and
inject it as a custom Zmod group.  This is cryptographically weaker
than a 1024-bit strong prime, but perfectly adequate for demonstrating
the protocol's correctness.  A production deployment would raise this
to 2048+ bits and accept the slower setup time (which only happens once
during TTP initialisation).

BSGS bound
----------
FeDamgardMulti.decrypt internally solves a discrete log via baby-step
giant-step.  It needs a search range (lo, hi) that covers the expected
inner product.  If the actual value falls outside this range, decryption
hangs or throws.  We compute a generous bound based on the maximum
possible masked value per meter times the number of meters.

Functions exposed
-----------------
    MIFEWrapper.setup()          → master_key
    MIFEWrapper.encrypt(…)       → ciphertext for one slot
    MIFEWrapper.key_derive(…)    → functional decryption key
    MIFEWrapper.decrypt(…)       → inner product (the masked aggregate)
"""

from __future__ import annotations

from typing import Any

from Crypto.Util.number import getPrime
from mife.data.zmod import Zmod
from mife.multi.damgard import FeDamgardMulti


class MIFEWrapper:
    """Convenience class that adapts PyMIFE for the GuardGrid use case.

    We fix the vector dimension m=1 because each smart meter contributes
    a single scalar reading per round.  The wrapper hides PyMIFE's API
    quirks (like requiring list-wrapped scalars) behind clean methods.
    """

    def __init__(self, n_users: int, m: int = 1, key_bits: int = 512):
        """
        Parameters
        ----------
        n_users  : int – number of MIFE slots (one per smart meter).
        m        : int – dimension of each slot's input vector (always 1).
        key_bits : int – bit-length of the Zmod prime.
                         512 = fast for dev; 1024+ = secure for production.
        """
        self.n = n_users
        self.m = m
        self.key_bits = key_bits

    # ──────────────────────────────────────────────────────────────────────
    # Setup  (MIFE.Setup)
    # ──────────────────────────────────────────────────────────────────────

    def setup(self) -> Any:
        """Generate the MIFE master key.

        The master key is a compound object containing both the public
        parameters and the secret key material.  Calling
        master_key.get_enc_key(i) returns the per-slot encryption key
        for smart meter i.  Calling master_key.get_public_key() returns
        the public portion that the AG uses during aggregation.

        Returns
        -------
        master_key – the PyMIFE master key object.
        """
        # Pre-generate a prime much faster than getStrongPrime(1024).
        p = getPrime(self.key_bits)
        F = Zmod(p)
        master_key = FeDamgardMulti.generate(n=self.n, m=self.m, F=F)
        return master_key

    # ──────────────────────────────────────────────────────────────────────
    # Encryption  (MIFE.Enc)
    # ──────────────────────────────────────────────────────────────────────

    def encrypt(self, master_key: Any, x_i: int, slot_index: int) -> Any:
        """Encrypt a single scalar value for the given slot.

        The encrypted value is the *masked* reading mi = xi + ki, not
        the raw reading.  This happens before this method is called —
        the caller (FEHH.Enc) has already added the session key mask.

        Parameters
        ----------
        master_key : master key object (holds sk).
        x_i        : int – the masked reading to encrypt.
        slot_index : int – 0-based slot index for this meter.

        Returns
        -------
        ciphertext – a PyMIFE ciphertext object.
        """
        enc_key = master_key.get_enc_key(slot_index)
        # PyMIFE wants a list of length m, even for m=1.
        return FeDamgardMulti.encrypt([x_i], enc_key)

    # ──────────────────────────────────────────────────────────────────────
    # Key derivation  (MIFE.KeyGen)
    # ──────────────────────────────────────────────────────────────────────

    def key_derive(self, master_key: Any,
                   y_vector: list[list[int]] | None = None) -> Any:
        """Derive a functional decryption key for the function vector y.

        For aggregation, y = [[1], [1], …, [1]]  (n copies).  The
        inner product <x, y> then equals the sum of all encrypted values.

        If you wanted a weighted sum (e.g., billing with per-meter
        multipliers), you would pass different coefficients here.

        Parameters
        ----------
        master_key : master key object (holds sk).
        y_vector   : the function vector.  None defaults to all-ones.

        Returns
        -------
        sk_y – the functional decryption key.
        """
        if y_vector is None:
            y_vector = [[1] for _ in range(self.n)]
        return FeDamgardMulti.keygen(y_vector, master_key)

    # ──────────────────────────────────────────────────────────────────────
    # Decryption  (MIFE.Dec)
    # ──────────────────────────────────────────────────────────────────────

    def decrypt(self, master_key: Any, ctx_list: list, sk_y: Any,
                bound: tuple[int, int] = (-10**9, 10**9)) -> int:
        """Decrypt the inner product from a list of ciphertexts.

        Uses the baby-step giant-step (BSGS) algorithm internally to
        solve a discrete log within the given bound.  The bound MUST
        cover the actual aggregate value — if it doesn't, BSGS will
        either hang or raise an error.

        For n=500 meters with max masked value 16000 per meter, the
        aggregate can reach 8,000,000 — safely within ±10^9.

        Parameters
        ----------
        master_key : master key object (public portion used).
        ctx_list   : list of ciphertexts, one per slot.
        sk_y       : functional decryption key from key_derive().
        bound      : (lo, hi) search range for BSGS.

        Returns
        -------
        int – the inner product ⟨x, y⟩ (i.e. the masked aggregate C').
        """
        pub_key = master_key.get_public_key()
        return FeDamgardMulti.decrypt(ctx_list, pub_key, sk_y, bound)
