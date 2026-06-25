"""
control_center.py – Control Center entity.
=============================================

Role in the protocol
--------------------
The CC is the fully trusted party in the system — the utility company's
secure computation server.  It is the only entity that ever sees the
true aggregate value.

In the four-phase protocol the CC is active in Phase 3 and Phase 4:

    Phase 3 – Receives (C', h*) from the AG.
        1. Verifies integrity:  g'^{C'} mod p'  ==  h* ?
           This catches any AG tampering.
        2. Reconstructs all n session keys ki using DH.
           The CC has its own private keys and every SM's public key,
           so it can independently derive the same ki that each SM used.
        3. Strips the mask:  C = C' - Σ ki.
        4. Converts to float:  aggregate = C / SCALE.

    Phase 4 – Encrypts the aggregate under FEFQ for the Cloud.
        The CC wants the Cloud to perform analytics but does not want
        to reveal the raw aggregate.  FEFQ lets the Cloud evaluate
        linear functions f(x) = ax + b on the encrypted value.

What the CC knows vs. what it reveals
--------------------------------------
    The CC knows:  the true aggregate C = Σ xi.
    The CC does NOT know:  individual readings xi.
        Why?  Because the MIFE ciphertext yields only the *sum* (via
        the all-ones functional key), never individual values.  The
        session keys ki are derived from DH and let the CC unmask the
        aggregate, but they don't help isolate individual xi from the
        sum.

    The Cloud knows:  f(C) for any function it has a key for.
    The Cloud does NOT know:  C itself (unless f is trivially
        invertible, which is a known limitation of linear FE).

Why the CC holds the FEFQ secret key
--------------------------------------
In the paper's model, the CC is the "owner" of the data.  It encrypts
under FEFQ and could issue restricted function keys to the Cloud.
In this simulation we give the full FEFQ params (including sk) to the
Cloud for simplicity.  A production system would have the CC issue
per-query function keys instead.
"""

from __future__ import annotations

from crypto.dh import generate_session_key
from crypto.lhh import lhh_verify
from crypto.fefq import fefq_encrypt


class ControlCenter:
    """Simulates the control center."""

    def __init__(self, cc_dh_keys: list[tuple[int, int]],
                 sm_dh_publics: list[int],
                 dh_p: int, dh_g: int,
                 lhh_p: int, lhh_g: int,
                 fefq_params: dict,
                 scale: int = 1000):
        """
        Parameters
        ----------
        cc_dh_keys    : list – CC's DH key pairs [(priv, pub), …].
        sm_dh_publics : list – each SM's DH public key.
        dh_p, dh_g    : int – DH group parameters.
        lhh_p, lhh_g  : int – LHH group parameters.
        fefq_params   : dict – full FEFQ params (including sk).
        scale         : int – SCALE factor for float conversion.
        """
        self.cc_dh_keys = cc_dh_keys
        self.sm_dh_publics = sm_dh_publics
        self.dh_p = dh_p
        self.dh_g = dh_g
        self.lhh_p = lhh_p
        self.lhh_g = lhh_g
        self.fefq_params = fefq_params
        self.scale = scale

    # ──────────────────────────────────────────────────────────────────────
    # Session key reconstruction
    # ──────────────────────────────────────────────────────────────────────

    def _compute_session_keys(self) -> list[int]:
        """Re-derive all n session keys.

        The CC uses its DH private key and each SM's public key to
        reconstruct the same session key ki that the SM derived during
        encryption.  This works because DH is commutative:
            SM: generate_session_key(sm_priv, cc_pub) = ki
            CC: generate_session_key(cc_priv, sm_pub) = ki

        Returns
        -------
        list[int] – [k1, k2, …, kn].
        """
        keys = []
        for i, (cc_priv, _cc_pub) in enumerate(self.cc_dh_keys):
            ki = generate_session_key(
                cc_priv, self.sm_dh_publics[i], self.dh_p, self.dh_g
            )
            keys.append(ki)
        return keys

    # ──────────────────────────────────────────────────────────────────────
    # Phase 3: Verification + decryption
    # ──────────────────────────────────────────────────────────────────────

    def verify_and_decrypt(self, C_prime: int, h_star: int) -> dict:
        """Verify the AG's work and recover the true aggregate.

        This is the CC's main function.  It takes the AG's output and
        either confirms the result is valid or flags potential tampering.

        Steps:
            1. LHH verification: g'^{C'} mod p' == h* ?
            2. Session key reconstruction: derive [k1, …, kn].
            3. Unmask: C = C' - Σ ki.
            4. Float conversion: aggregate = C / SCALE.

        Parameters
        ----------
        C_prime : int – masked aggregate from the AG.
        h_star  : int – hash product from the AG.

        Returns
        -------
        dict with:
            verified       – bool.
            C              – int, the true aggregate.
            aggregate_float – float, in original units.
        """
        # Step 1: integrity check.
        verified = lhh_verify(C_prime, h_star, self.lhh_g, self.lhh_p)

        if not verified:
            print("[CC] ⚠  Verification FAILED – AG may be misbehaving!")

        # Step 2+3: unmask.
        session_keys = self._compute_session_keys()
        C = C_prime - sum(session_keys)

        # Step 4: recover the original floating-point value.
        aggregate_float = C / self.scale

        return {
            "verified": verified,
            "C": C,
            "aggregate_float": aggregate_float,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Phase 4: FEFQ encryption for the Cloud
    # ──────────────────────────────────────────────────────────────────────

    def encrypt_for_cloud(self, aggregate: int) -> tuple[int, int]:
        """Encrypt the true aggregate under FEFQ for cloud analytics.

        The ciphertext is uploaded to the Cloud Server, which can then
        evaluate authorized functions on it.

        Returns
        -------
        tuple[int, int] – the FEFQ ciphertext (c1, c2).
        """
        return fefq_encrypt(aggregate, self.fefq_params)

    def generate_function_key(self, a: int, b: int) -> dict:
        """Generate a function key for the Cloud Server to evaluate f(x) = a·x + b.

        Parameters
        ----------
        a : int – multiplicative coefficient.
        b : int – additive constant.

        Returns
        -------
        dict – the function key containing a, b, and sk.
        """
        from crypto.fefq import fefq_keygen
        return fefq_keygen(self.fefq_params, a, b)
