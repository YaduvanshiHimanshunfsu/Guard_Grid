"""
smart_meter.py – Smart Meter entity.
=======================================

Role in the protocol
--------------------
Each Smart Meter is a low-power device installed at a household or
industrial site.  In every metering round it:

    1. Reads its current power output/consumption (a float, e.g. 3.763 kW).
    2. Scales it to an integer (3763) using the SCALE factor.
    3. Derives the session key ki with the CC via Diffie-Hellman.
    4. Masks the reading:  mi = xi + ki.
    5. Encrypts mi using MIFE (the AG can compute Σ mi but not any mi).
    6. Computes the LHH hash:  hi = g'^{mi} mod p'.
    7. Sends (ciphertext, hash) to the Aggregation Gateway.
    8. Keeps ki secret — it never leaves the SM.

What a Smart Meter does NOT know
---------------------------------
    - Other meters' readings (obviously).
    - The MIFE functional decryption key sk_y (only the AG has that).
    - The LHH parameters of other meters.
    - The CC's DH private key (only the CC has that).

The SM holds its own DH private key and the CC's DH public key for
its slot.  That is the absolute minimum needed to participate in the
protocol.

Why the SM does not verify anything
-------------------------------------
In the paper's model, the SM is a "send and forget" device.  It
encrypts, sends, and is done.  Verification is the CC's job.  This
keeps the SM's computational burden minimal — important because real
smart meters have very limited processing power (think ARM Cortex-M
class, not a desktop CPU).
"""

from __future__ import annotations

from schemes.fehh import fehh_enc


class SmartMeter:
    """Represents a single smart meter in the simulation."""

    def __init__(self, slot_index: int, sm_dh_private: int,
                 cc_dh_public: int, fehh_params: dict):
        """
        Parameters
        ----------
        slot_index    : int – 0-based MIFE slot index.
        sm_dh_private : int – this SM's DH private key.
        cc_dh_public  : int – CC's DH public key for this slot.
        fehh_params   : dict – output of fehh_setup.
        """
        self.slot_index = slot_index
        self.sm_dh_private = sm_dh_private
        self.cc_dh_public = cc_dh_public
        self.fehh_params = fehh_params

    def encrypt(self, x_i: int) -> dict:
        """Encrypt a single reading and produce the (ctx, h, ki) bundle.

        The SM calls this once per round.  The ciphertext and hash are
        sent to the AG.  The session key ki stays inside the SM — the
        simulation code in main.py collects it only for bookkeeping;
        in a real system it would never leave the device.

        Parameters
        ----------
        x_i : int – the integer-scaled meter reading.

        Returns
        -------
        dict with:
            ctx – MIFE ciphertext (opaque object, sent to AG).
            h   – LHH hash value (int, sent to AG).
            ki  – session key (int, kept by SM).
        """
        return fehh_enc(
            x_i=x_i,
            slot_index=self.slot_index,
            params=self.fehh_params,
            sm_private=self.sm_dh_private,
            cc_public=self.cc_dh_public,
        )
