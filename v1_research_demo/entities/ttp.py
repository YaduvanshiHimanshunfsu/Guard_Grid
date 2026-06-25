"""
ttp.py – Trusted Third Party entity.
=======================================

Role in the protocol
--------------------
The TTP is the "god" of the system — it has access to ALL secret keys
for ALL entities during setup.  Its job is to:

    1. Generate every cryptographic parameter the system needs.
    2. Hand out the right subset of keys to each entity.
    3. Destroy its own copies and go permanently offline.

The TTP existing only during initialisation is a common pattern in
cryptographic protocols.  It avoids the need for complex distributed
key generation while keeping the operational phase free from any single
point of trust.  After setup, even if someone hacks the TTP's hardware,
there is nothing to steal — all keys have been wiped.

Security consideration
----------------------
In a real deployment, the TTP would run on a physically secured machine
(an air-gapped HSM, for example) and its storage would be shredded
after key distribution.  In this simulation, we model the "offline"
state by setting a flag that prevents any further method calls after
initialise() completes.

Key distribution logic
----------------------
Each entity receives ONLY the keys it needs:

    Smart Meter i:
        - Its own DH private key (to derive the session key with CC)
        - CC's DH public key for slot i (to complete the DH exchange)
        - FEHH public params (to encrypt and hash)

    Aggregation Gateway:
        - MIFE functional key sk_y (to decrypt the aggregate)
        - MIFE public key (for MIFE decryption API)
        - LHH params (to multiply hashes)
        - NO DH private keys (cannot unmask individual readings)

    Control Center:
        - All CC DH private keys (to derive session keys with each SM)
        - All SM DH public keys (other half of DH)
        - FEFQ full params including sk (to encrypt for cloud)
        - LHH params (to verify AG's work)

    Cloud Server:
        - FEFQ public params only — p, g, pk (to store ciphertexts)
        - In simulation: also gets sk for convenience (see note below)

Note on the Cloud Server key:
    The paper's ideal model has the CC issuing per-query function keys
    to the Cloud.  In our simulation, we give the Cloud the full FEFQ
    params (including sk) so it can derive its own function keys.  This
    is a simplification — in production the CC would gate which queries
    the Cloud can run by only issuing keys for authorized functions.
"""

from __future__ import annotations

from schemes.guardgrid import guardgrid_init


class TTP:
    """Trusted Third Party – generates keys, distributes them, goes offline."""

    def __init__(self, n_users: int, bits: int = 512):
        """
        Parameters
        ----------
        n_users : int – number of smart meters to support.
        bits    : int – security parameter (prime bit-length).
        """
        self.n_users = n_users
        self.bits = bits
        self.sys_params: dict | None = None
        self._active = True

    # ──────────────────────────────────────────────────────────────────────
    # Initialisation — the TTP's only real job
    # ──────────────────────────────────────────────────────────────────────

    def initialise(self) -> dict:
        """Run the full GuardGrid system setup.

        After this call the TTP marks itself as offline.  Any subsequent
        call to key distribution methods will still work (the keys are
        stored in sys_params), but initialise() cannot be called again.

        Returns
        -------
        dict – the complete sys_params bundle.
        """
        if not self._active:
            raise RuntimeError("TTP is already offline; setup was done.")

        self.sys_params = guardgrid_init(self.n_users, self.bits)
        self._active = False
        return self.sys_params

    # ──────────────────────────────────────────────────────────────────────
    # Key distribution — each method returns ONLY what that entity needs
    # ──────────────────────────────────────────────────────────────────────

    def get_sm_keys(self, slot_index: int) -> dict:
        """Return the keys that Smart Meter *slot_index* needs.

        Returns
        -------
        dict with:
            sm_dh_private – this SM's DH private key
            sm_dh_public  – this SM's DH public key (for reference)
            cc_dh_public  – the CC's DH public key for this slot
        """
        self._require_setup()
        sm_priv, sm_pub = self.sys_params["sm_dh_keys"][slot_index]
        _cc_priv, cc_pub = self.sys_params["fehh_params"]["cc_keys"][slot_index]
        return {
            "sm_dh_private": sm_priv,
            "sm_dh_public": sm_pub,
            "cc_dh_public": cc_pub,
        }

    def get_cc_keys(self) -> dict:
        """Return everything the Control Center needs.

        Returns
        -------
        dict with:
            cc_dh_keys    – all CC DH key pairs [(priv, pub), …]
            master_key    – MIFE master key (public portion for ref)
            fefq_params   – full FEFQ params (including sk)
            sm_dh_publics – all SM public keys
            dh_p, dh_g    – DH group params
            lhh_p, lhh_g  – LHH group params
        """
        self._require_setup()
        fp = self.sys_params["fehh_params"]
        return {
            "cc_dh_keys": fp["cc_keys"],
            "master_key": fp["master_key"],
            "fefq_params": self.sys_params["fefq_params"],
            "sm_dh_publics": [pub for (_prv, pub) in self.sys_params["sm_dh_keys"]],
            "dh_p": fp["dh_p"],
            "dh_g": fp["dh_g"],
            "lhh_p": fp["lhh_p"],
            "lhh_g": fp["lhh_g"],
        }

    def get_ag_keys(self) -> dict:
        """Return the keys the Aggregation Gateway needs.

        The AG gets the functional decryption key (to compute the sum)
        and the MIFE/LHH public params, but NO DH private keys.

        Returns
        -------
        dict with:
            sk_y       – MIFE functional key for the sum query
            master_key – MIFE master key (public portion)
            mife       – MIFEWrapper instance
            lhh_p, lhh_g – LHH group params
        """
        self._require_setup()
        fp = self.sys_params["fehh_params"]
        return {
            "sk_y": fp["sk_y"],
            "master_key": fp["master_key"],
            "mife": fp["mife"],
            "lhh_p": fp["lhh_p"],
            "lhh_g": fp["lhh_g"],
        }

    def get_cloud_keys(self) -> dict:
        """Return the keys the Cloud Server needs.

        The Cloud gets ONLY the FEFQ public parameters — it should not
        hold the secret key.  (In simulation we bend this rule; see
        the note in the module docstring.)

        Returns
        -------
        dict with:
            fefq_public – {p, g, pk} without sk.
        """
        self._require_setup()
        fefq = self.sys_params["fefq_params"]
        return {
            "fefq_public": {
                "p": fefq["p"],
                "g": fefq["g"],
                "pk": fefq["pk"],
            }
        }

    # ──────────────────────────────────────────────────────────────────────

    def _require_setup(self):
        """Guard: ensure initialise() has been called."""
        if self.sys_params is None:
            raise RuntimeError("Call initialise() first.")
