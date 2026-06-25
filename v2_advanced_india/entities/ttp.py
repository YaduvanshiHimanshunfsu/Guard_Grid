#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    entities/ttp.py
# Purpose: Trusted Third Party entity.
#          Modified from V1 to generate backup (dummy) ciphertexts
#          during initialisation for fault tolerance.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

from schemes.guardgrid import guardgrid_init
from schemes.fehh_threshold import generate_backup_ciphertexts


class TTP:
    """Trusted Third Party – generates keys, distributes them, goes offline."""

    def __init__(self, n_users: int, bits: int = 512):
        self.n_users = n_users
        self.bits = bits
        self.sys_params: dict | None = None
        self._active = True

    def initialise(self) -> dict:
        """Run the full GuardGrid system setup and generate backups."""
        if not self._active:
            raise RuntimeError("TTP is already offline; setup was done.")

        # 1. Base initialization (DH, LHH, MIFE, FEFQ)
        self.sys_params = guardgrid_init(self.n_users, self.bits)

        # 2. V2-specific: Generate backup ciphertexts for fault tolerance
        backups = generate_backup_ciphertexts(self.sys_params["fehh_params"])
        self.sys_params["backup_ciphertexts"] = backups

        # Also store sm_dh_publics for CC convenience in V2
        self.sys_params["sm_dh_publics"] = [pub for (_prv, pub) in self.sys_params["sm_dh_keys"]]

        self._active = False
        return self.sys_params

    def get_sm_keys(self, slot_index: int) -> dict:
        self._require_setup()
        sm_priv, sm_pub = self.sys_params["sm_dh_keys"][slot_index]
        _cc_priv, cc_pub = self.sys_params["fehh_params"]["cc_keys"][slot_index]
        return {
            "sm_dh_private": sm_priv,
            "sm_dh_public": sm_pub,
            "cc_dh_public": cc_pub,
        }

    def get_cc_keys(self) -> dict:
        self._require_setup()
        fp = self.sys_params["fehh_params"]
        return {
            "cc_dh_keys": fp["cc_keys"],
            "master_key": fp["master_key"],
            "fefq_params": self.sys_params["fefq_params"],
            "sm_dh_publics": self.sys_params["sm_dh_publics"],
            "dh_p": fp["dh_p"],
            "dh_g": fp["dh_g"],
            "lhh_p": fp["lhh_p"],
            "lhh_g": fp["lhh_g"],
        }

    def get_ag_keys(self) -> dict:
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
        self._require_setup()
        fefq = self.sys_params["fefq_params"]
        return {
            "fefq_public": {
                "p": fefq["p"],
                "g": fefq["g"],
                "pk": fefq["pk"],
            }
        }

    def _require_setup(self):
        if self.sys_params is None:
            raise RuntimeError("Call initialise() first.")
