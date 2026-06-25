#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    entities/agg_gateway.py
# Purpose: Aggregation Gateway entity.
#          Modified from V1 to handle missing (None) results and
#          integrate with fehh_threshold.py.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

from schemes.fehh_threshold import fehh_agg_threshold


class AggregationGateway:
    """Simulates the aggregation gateway with fault tolerance."""

    def __init__(self, fehh_params: dict, backup_ciphertexts: list[dict]):
        """
        Parameters
        ----------
        fehh_params        : dict – output of fehh_setup.
        backup_ciphertexts : list[dict] – from TTP setup.
        """
        self.fehh_params = fehh_params
        self.backup_ciphertexts = backup_ciphertexts
        
        # Determine number of expected slots
        self.n_users = len(backup_ciphertexts)
        # Initialize buffer with None for all slots
        self._collected: list[dict | None] = [None] * self.n_users

    def receive_or_mark_offline(self, enc_result: dict | None, slot_index: int) -> None:
        """Accept a single SM's encrypted bundle, or mark it missing.

        Parameters
        ----------
        enc_result : dict | None – {ctx, h} from a SmartMeter. None if offline.
        slot_index : int – 0-based slot index of the meter.
        """
        self._collected[slot_index] = enc_result

    def aggregate(self) -> dict:
        """Run FEHH threshold aggregation.

        Replaces missing ciphertexts with backups, computes aggregate,
        and returns the result along with the online_mask.
        Clears the buffer afterwards.

        Returns
        -------
        dict – {C_prime, h_star, online_mask, n_online, n_offline}
        """
        # Run threshold aggregation
        result = fehh_agg_threshold(self._collected, self.backup_ciphertexts, self.fehh_params)
        
        # Clear buffer for next round
        self._collected = [None] * self.n_users
        
        return result
