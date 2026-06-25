#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    schemes/timeseries_aggregator.py
# Purpose: Orchestrates FEHH aggregation across multiple time slots
#          (e.g., 96 slots for a full day).
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

from schemes.fehh_threshold import fehh_agg_threshold, fehh_dec_threshold
from entities.smart_meter import SmartMeter


def aggregate_time_slot(slot_index: int,
                        enc_results: list[dict | None],
                        sys_params: dict,
                        session_keys: list[int],
                        scale: int = 1000) -> dict:
    """Run one round of FEHH for a single 15-minute slot.

    Parameters
    ----------
    slot_index   : int – the 0-95 slot ID (mostly for logging/tracking).
    enc_results  : list[dict | None] – ciphertexts from SMs (None = offline).
    sys_params   : dict – system params containing fehh_params and backups.
    session_keys : list[int] – precomputed DH session keys for all SMs.
    scale        : int – SCALE factor for converting to float.

    Returns
    -------
    dict – {verified, C, aggregate_float, n_online, n_offline, slot_index}
    """
    fehh_params = sys_params["fehh_params"]
    backup_ciphertexts = sys_params["backup_ciphertexts"]
    cc_keys = fehh_params["cc_keys"]
    sm_dh_publics = sys_params["sm_dh_publics"]
    dh_p = fehh_params["dh_p"]
    dh_g = fehh_params["dh_g"]

    # --- AG side ---
    agg = fehh_agg_threshold(enc_results, backup_ciphertexts, fehh_params)

    # --- CC side ---
    # In V2, session keys are derived once in Phase 1 and passed in.

    dummy_session_keys = [b["ki_dummy"] for b in backup_ciphertexts]

    dec = fehh_dec_threshold(
        C_prime=agg["C_prime"],
        h_star=agg["h_star"],
        session_keys=session_keys,
        dummy_session_keys=dummy_session_keys,
        online_mask=agg["online_mask"],
        params=fehh_params,
        scale=scale
    )

    return {
        "slot_index": slot_index,
        "verified": dec["verified"],
        "C": dec["C"],
        "aggregate_float": dec["aggregate_float"],
        "n_online": dec["n_online"],
        "n_offline": agg["n_offline"]
    }
