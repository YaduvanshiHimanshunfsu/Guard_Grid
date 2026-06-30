#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    entities/smart_meter_v3.py
# Purpose: Smart Meter entity for V3.
# ──────────────────────────────────────────────────────────────────────

from schemes.fehh_pq import sm_encrypt_pipeline

class SmartMeterV3:
    def __init__(self, sm_id: int, mife_key: dict, cc_pk: bytes, sys_params: dict):
        self.sm_id = sm_id
        self.mife_key = mife_key
        self.cc_pk = cc_pk
        self.sys_params = sys_params

    def report_reading(self, reading: float, epsilon: float, max_reading: int, mask_bound: int) -> dict:
        """
        Encrypts and reports the reading.
        Returns the V3 transmission bundle.
        """
        return sm_encrypt_pipeline(
            x_i=reading,
            sm_id=self.sm_id,
            cc_pk=self.cc_pk,
            mife_key=self.mife_key,
            lhh_g=self.sys_params["g"],
            lhh_p=self.sys_params["p"],
            zkp_params=self.sys_params["zkp_params"],
            epsilon=epsilon,
            max_reading=max_reading,
            mask_bound=mask_bound
        )
