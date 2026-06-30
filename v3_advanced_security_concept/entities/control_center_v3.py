#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    entities/control_center_v3.py
# Purpose: Control Center entity for V3.
# ──────────────────────────────────────────────────────────────────────

from schemes.fehh_pq import cc_unmask_pipeline

class ControlCenterV3:
    def __init__(self, cc_keys: list, sys_params: dict):
        self.cc_keys = cc_keys # List of {"ek": ek, "dk": dk}
        self.sys_params = sys_params

    def verify_and_unmask(self, mife_res: int, h_star: int, sm_bundles: list, mask_bound: int) -> int:
        """
        Verifies LHH and unmasks the aggregate using ML-KEM decapsulation.
        """
        # We have a CC key per meter (in a real system, the CC would have one PK
        # and meters would encapsulate to it. For this simulation structure we
        # mapped 1:1 to match the V1 DH logic).
        
        # We can re-use the pipeline but we need to do it meter by meter for keys
        from crypto.lhh import lhh_verify
        from crypto.mlkem import mlkem_decaps, derive_session_mask
        
        if not lhh_verify(mife_res, h_star, self.sys_params["g"], self.sys_params["p"]):
            raise ValueError("LHH Verification Failed! AG tampered with data.")
            
        k_sum = 0
        for i, bundle in enumerate(sm_bundles):
            dk = self.cc_keys[i]["dk"]
            shared_secret = mlkem_decaps(dk, bundle["ct_kem"])
            k_i = derive_session_mask(shared_secret, mask_bound)
            k_sum += k_i
            
        return mife_res - k_sum
