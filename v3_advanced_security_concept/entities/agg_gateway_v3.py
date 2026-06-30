#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    entities/agg_gateway_v3.py
# Purpose: Aggregation Gateway entity for V3.
# ──────────────────────────────────────────────────────────────────────

from crypto.mife_wrapper import MIFEWrapper
from crypto.zkp_range import verify_range

class AggGatewayV3:
    def __init__(self, mife_pk: dict, sys_params: dict):
        self.mife_pk = mife_pk
        self.sys_params = sys_params

    def aggregate(self, sm_bundles: list) -> dict:
        """
        1. Verify ZKP Range Proofs.
        2. Compute MIFE sum.
        3. Compute LHH product.
        """
        # 1. Verify ZKPs
        for bundle in sm_bundles:
            if not verify_range(bundle["zkp"], self.sys_params["zkp_params"]):
                raise ValueError(f"ZKP verification failed for meter {bundle['sm_id']}")
                
        # 2. MIFE aggregate
        cts = [b["ct_mife"] for b in sm_bundles]
        # In this simulation, mife_pk is just the MIFE public key from setup
        # MIFEWrapper.decrypt(pk, sk_y, ciphertexts)
        # We need the AG's evaluation key (sk_y).
        # We'll pass it in when called.
        pass
        
    def execute_aggregation(self, sm_bundles: list, sk_y: dict, lhh_p: int) -> tuple:
        """
        Execute MIFE and LHH.
        """
        cts = [b["ct_mife"] for b in sm_bundles]
        mife_res = MIFEWrapper.decrypt(self.mife_pk, sk_y, cts)
        
        # LHH Product
        h_star = 1
        for b in sm_bundles:
            h_star = (h_star * b["h_i"]) % lhh_p
            
        return mife_res, h_star
