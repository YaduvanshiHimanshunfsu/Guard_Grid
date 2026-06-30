#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    schemes/guardgrid_v3.py
# Purpose: High-level orchestrator for the 5 phases of GuardGrid V3.
# ──────────────────────────────────────────────────────────────────────

from crypto.pedersen_dkg import DKGOrchestrator
from crypto.mlkem import mlkem_keygen
from crypto.mife_wrapper import MIFEWrapper
from crypto.lattice_fe import LatticeFE
from schemes.fehh_pq import sm_encrypt_pipeline, cc_unmask_pipeline
import gmpy2
from crypto.pedersen_commitment import generate_pedersen_params

def v3_phase0_setup(K: int, T: int, p: int, g: int):
    """
    Phase 0: DKG + Parameter Setup
    """
    # 1. DKG for global parameters (simulated)
    orchestrator = DKGOrchestrator(num_nodes=K, threshold=T, p=p, g=g)
    global_pk = orchestrator.run_dkg()
    
    # 2. Pedersen parameters for ZKP
    zkp_params = generate_pedersen_params(p, g)
    
    # 3. Lattice FE parameters
    lattice_fe = LatticeFE(n_dim=64, q_modulus=16384, sigma=3.2)
    lfe_pk, lfe_msk = lattice_fe.setup()
    
    return {
        "global_pk": global_pk,
        "zkp_params": zkp_params,
        "lfe_pk": lfe_pk,
        "lfe_msk": lfe_msk,
        "p": p,
        "g": g
    }

def v3_phase1_key_exchange(n_meters: int):
    """
    Phase 1: Generates ML-KEM keys for CC (one per meter for simplicity).
    """
    cc_keys = []
    for _ in range(n_meters):
        ek, dk = mlkem_keygen()
        cc_keys.append({"ek": ek, "dk": dk})
    return cc_keys

def v3_phase2_collect(readings: list, cc_keys: list, mife_keys: list, sys_params: dict, epsilon: float, max_reading: int, mask_bound: int):
    """
    Phase 2: Meters encrypt and add DP noise.
    """
    bundles = []
    for i, x_i in enumerate(readings):
        bundle = sm_encrypt_pipeline(
            x_i=x_i,
            sm_id=i,
            cc_pk=cc_keys[i]["ek"],
            mife_key=mife_keys[i],
            lhh_g=sys_params["g"],
            lhh_p=sys_params["p"],
            zkp_params=sys_params["zkp_params"],
            epsilon=epsilon,
            max_reading=max_reading,
            mask_bound=mask_bound
        )
        bundles.append(bundle)
    return bundles
