#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    schemes/fehh_pq.py
# Purpose: Post-Quantum FEHH. Combines MIFE with ML-KEM session keys,
#          Laplace DP noise, and ZKP range proofs.
# ──────────────────────────────────────────────────────────────────────

from crypto.mlkem import mlkem_keygen, mlkem_encaps, mlkem_decaps, derive_session_mask
from privacy.laplace import add_laplace_noise
from crypto.mife_wrapper import MIFEWrapper
from crypto.lhh import lhh_hash, lhh_eval, lhh_verify
from crypto.zkp_range import prove_range, verify_range
from network.packet import NetworkPacket

def sm_encrypt_pipeline(
    x_i: float, 
    sm_id: int, 
    cc_pk, 
    mife_key, 
    lhh_g, 
    lhh_p, 
    zkp_params, 
    epsilon: float,
    max_reading: int,
    mask_bound: int
) -> dict:
    """
    Phase 2: Smart Meter Encryption Pipeline (V3)
    """
    # 1. DP Noise
    sensitivity = max_reading
    x_noisy = add_laplace_noise(x_i, sensitivity, epsilon, clip_max=max_reading)
    
    # 2. PQ Session Key (Encapsulation)
    # The CC provides its public ML-KEM key (cc_pk).
    # The SM encapsulates a shared secret to it.
    shared_secret, ct_kem = mlkem_encaps(cc_pk)
    k_i = derive_session_mask(shared_secret, mask_bound)
    
    # 3. Masking (Linear addition, DO NOT modulo mask_bound here!)
    m_i = x_noisy + k_i
    
    # 4. MIFE Encryption
    # MIFE expects a list, we wrap m_i
    mife_ct = MIFEWrapper.encrypt([m_i], mife_key)
    
    # 5. LHH Hash
    h_i = lhh_hash(m_i, lhh_g, lhh_p)
    
    # 6. ZKP Range Proof
    # Proves x_noisy is in [0, max_reading]
    # For simulation, we use a random r for the commitment
    r_zkp = 42 # dummy randomness
    zkp_proof = prove_range(x_noisy, r_zkp, zkp_params, max_reading)
    
    # Return bundle
    return {
        "sm_id": sm_id,
        "ct_mife": mife_ct,
        "h_i": h_i,
        "ct_kem": ct_kem,
        "zkp": zkp_proof,
        "m_i_clear": m_i # Only for AG to use in simulation, normally hidden
    }

def cc_unmask_pipeline(
    ag_mife_result: int,
    ag_h_star: int,
    sm_bundles: list,
    cc_sk,
    lhh_g,
    lhh_p,
    mask_bound: int
) -> int:
    """
    Phase 3 (CC side): Verify LHH and unmask the aggregate.
    """
    # 1. Verify LHH
    if not lhh_verify(ag_mife_result, ag_h_star, lhh_g, lhh_p):
        raise ValueError("LHH Verification Failed! AG tampered with data.")
        
    # 2. Decapsulate session keys and unmask
    k_sum = 0
    for bundle in sm_bundles:
        shared_secret = mlkem_decaps(cc_sk, bundle["ct_kem"])
        k_i = derive_session_mask(shared_secret, mask_bound)
        k_sum += k_i
        
    # 3. True noisy aggregate
    aggregate = (ag_mife_result - k_sum)
    return aggregate
