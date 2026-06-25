"""
fehh.py – Functional Encryption with Homomorphic Hash (Algorithm 2).
======================================================================

This is the heart of the paper.  FEHH is not a single cryptographic
primitive — it is a *composition* of three primitives working together:

    1. DH key agreement   → generates session keys to mask readings
    2. MIFE encryption    → encrypts masked readings so the AG can
                            compute the aggregate without seeing parts
    3. LHH hashing        → creates an integrity proof that the CC
                            uses to catch a cheating AG

The composition creates a system where:
    - The AG learns ONLY the masked aggregate C' = Σ(xi + ki).
    - The AG cannot learn any individual xi because each is hidden
      behind a DH-derived session key ki.
    - The CC can remove the mask (it knows all ki via DH) and verify
      that the AG did not tamper (via LHH).
    - Nobody except the CC ever sees the true aggregate C = Σ xi.

Algorithm walkthrough  (matching the paper's Algorithm 2)
---------------------------------------------------------

FEHH.Setup:
    1. Generate DH parameters (p, g) for session key agreement.
    2. Generate separate LHH parameters (p', g') for hash verification.
    3. Initialize MIFE for n slots, dimension m=1.
    4. Derive the functional decryption key sk_y for y = [1,…,1]
       (the "sum" function).
    5. Generate n CC-side DH key pairs — one per smart meter.

FEHH.Enc (per smart meter i):
    1. SM_i and CC derive shared session key  ki = DH(SM_priv, CC_pub).
    2. Mask the reading:  mi = xi + ki.
    3. MIFE-encrypt mi into slot i.
    4. Compute LHH hash:  hi = g'^{mi} mod p'.
    5. Send (ciphertext, hash) to the AG.  Keep ki secret.

FEHH.Agg (at the AG):
    1. Collect all n ciphertexts.
    2. MIFE-decrypt with sk_y to get C' = Σ mi  (the masked aggregate).
    3. Multiply all hashes:  h* = ∏ hi mod p'.
    4. Forward (C', h*) to the CC.

FEHH.Dec (at the CC):
    1. Verify:  g'^{C'} mod p'  ==  h* ?
       If yes → AG was honest.  If no → AG cheated.
    2. Unmask:  C = C' - Σ ki.
    3. Recover float:  aggregate = C / SCALE.

Why separate DH and LHH groups?
    Domain separation.  If both used the same (p, g), a vulnerability
    in one context could leak information useful in the other.  With
    independent parameters, breaking the LHH group tells you nothing
    about the DH session keys, and vice versa.

Functions exposed
-----------------
    fehh_setup(n_users, bits)        → params dict
    fehh_enc(xi, slot, params, …)    → {ctx, h, ki}
    fehh_agg(enc_results, params)    → {C_prime, h_star}
    fehh_dec(C_prime, h_star, …)     → {verified, C, aggregate_float}
"""

from __future__ import annotations

from crypto.dh import dh_params, dh_generate, generate_session_key
from crypto.lhh import lhh_hash, lhh_eval, lhh_verify
from crypto.mife_wrapper import MIFEWrapper


# ──────────────────────────────────────────────────────────────────────────────
# FEHH.Setup
# ──────────────────────────────────────────────────────────────────────────────

def fehh_setup(n_users: int, bits: int = 512) -> dict:
    """Run the full FEHH setup phase.

    This is the most expensive step in the entire protocol.  It
    generates three independent sets of cryptographic parameters
    (DH, LHH, MIFE) and derives the functional decryption key.

    In a real deployment this runs exactly once when the TTP
    bootstraps the network.  After distributing keys, the TTP
    deletes its copies and goes permanently offline.

    Parameters
    ----------
    n_users : int – number of smart meters in the network.
    bits    : int – security parameter for prime generation.

    Returns
    -------
    dict containing:
        dh_p, dh_g       – DH group parameters
        lhh_p, lhh_g     – LHH group parameters (independent group)
        mife              – MIFEWrapper instance
        master_key        – MIFE master key (holds both pk and sk)
        sk_y              – functional decryption key for the sum query
        cc_keys           – list of (priv, pub) DH pairs for the CC
                            (one pair per smart meter)
    """
    # 1. DH group — used for session key agreement between SM and CC.
    dh_p, dh_g = dh_params(bits)

    # 2. LHH group — separate parameters for hash-based integrity checks.
    #    We call dh_params again; same maths, fresh random primes.
    lhh_p, lhh_g = dh_params(bits)

    # 3. MIFE — the multi-party encryption engine.
    #    n slots (one per meter), m=1 (scalar readings).
    mife = MIFEWrapper(n_users, m=1)
    master_key = mife.setup()

    # 4. Derive the "sum" key:  y = [[1], [1], …, [1]].
    #    When the AG uses this key to decrypt, it gets ⟨x, y⟩ = Σ xi.
    sk_y = mife.key_derive(master_key)

    # 5. CC generates one DH key pair per SM.
    #    cc_keys[i] = (cc_private_i, cc_public_i).
    #    SM_i will receive cc_public_i during key distribution.
    cc_keys = [dh_generate(dh_p, dh_g) for _ in range(n_users)]

    return {
        "dh_p": dh_p,
        "dh_g": dh_g,
        "lhh_p": lhh_p,
        "lhh_g": lhh_g,
        "mife": mife,
        "master_key": master_key,
        "sk_y": sk_y,
        "cc_keys": cc_keys,
    }


# ──────────────────────────────────────────────────────────────────────────────
# FEHH.Enc  (runs once per smart meter per round)
# ──────────────────────────────────────────────────────────────────────────────

def fehh_enc(x_i: int, slot_index: int, params: dict,
             sm_private: int, cc_public: int) -> dict:
    """Encrypt a single SM reading.

    This function is the SM's entire contribution to a round.  After
    calling this, the SM sends (ctx, h) to the AG and is done until
    the next round.

    The session key ki stays inside the SM — it is never transmitted.
    The CC independently derives the same ki using its own private key
    and the SM's public key (DH commutativity).

    Parameters
    ----------
    x_i        : int – raw reading, already scaled to an integer.
    slot_index : int – this SM's MIFE slot number (0-based).
    params     : dict – from fehh_setup().
    sm_private : int – SM's DH private key.
    cc_public  : int – CC's DH public key for this SM.

    Returns
    -------
    dict with:
        ctx – MIFE ciphertext (opaque PyMIFE object).
        h   – LHH hash value (int).
        ki  – session key (int, kept by SM, never sent to AG).
    """
    dh_p, dh_g = params["dh_p"], params["dh_g"]
    lhh_g, lhh_p = params["lhh_g"], params["lhh_p"]
    mife = params["mife"]
    master_key = params["master_key"]

    # Step 1: derive the session key ki from the DH shared secret.
    ki = generate_session_key(sm_private, cc_public, dh_p, dh_g)

    # Step 2: mask the reading.  The AG will see mi but cannot recover
    # xi without knowing ki.
    m_i = x_i + ki

    # Step 3: encrypt the masked value under MIFE.
    ctx = mife.encrypt(master_key, m_i, slot_index)

    # Step 4: compute the LHH hash of the masked value.
    # hi = g'^{mi} mod p'.  The AG will multiply all h_i values together.
    h_i = lhh_hash(m_i, lhh_g, lhh_p)

    return {"ctx": ctx, "h": h_i, "ki": ki}


# ──────────────────────────────────────────────────────────────────────────────
# FEHH.Agg  (runs at the Aggregation Gateway)
# ──────────────────────────────────────────────────────────────────────────────

def fehh_agg(enc_results: list[dict], params: dict) -> dict:
    """Aggregate ciphertexts and hashes.

    The AG collects all n bundles from the SMs and does two things:

    1. MIFE decryption with the sum-key sk_y → produces C', the masked
       aggregate.  Note that C' = Σ mi = Σ (xi + ki) — the AG cannot
       separate the readings from the masks.

    2. LHH hash evaluation → multiplies all individual hashes into h*.
       This h* will be checked by the CC against g'^{C'} mod p'.

    The BSGS bound is carefully computed.  Each masked value mi can be
    at most ~16,000 (reading up to 6000 from the p1 column + session
    key up to 10,000 from MASK_BOUND).  So the aggregate for n meters
    is at most n × 16,000.

    Parameters
    ----------
    enc_results : list[dict] – per-SM outputs of fehh_enc().
    params      : dict – from fehh_setup().

    Returns
    -------
    dict with:
        C_prime – the masked aggregate (int).
        h_star  – the evaluated hash product (int).
    """
    mife = params["mife"]
    master_key = params["master_key"]
    sk_y = params["sk_y"]
    lhh_g, lhh_p = params["lhh_g"], params["lhh_p"]

    # Collect the MIFE ciphertexts into a list.
    ctx_list = [r["ctx"] for r in enc_results]

    # MIFE decryption → masked aggregate C'.
    # Bound computation: each masked value ≤ 16,000.
    n = len(enc_results)
    max_per_sm = 16_000
    bound = (0, n * max_per_sm)
    C_prime = mife.decrypt(master_key, ctx_list, sk_y, bound)

    # LHH evaluation:  h* = ∏ hi mod p'  (all coefficients = 1).
    hash_list = [r["h"] for r in enc_results]
    h_star = lhh_eval(hash_list, lhh_g, lhh_p)

    return {"C_prime": C_prime, "h_star": h_star}


# ──────────────────────────────────────────────────────────────────────────────
# FEHH.Dec  (runs at the Control Center)
# ──────────────────────────────────────────────────────────────────────────────

def fehh_dec(C_prime: int, h_star: int, session_keys: list[int],
             params: dict, scale: int = 1000) -> dict:
    """Verify and decrypt the aggregate.

    This is the CC's core function.  It takes the AG's output (C', h*)
    and:
        1. Checks integrity via LHH verification.
        2. Strips the session key mask to recover the true aggregate.
        3. Converts back to the original floating-point scale.

    If verification fails, the CC knows the AG misbehaved — but still
    proceeds with decryption (the aggregate might be wrong, but the CC
    should log the failure and potentially revoke the AG's key).

    Parameters
    ----------
    C_prime      : int – masked aggregate from the AG.
    h_star       : int – hash product from the AG.
    session_keys : list[int] – all session keys [k1, …, kn].
    params       : dict – from fehh_setup().
    scale        : int – SCALE factor (default 1000).

    Returns
    -------
    dict with:
        verified       – bool, True if the AG was honest.
        C              – int, the true unmasked aggregate.
        aggregate_float – float, the aggregate in original units.
    """
    lhh_g, lhh_p = params["lhh_g"], params["lhh_p"]

    # Step 1: Verify that g'^{C'} mod p' == h*.
    verified = lhh_verify(C_prime, h_star, lhh_g, lhh_p)

    # Step 2: Remove the session key mask.
    # C' = Σ (xi + ki)  →  C = C' - Σ ki  =  Σ xi.
    C = C_prime - sum(session_keys)

    # Step 3: Undo the integer scaling.
    # We multiplied each reading by 1000 before encryption.
    aggregate_float = C / scale

    return {
        "verified": verified,
        "C": C,
        "aggregate_float": aggregate_float,
    }
