"""
guardgrid.py – Full GuardGrid Scheme (Section VI of the paper).
================================================================

This module sits at the very top of the cryptographic stack.  It
orchestrates the complete four-phase protocol by combining FEHH
(for privacy-preserving aggregation) with FEFQ (for cloud-side
function queries).

Architecture overview
---------------------
    Phase 1 – System Initialisation
        TTP runs FEHH.Setup + FEFQ.Setup.
        Generates all keys, distributes them, then goes offline.

    Phase 2 – Data Collection
        Each SM encrypts its reading using FEHH.Enc.
        Sends (ciphertext, hash) to the AG.

    Phase 3 – Aggregation + Verification
        AG runs FEHH.Agg → produces (C', h*).
        CC runs FEHH.Dec → verifies and unmasks → recovers C.

    Phase 4 – Function Queries
        CC encrypts C under FEFQ → sends ciphertext to Cloud.
        Cloud evaluates f(C) = a·C + b without learning C.

This module provides four public functions — one per phase — plus
a helper for cloud queries.  It is used in two contexts:

    1. By the entity classes (TTP, SM, AG, CC, Cloud) in the entities/
       package, which are the "actors" in the simulation.
    2. By the benchmark module, which calls these functions directly
       without going through the entity layer.

Relationship to entities/
--------------------------
    entities/ wraps this module in OOP classes with state management.
    This module is purely functional: every function takes explicit
    parameters and returns results, with no internal state.

    Why both?  Because the entities/ layer models the real-world
    architecture (who holds what key, who talks to whom), while this
    module models the mathematics (what computations happen in what
    order).  The benchmark module only cares about the maths and
    timing, not the actor model.
"""

from __future__ import annotations

from crypto.dh import dh_generate, generate_session_key
from crypto.fefq import fefq_setup, fefq_encrypt, fefq_keygen, fefq_decrypt
from schemes.fehh import fehh_setup, fehh_enc, fehh_agg, fehh_dec


# ──────────────────────────────────────────────────────────────────────────────
# Phase 1 – System Initialisation
# ──────────────────────────────────────────────────────────────────────────────

def guardgrid_init(n_users: int, bits: int = 512) -> dict:
    """Run the complete GuardGrid system initialisation.

    Combines FEHH setup (DH + LHH + MIFE) with FEFQ setup, and
    generates per-SM DH key pairs for session key agreement.

    Parameters
    ----------
    n_users : int – number of smart meters.
    bits    : int – security parameter (prime bit-length).

    Returns
    -------
    dict containing:
        fehh_params – everything from fehh_setup (DH, LHH, MIFE keys).
        fefq_params – FEFQ key pair (p, g, sk, pk).
        sm_dh_keys  – list of (private, public) DH pairs, one per SM.
    """
    # FEHH side: DH params, LHH params, MIFE keys, CC DH keys.
    fehh_params = fehh_setup(n_users, bits)

    # FEFQ side: independent DH-based FE for cloud queries.
    fefq_params = fefq_setup(bits)

    # Each SM gets its own DH key pair.  The public key is sent to the
    # CC so both sides can derive the same session key.
    dh_p, dh_g = fehh_params["dh_p"], fehh_params["dh_g"]
    sm_dh_keys = [dh_generate(dh_p, dh_g) for _ in range(n_users)]

    return {
        "fehh_params": fehh_params,
        "fefq_params": fefq_params,
        "sm_dh_keys": sm_dh_keys,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Phase 2 – Data Collection  (all SMs encrypt)
# ──────────────────────────────────────────────────────────────────────────────

def guardgrid_collect(readings: list[int], sys_params: dict) -> list[dict]:
    """Each smart meter encrypts its reading.

    Iterates through all readings and calls fehh_enc for each one.
    In the real world these encryptions happen in parallel on separate
    devices; here we do them sequentially for simplicity.

    Parameters
    ----------
    readings   : list[int] – integer-scaled meter readings [x1, …, xn].
    sys_params : dict – output of guardgrid_init.

    Returns
    -------
    list[dict] – per-SM encryption bundles {ctx, h, ki}.
    """
    fehh_params = sys_params["fehh_params"]
    sm_dh_keys = sys_params["sm_dh_keys"]
    cc_keys = fehh_params["cc_keys"]

    enc_results = []
    for i, x_i in enumerate(readings):
        sm_priv, _sm_pub = sm_dh_keys[i]
        _cc_priv, cc_pub = cc_keys[i]

        result = fehh_enc(
            x_i=x_i,
            slot_index=i,
            params=fehh_params,
            sm_private=sm_priv,
            cc_public=cc_pub,
        )
        enc_results.append(result)

    return enc_results


# ──────────────────────────────────────────────────────────────────────────────
# Phase 3 – Aggregation + Verification
# ──────────────────────────────────────────────────────────────────────────────

def guardgrid_aggregate(enc_results: list[dict], sys_params: dict,
                        scale: int = 1000) -> dict:
    """AG aggregates, then CC verifies and unmasks.

    This function encapsulates both the AG and CC actions because
    from the maths perspective they are two steps of the same pipeline.
    The entity layer (entities/agg_gateway.py, entities/control_center.py)
    splits them into separate actor methods.

    Parameters
    ----------
    enc_results : list[dict] – outputs of Phase 2.
    sys_params  : dict – output of guardgrid_init.
    scale       : int – SCALE factor to convert back to float.

    Returns
    -------
    dict with keys: verified, C, aggregate_float, C_prime, h_star.
    """
    fehh_params = sys_params["fehh_params"]
    sm_dh_keys = sys_params["sm_dh_keys"]
    cc_keys = fehh_params["cc_keys"]
    dh_p = fehh_params["dh_p"]
    dh_g = fehh_params["dh_g"]

    # --- AG side: aggregate ciphertexts + hashes ---
    agg = fehh_agg(enc_results, fehh_params)

    # --- CC side: reconstruct session keys, then verify + unmask ---
    session_keys = []
    for i in range(len(enc_results)):
        cc_priv, _cc_pub = cc_keys[i]
        _sm_priv, sm_pub = sm_dh_keys[i]
        ki = generate_session_key(cc_priv, sm_pub, dh_p, dh_g)
        session_keys.append(ki)

    dec = fehh_dec(
        C_prime=agg["C_prime"],
        h_star=agg["h_star"],
        session_keys=session_keys,
        params=fehh_params,
        scale=scale,
    )

    return {**dec, "C_prime": agg["C_prime"], "h_star": agg["h_star"]}


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4 – Function Queries  (CC → Cloud)
# ──────────────────────────────────────────────────────────────────────────────

def guardgrid_encrypt_for_cloud(aggregate: int, sys_params: dict) -> tuple:
    """CC encrypts the true aggregate under FEFQ for the cloud.

    After this call, the CC uploads the ciphertext to the Cloud Server.
    The Cloud can then evaluate authorized functions on the ciphertext
    without ever seeing the raw aggregate value.

    Returns
    -------
    tuple[int, int] – the FEFQ ciphertext (c1, c2).
    """
    return fefq_encrypt(aggregate, sys_params["fefq_params"])


def guardgrid_cloud_query(ct: tuple, sys_params: dict,
                          a: int = 1, b: int = 0) -> int:
    """Cloud evaluates f(x) = a·x + b on the encrypted aggregate.

    The Cloud derives a function key for the specific (a, b) pair
    and uses it to decrypt the function result — never the raw value.

    Parameters
    ----------
    ct         : tuple – FEFQ ciphertext.
    sys_params : dict – output of guardgrid_init.
    a, b       : int – linear function coefficients.

    Returns
    -------
    int – the result f(aggregate) = a · aggregate + b.
    """
    fk = fefq_keygen(sys_params["fefq_params"], a=a, b=b)
    return fefq_decrypt(ct, fk, sys_params["fefq_params"])
