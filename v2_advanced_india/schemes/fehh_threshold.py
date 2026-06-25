#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    schemes/fehh_threshold.py
# Purpose: Fault-tolerant extension of FEHH that handles offline meters
#          using dummy (zero-reading) ciphertexts.
#
# Problem: Standard FEHH requires exactly n ciphertexts.  If meter i
#          is offline, its ciphertext is missing, and MIFE decryption
#          fails because it expects one input per slot.
#
# Solution: At setup time, the TTP pre-generates a "backup" ciphertext
#           for every slot by encrypting a zero reading (x_i = 0).
#           When a meter goes offline, the backup is substituted in.
#           The aggregate then equals the sum of only the online meters'
#           readings — the offline meters contribute 0.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

from crypto.dh import generate_session_key
from crypto.lhh import lhh_hash, lhh_eval, lhh_verify
from crypto.mife_wrapper import MIFEWrapper
from schemes.fehh import fehh_enc


def generate_backup_ciphertexts(params: dict) -> list[dict]:
    """Generate one zero-reading backup ciphertext per slot.

    Called once during TTP initialisation.  Each backup encrypts
    x_i = 0 with a deterministic session key so the CC knows how
    to unmask it later.

    Parameters
    ----------
    params : dict – output of fehh_setup.

    Returns
    -------
    list[dict] – backup bundles [{ctx, h, ki_dummy}, …] per slot.
    """
    n_users = len(params["cc_keys"])
    mife = params["mife"]
    master_key = params["master_key"]
    lhh_g, lhh_p = params["lhh_g"], params["lhh_p"]
    dh_p, dh_g = params["dh_p"], params["dh_g"]

    backups = []
    for i in range(n_users):
        # Use a fixed "dummy" session key of 0 for simplicity.
        # The CC knows this is 0, so it can adjust the mask sum.
        ki_dummy = 0
        m_i = 0 + ki_dummy     # x_i=0 + ki=0 = 0

        ctx = mife.encrypt(master_key, m_i, i)
        h_i = lhh_hash(m_i, lhh_g, lhh_p)

        backups.append({"ctx": ctx, "h": h_i, "ki_dummy": ki_dummy})

    return backups


def fehh_agg_threshold(enc_results: list[dict | None],
                       backup_ciphertexts: list[dict],
                       params: dict) -> dict:
    """Aggregate with fault tolerance — substitute backups for offline meters.

    Parameters
    ----------
    enc_results         : list[dict | None] – per-SM results.  None = offline.
    backup_ciphertexts  : list[dict] – from generate_backup_ciphertexts().
    params              : dict – FEHH params.

    Returns
    -------
    dict – {C_prime, h_star, online_mask, n_online, n_offline}
    """
    n = len(enc_results)
    mife = params["mife"]
    master_key = params["master_key"]
    sk_y = params["sk_y"]
    lhh_g, lhh_p = params["lhh_g"], params["lhh_p"]

    # Build the full list — substitute backups where needed.
    online_mask = []
    filled_results = []
    for i in range(n):
        if enc_results[i] is not None:
            filled_results.append(enc_results[i])
            online_mask.append(True)
        else:
            filled_results.append(backup_ciphertexts[i])
            online_mask.append(False)

    # MIFE decryption (all n slots filled).
    ctx_list = [r["ctx"] for r in filled_results]
    max_per_sm = 16_000
    bound = (0, n * max_per_sm)
    C_prime = mife.decrypt(master_key, ctx_list, sk_y, bound)

    # LHH evaluation.
    hash_list = [r["h"] for r in filled_results]
    h_star = lhh_eval(hash_list, lhh_g, lhh_p)

    n_online = online_mask.count(True)
    return {
        "C_prime": C_prime,
        "h_star": h_star,
        "online_mask": online_mask,
        "n_online": n_online,
        "n_offline": n - n_online,
    }


def fehh_dec_threshold(C_prime: int, h_star: int,
                       session_keys: list[int],
                       dummy_session_keys: list[int],
                       online_mask: list[bool],
                       params: dict, scale: int = 1000) -> dict:
    """Verify and decrypt with awareness of which meters were offline.

    The session key sum is adjusted:
        For online meters  → use the real session key ki.
        For offline meters → use the dummy key (0).

    Parameters
    ----------
    C_prime            : int – masked aggregate.
    h_star             : int – hash product.
    session_keys       : list[int] – real session keys for ALL n meters.
    dummy_session_keys : list[int] – dummy keys (typically all zeros).
    online_mask        : list[bool] – True = online.
    params             : dict – FEHH params.
    scale              : int – SCALE factor.

    Returns
    -------
    dict – {verified, C, aggregate_float, n_online}
    """
    lhh_g, lhh_p = params["lhh_g"], params["lhh_p"]

    verified = lhh_verify(C_prime, h_star, lhh_g, lhh_p)

    # Build the adjusted key sum.
    total_mask = 0
    for i, is_online in enumerate(online_mask):
        if is_online:
            total_mask += session_keys[i]
        else:
            total_mask += dummy_session_keys[i]

    C = C_prime - total_mask
    aggregate_float = C / scale

    return {
        "verified": verified,
        "C": C,
        "aggregate_float": aggregate_float,
        "n_online": online_mask.count(True),
    }
