#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    config.py
# Purpose: Central configuration for the V3 simulation.
# ──────────────────────────────────────────────────────────────────────

from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True, slots=True)
class GuardGridConfigV3:
    """Configuration for V3."""

    # ── Crypto params (V1/V2 baseline) ──
    security_parameter_bits: int = 512
    default_user_count:      int = 10
    scale_factor:            int = 1000
    dh_group_bits:           int = 512 # Still used for LHH hash group
    data_path:              Path = Path("../shared/smart_grid_stability_augmented.csv")

    # ── DP Noise Params ──
    dp_epsilon_daily:        float = 50.0 # Strict privacy budget (increased for small N demo accuracy)
    max_reading_kw:          float = 6.0 # Max expected reading from dataset
    
    # ── DKG Params ──
    dkg_k_nodes:             int = 5
    dkg_t_threshold:         int = 3

    # ── Network Params ──
    padder_lambda:           float = 50.0 # dummy packets per hour
    
CONFIG = GuardGridConfigV3()

LAMBDA     = CONFIG.security_parameter_bits
N_USERS    = CONFIG.default_user_count
SCALE      = CONFIG.scale_factor
GROUP_BITS = CONFIG.dh_group_bits
DATA_PATH  = str(CONFIG.data_path)
EPSILON    = CONFIG.dp_epsilon_daily
MAX_READING = int(CONFIG.max_reading_kw * SCALE)
DKG_K      = CONFIG.dkg_k_nodes
DKG_T      = CONFIG.dkg_t_threshold
MASK_BOUND = 10_000
