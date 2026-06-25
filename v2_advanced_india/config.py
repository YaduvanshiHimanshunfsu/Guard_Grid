#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    config.py
# Purpose: Central configuration for the extended simulation.
#          Includes all V1 constants PLUS India-specific parameters
#          for time-series metering (RDSS), fault tolerance, billing,
#          anomaly detection, and AG credit scoring.
# Author:  GuardGrid Team
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class GuardGridConfig:
    """Immutable configuration for V2.

    Extends V1's config with India-specific parameters.

    WARNING: 512-bit primes are for simulation only.
             Production deployments require >= 2048 bits.
    """

    # ── Crypto params (same as V1) ──
    security_parameter_bits: int = 512
    default_user_count:      int = 10
    scale_factor:            int = 1000
    dh_group_bits:           int = 512
    data_path:              Path = Path("../shared/smart_grid_stability_augmented.csv")

    # ── Time-series (India RDSS specification) ──
    # India's Revamped Distribution Sector Scheme (RDSS) mandates
    # 15-minute interval metering for all smart meters.
    # 24 hours × 4 slots/hour = 96 slots per day.
    slots_per_day:      int = 96
    slot_duration_min:  int = 15
    default_sim_days:   int = 1

    # ── Fault tolerance ──
    # Alert threshold: if more than 30% of meters are offline
    # simultaneously, it may indicate a coordinated attack.
    max_offline_pct:    float = 0.30
    default_offline_count: int = 0

    # ── AG Credit scoring (Section VI-A of the paper) ──
    credit_initial:          int = 100
    credit_pass_bonus:       int = 2
    credit_fail_penalty:     int = 15
    credit_flag_threshold:   int = 50
    credit_revoke_threshold: int = 20

    # ── Anomaly detection ──
    anomaly_window_days:  int = 7
    anomaly_z_threshold:  float = 2.0


CONFIG = GuardGridConfig()

# ── Module-level aliases (backward compatible with V1 imports) ──
LAMBDA     = CONFIG.security_parameter_bits
N_USERS    = CONFIG.default_user_count
SCALE      = CONFIG.scale_factor
GROUP_BITS = CONFIG.dh_group_bits
DATA_PATH  = str(CONFIG.data_path)

# ── V2-specific aliases ──
SLOTS_PER_DAY       = CONFIG.slots_per_day
SLOT_DURATION_MIN   = CONFIG.slot_duration_min
DEFAULT_SIM_DAYS    = CONFIG.default_sim_days
MAX_OFFLINE_PCT     = CONFIG.max_offline_pct
DEFAULT_OFFLINE_COUNT = CONFIG.default_offline_count
CREDIT_INITIAL      = CONFIG.credit_initial
CREDIT_PASS_BONUS   = CONFIG.credit_pass_bonus
CREDIT_FAIL_PENALTY = CONFIG.credit_fail_penalty
CREDIT_FLAG         = CONFIG.credit_flag_threshold
CREDIT_REVOKE       = CONFIG.credit_revoke_threshold
ANOMALY_WINDOW      = CONFIG.anomaly_window_days
ANOMALY_Z           = CONFIG.anomaly_z_threshold
