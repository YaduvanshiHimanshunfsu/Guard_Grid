#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    data/timeseries_loader.py
# Purpose: Reshape the flat CSV into a 3D time-series structure
#          simulating 15-minute interval metering per India's RDSS.
#
# ⚠ SYNTHETIC MAPPING:
#   The original dataset rows are INDEPENDENT simulations, NOT
#   sequential time readings.  We treat consecutive rows as consecutive
#   15-minute slots purely for demonstration.  Any publication must
#   state this caveat clearly.
#
# Capacity: 60,000 rows / 96 slots = 625 meter-days.
#           Example configs: n=6 × d=100, or n=50 × d=12.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SCALE, DATA_PATH, SLOTS_PER_DAY  # noqa: E402


def load_timeseries(n_users: int, n_days: int = 1,
                    col: str = "p1") -> list[list[list[int]]]:
    """Load time-series structured readings from the CSV.

    Output shape: readings[user_idx][day_idx][slot_idx] → int.

    Parameters
    ----------
    n_users : int – number of simulated smart meters.
    n_days  : int – number of simulated days (each = 96 slots).
    col     : str – column to extract (default "p1").

    Returns
    -------
    list[list[list[int]]] – 3D integer-scaled readings.

    Raises
    ------
    FileNotFoundError – if CSV is missing.
    ValueError        – if dataset is too small for the requested config.
    """
    total_rows_needed = n_users * n_days * SLOTS_PER_DAY

    csv_path = Path(__file__).resolve().parent.parent / DATA_PATH
    if not csv_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {csv_path}. "
            "Ensure the CSV is in the shared/ folder."
        )

    df = pd.read_csv(csv_path)

    if col not in df.columns:
        raise KeyError(f"Column '{col}' not found. Available: {list(df.columns)}")

    if len(df) < total_rows_needed:
        raise ValueError(
            f"Need {total_rows_needed} rows for {n_users} users × {n_days} days × "
            f"{SLOTS_PER_DAY} slots, but dataset has only {len(df)} rows. "
            f"Reduce n_users or n_days."
        )

    raw = (df[col].head(total_rows_needed) * SCALE).astype(int).tolist()

    # Reshape: flat → [user][day][slot].
    readings = []
    idx = 0
    for _user in range(n_users):
        user_days = []
        for _day in range(n_days):
            day_slots = raw[idx : idx + SLOTS_PER_DAY]
            user_days.append(day_slots)
            idx += SLOTS_PER_DAY
        readings.append(user_days)

    return readings


def get_slot_readings(timeseries: list[list[list[int]]],
                      day: int, slot: int) -> list[int]:
    """Extract all users' readings for a specific day and time slot.

    This is what gets fed into the FEHH encryption pipeline for one round.

    Parameters
    ----------
    timeseries : 3D readings from load_timeseries.
    day        : day index (0-based).
    slot       : slot index (0-based, 0–95).

    Returns
    -------
    list[int] – one reading per user for this time slot.
    """
    return [timeseries[user][day][slot] for user in range(len(timeseries))]
