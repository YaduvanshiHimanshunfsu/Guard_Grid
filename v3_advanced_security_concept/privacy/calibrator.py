#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    privacy/calibrator.py
# Purpose: Utilities for determining dataset sensitivity and analyzing
#          privacy/accuracy trade-offs.
# ──────────────────────────────────────────────────────────────────────

from privacy.laplace import compute_aggregate_error_std

def calibrate_sensitivity(max_expected_reading_kw: float, scale_factor: int) -> float:
    """
    Calculate the sensitivity Delta f for the sum query.
    Sensitivity is the maximum change one individual can make to the aggregate.
    Since one meter can report at most max_expected_reading_kw, and the minimum is 0,
    the sensitivity is max_expected_reading_kw * scale_factor.
    """
    return max_expected_reading_kw * scale_factor

def analyze_tradeoff(n_meters: int, sensitivity: float, epsilons: list[float], scale_factor: int):
    """
    Print a simple table showing how the choice of Epsilon affects aggregate billing accuracy.
    """
    print(f"--- DP Accuracy Trade-off Analysis (N={n_meters} meters) ---")
    print(f"Max single-meter reading: {sensitivity/scale_factor:.2f} kW")
    print(f"{'Epsilon (Daily)':<16} | {'Epsilon (Slot)':<15} | {'Agg Std Dev (scaled)':<22} | {'Agg Std Dev (kW)':<18}")
    print("-" * 75)
    
    slots_per_day = 96
    
    for ep_day in epsilons:
        ep_slot = ep_day / slots_per_day
        std_dev = compute_aggregate_error_std(n_meters, sensitivity, ep_slot)
        std_dev_kw = std_dev / scale_factor
        print(f"{ep_day:<16.2f} | {ep_slot:<15.4f} | {std_dev:<22.2f} | +/- {std_dev_kw:<14.2f} kW")
        
    print("-" * 75)
    print("Note: If the +/- kW is acceptable for neighborhood billing error, the epsilon is viable.\n")
