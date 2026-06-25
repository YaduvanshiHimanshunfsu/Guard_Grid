#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    benchmark/measure.py
# Purpose: Extended benchmarks including fault tolerance overhead
#          and time-series daily cycle timing.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import sys
import time
from pathlib import Path
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import SCALE, SLOTS_PER_DAY
from data.timeseries_loader import load_timeseries, get_slot_readings
from schemes.guardgrid import guardgrid_encrypt_for_cloud
from schemes.timeseries_aggregator import aggregate_time_slot
from entities.ttp import TTP
from entities.smart_meter import SmartMeter
from entities.agg_gateway import AggregationGateway


def _run_v2_pipeline(n: int, faults: int = 0, bits: int = 512) -> dict:
    """Run one full slot in V2 to measure fault tolerance overhead."""
    # Setup
    t0 = time.perf_counter()
    ttp = TTP(n, bits)
    sys_params = ttp.initialise()
    t_init = time.perf_counter() - t0

    fehh_params = sys_params["fehh_params"]
    smart_meters = []
    for i in range(n):
        sm_keys = ttp.get_sm_keys(i)
        sm = SmartMeter(i, sm_keys["sm_dh_private"], sm_keys["cc_dh_public"], fehh_params)
        smart_meters.append(sm)

    ag = AggregationGateway(fehh_params, sys_params["backup_ciphertexts"])

    # Load 1 slot
    timeseries = load_timeseries(n, n_days=1)
    slot_readings = get_slot_readings(timeseries, day=0, slot=0)

    # Encrypt
    t0 = time.perf_counter()
    for i, sm in enumerate(smart_meters):
        if i >= faults:  # First `faults` meters are offline
            res = sm.encrypt(slot_readings[i])
            ag.receive_or_mark_offline(res, i)
        else:
            ag.receive_or_mark_offline(None, i)
    t_enc_total = time.perf_counter() - t0
    t_enc_per_sm = t_enc_total / (n - faults) if n > faults else 0

    # Aggregate
    t0 = time.perf_counter()
    enc_results = ag._collected
    agg_res = aggregate_time_slot(0, enc_results, sys_params, SCALE)
    t_agg = time.perf_counter() - t0

    return {
        "n": n,
        "faults": faults,
        "t_init": t_init,
        "t_enc_per_sm": t_enc_per_sm,
        "t_enc_total": t_enc_total,
        "t_agg": t_agg,
        "verified": agg_res["verified"]
    }


def run_benchmarks(n_values: list[int] | None = None) -> list[dict]:
    if n_values is None:
        n_values = [10, 50, 100]

    results = []
    
    # 1. Standard scaling (0 faults)
    for n in n_values:
        print(f"\nBenchmarking n = {n}, faults = 0")
        r = _run_v2_pipeline(n, faults=0)
        results.append(r)
        print(f"  ✓ agg = {r['t_agg']:.4f}s")
        
    # 2. Fault tolerance overhead
    n = 50
    for faults in [0, 5, 15, 25]:
        print(f"\nBenchmarking n = {n}, faults = {faults}")
        r = _run_v2_pipeline(n, faults=faults)
        results.append(r)
        print(f"  ✓ agg = {r['t_agg']:.4f}s")

    return results


def plot_results(results: list[dict], save_dir: str = "plots") -> None:
    Path(save_dir).mkdir(exist_ok=True)
    plt.style.use("seaborn-v0_8-darkgrid")

    # Plot Fault Tolerance Overhead
    fault_res = [r for r in results if r["n"] == 50]
    faults = [r["faults"] for r in fault_res]
    aggs = [r["t_agg"] * 1000 for r in fault_res]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(faults, aggs, "s-", color="#FF5722", linewidth=2, markersize=8)
    ax.set_xlabel("Number of Offline Meters (out of 50)")
    ax.set_ylabel("Aggregation Time (ms)")
    ax.set_title("V2 Benchmark: Fault Tolerance Overhead (n=50)")
    fig.tight_layout()
    fig.savefig(f"{save_dir}/v2_fault_overhead.png", dpi=150)
    plt.close(fig)

    print(f"\n✓ Plots saved to '{save_dir}/'")


if __name__ == "__main__":
    results = run_benchmarks()
    plot_results(results)
