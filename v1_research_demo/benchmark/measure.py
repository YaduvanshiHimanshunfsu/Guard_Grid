"""
measure.py – Benchmark module for performance evaluation.
============================================================

Purpose
-------
This module automates what would otherwise be tedious manual timing:
run the full GuardGrid pipeline at different scales (n = 1, 10, 50,
100, 500 smart meters) and record how long each phase takes.

The output is a set of plots comparable to Figures 3–7 in the paper:

    Figure 3 – Encryption time per SM vs n.
               Shows whether per-SM cost scales or stays constant.
               Expectation: roughly constant (MIFE encrypt is per-slot).

    Figure 4 – Aggregation time vs n.
               Shows the AG's cost as meter count grows.
               Expectation: linear in n (MIFE decrypt touches n ciphertexts).

    Figure 5 – Total pipeline time vs n.
               End-to-end wall clock from init to cloud query.

    Figure 6 – Per-entity cost breakdown (stacked bar).
               Visualises where time is spent: SM, AG, or CC.

    Figure 7 – Communication cost vs n.
               Estimates total bytes transmitted (ciphertext sizes).

How communication cost is estimated
-------------------------------------
We use Python's pickle to serialize one MIFE ciphertext and measure
its byte size.  The total communication cost is then:
    single_ciphertext_bytes × n.

This is a rough estimate — real network overhead (headers, TLS, etc.)
would add more — but it captures the asymptotic scaling behaviour.

Usage
-----
    From the command line:
        python main.py benchmark

    Or directly:
        python -m benchmark.measure
"""

from __future__ import annotations

import sys
import time
import pickle
from pathlib import Path

import matplotlib.pyplot as plt

# Ensure the V1 root is on the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import SCALE                       # noqa: E402
from data.loader import load_readings          # noqa: E402
from schemes.guardgrid import (                # noqa: E402
    guardgrid_init,
    guardgrid_collect,
    guardgrid_aggregate,
    guardgrid_encrypt_for_cloud,
    guardgrid_cloud_query,
)


# ──────────────────────────────────────────────────────────────────────────────
# Core timing harness
# ──────────────────────────────────────────────────────────────────────────────

def _run_pipeline(n: int, bits: int = 512) -> dict:
    """Run the full GuardGrid pipeline for n users and time each phase.

    Returns a dict of timings (seconds) and metadata.
    """
    readings = load_readings(n)

    # Phase 1: System Init.
    t0 = time.perf_counter()
    sys_params = guardgrid_init(n, bits)
    t_init = time.perf_counter() - t0

    # Phase 2: Data Collection (SM encryption).
    t0 = time.perf_counter()
    enc_results = guardgrid_collect(readings, sys_params)
    t_enc_total = time.perf_counter() - t0
    t_enc_per_sm = t_enc_total / n

    # Phase 3: Aggregation + Verification.
    t0 = time.perf_counter()
    agg_result = guardgrid_aggregate(enc_results, sys_params, scale=SCALE)
    t_agg = time.perf_counter() - t0

    # Phase 4: FEFQ encrypt + cloud query.
    t0 = time.perf_counter()
    ct = guardgrid_encrypt_for_cloud(agg_result["C"], sys_params)
    t_fefq_enc = time.perf_counter() - t0

    t0 = time.perf_counter()
    _query_result = guardgrid_cloud_query(ct, sys_params, a=1, b=500)
    t_fefq_query = time.perf_counter() - t0

    # Communication cost estimate: serialize one ciphertext, multiply by n.
    try:
        single_ct_bytes = len(pickle.dumps(enc_results[0]["ctx"]))
    except Exception:
        single_ct_bytes = 0
    total_comm_bytes = single_ct_bytes * n

    return {
        "n": n,
        "t_init": t_init,
        "t_enc_per_sm": t_enc_per_sm,
        "t_enc_total": t_enc_total,
        "t_agg": t_agg,
        "t_fefq_enc": t_fefq_enc,
        "t_fefq_query": t_fefq_query,
        "t_pipeline": t_init + t_enc_total + t_agg + t_fefq_enc + t_fefq_query,
        "comm_bytes": total_comm_bytes,
        "verified": agg_result["verified"],
        "aggregate": agg_result["aggregate_float"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Sweep across multiple n values
# ──────────────────────────────────────────────────────────────────────────────

def run_benchmarks(n_values: list[int] | None = None,
                   bits: int = 512) -> list[dict]:
    """Run the pipeline for each n and collect timing results.

    Parameters
    ----------
    n_values : list[int] | None
        User counts to test.  Default [1, 10, 50, 100, 500].
    bits : int
        Security parameter for prime generation.

    Returns
    -------
    list[dict] – one result dict per n value.
    """
    if n_values is None:
        n_values = [1, 10, 50, 100, 500]

    results = []
    for n in n_values:
        print(f"\n{'='*60}")
        print(f"  Benchmarking  n = {n}")
        print(f"{'='*60}")
        r = _run_pipeline(n, bits)
        results.append(r)
        print(f"  ✓  init     = {r['t_init']:.4f}s")
        print(f"  ✓  enc/SM   = {r['t_enc_per_sm']:.6f}s")
        print(f"  ✓  agg      = {r['t_agg']:.4f}s")
        print(f"  ✓  pipeline = {r['t_pipeline']:.4f}s")
        print(f"  ✓  comm     = {r['comm_bytes']} bytes")
        print(f"  ✓  verified = {r['verified']}")
        print(f"  ✓  aggregate= {r['aggregate']:.4f}")

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Plotting  (generates Figures 3–7 equivalents)
# ──────────────────────────────────────────────────────────────────────────────

def plot_results(results: list[dict], save_dir: str = "plots") -> None:
    """Generate benchmark plots and save them as PNGs.

    Each plot corresponds to one of the paper's evaluation figures.
    """
    Path(save_dir).mkdir(exist_ok=True)

    ns = [r["n"] for r in results]

    plt.style.use("seaborn-v0_8-darkgrid")
    fig_kw = dict(figsize=(8, 5))

    # ── Figure 3: Encryption time per SM ──
    fig, ax = plt.subplots(**fig_kw)
    ax.plot(ns, [r["t_enc_per_sm"] * 1000 for r in results],
            "o-", color="#2196F3", linewidth=2, markersize=8)
    ax.set_xlabel("Number of Smart Meters (n)")
    ax.set_ylabel("Encryption Time per SM (ms)")
    ax.set_title("Figure 3 – Encryption Cost per Smart Meter")
    fig.tight_layout()
    fig.savefig(f"{save_dir}/fig3_enc_per_sm.png", dpi=150)
    plt.close(fig)

    # ── Figure 4: Aggregation time ──
    fig, ax = plt.subplots(**fig_kw)
    ax.plot(ns, [r["t_agg"] * 1000 for r in results],
            "s-", color="#FF5722", linewidth=2, markersize=8)
    ax.set_xlabel("Number of Smart Meters (n)")
    ax.set_ylabel("Aggregation Time (ms)")
    ax.set_title("Figure 4 – Aggregation Cost at the AG")
    fig.tight_layout()
    fig.savefig(f"{save_dir}/fig4_agg_time.png", dpi=150)
    plt.close(fig)

    # ── Figure 5: Total pipeline time ──
    fig, ax = plt.subplots(**fig_kw)
    ax.plot(ns, [r["t_pipeline"] for r in results],
            "D-", color="#4CAF50", linewidth=2, markersize=8)
    ax.set_xlabel("Number of Smart Meters (n)")
    ax.set_ylabel("Total Pipeline Time (s)")
    ax.set_title("Figure 5 – End-to-End Pipeline Cost")
    fig.tight_layout()
    fig.savefig(f"{save_dir}/fig5_pipeline.png", dpi=150)
    plt.close(fig)

    # ── Figure 6: Per-entity cost breakdown (stacked bar) ──
    fig, ax = plt.subplots(**fig_kw)
    t_enc = [r["t_enc_total"] for r in results]
    t_agg = [r["t_agg"] for r in results]
    t_cc  = [r["t_fefq_enc"] + r["t_fefq_query"] for r in results]

    ax.bar(range(len(ns)), t_enc, label="SM (encryption)", color="#2196F3")
    ax.bar(range(len(ns)), t_agg, bottom=t_enc, label="AG (aggregation)",
           color="#FF5722")
    bottom2 = [e + a for e, a in zip(t_enc, t_agg)]
    ax.bar(range(len(ns)), t_cc, bottom=bottom2, label="CC (FEFQ + verify)",
           color="#9C27B0")
    ax.set_xticks(range(len(ns)))
    ax.set_xticklabels([str(n) for n in ns])
    ax.set_xlabel("Number of Smart Meters (n)")
    ax.set_ylabel("Time (s)")
    ax.set_title("Figure 6 – Per-Entity Cost Breakdown")
    ax.legend()
    fig.tight_layout()
    fig.savefig(f"{save_dir}/fig6_entity_breakdown.png", dpi=150)
    plt.close(fig)

    # ── Figure 7: Communication cost ──
    fig, ax = plt.subplots(**fig_kw)
    ax.plot(ns, [r["comm_bytes"] / 1024 for r in results],
            "^-", color="#795548", linewidth=2, markersize=8)
    ax.set_xlabel("Number of Smart Meters (n)")
    ax.set_ylabel("Communication Cost (KB)")
    ax.set_title("Figure 7 – Total Communication Cost")
    fig.tight_layout()
    fig.savefig(f"{save_dir}/fig7_comm_cost.png", dpi=150)
    plt.close(fig)

    print(f"\n✓  All plots saved to '{save_dir}/'")


def run_security_sweep() -> None:
    print("\n" + "="*70)
    print("  SECURITY PARAMETER SWEEP")
    print("="*70)
    print("  Bits | Setup (s) | Encrypt/SM (ms) | Aggregate (ms) | Security Level")
    print("  -----|-----------|-----------------|----------------|---------------")

    bits_list = [512, 1024, 2048]
    for b in bits_list:
        r = _run_pipeline(n=5, bits=b)
        
        setup_s = r['t_init']
        enc_ms = r['t_enc_per_sm'] * 1000
        agg_ms = r['t_agg'] * 1000
        
        if b == 512:
            sec_level = "DEMO ONLY"
        elif b == 1024:
            sec_level = "Weak (deprecated)"
        else:
            sec_level = "Production minimum"
            
        print(f"  {b:4d} | {setup_s:9.2f} | {enc_ms:15.1f} | {agg_ms:14.1f} | {sec_level}")

    print("\n  Note: NIST recommends 2048-bit minimum for DH. 512-bit is broken")
    print("  by academic teams (Logjam, 2015). This table shows the performance cost of security.\n")


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "sweep":
        run_security_sweep()
    else:
        results = run_benchmarks()
        plot_results(results)
