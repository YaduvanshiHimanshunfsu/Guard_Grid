"""
main.py – GuardGrid V1 Research Demo entry point.
====================================================

This is the file you run.  It wires all five entities (TTP, SmartMeter,
AggregationGateway, ControlCenter, CloudServer) together, executes the
full four-phase protocol, and prints the result with timing.

Usage
-----
    python main.py            # default n=10
    python main.py 50         # override to 50 smart meters
    python main.py benchmark  # run benchmarks + generate plots

What to expect
--------------
The output walks through each phase, showing:
    - How long the TTP setup takes (Phase 1).
    - Per-SM encryption time (Phase 2).
    - AG aggregation and CC verification results (Phase 3).
    - Cloud function queries on the encrypted aggregate (Phase 4).
    - Final check: does the decrypted aggregate match the expected sum?

If "Match: YES" appears at the end, the entire pipeline — from raw CSV
float to encrypted aggregate to decrypted result — is working correctly.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure the V1 root is on the import path so all packages resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import N_USERS, SCALE              # noqa: E402
from data.loader import load_readings           # noqa: E402
from entities.ttp import TTP                    # noqa: E402
from entities.smart_meter import SmartMeter     # noqa: E402
from entities.agg_gateway import AggregationGateway   # noqa: E402
from entities.control_center import ControlCenter     # noqa: E402
from entities.cloud_server import CloudServer         # noqa: E402


def run_simulation(n: int = N_USERS) -> None:
    """Run the full GuardGrid simulation with n smart meters."""

    print("=" * 70)
    print(f"  GuardGrid V1 – Research Demo  |  n = {n}  smart meters")
    print("=" * 70)

    # ─────────────────────────────────────────────────────────────────────
    # Phase 1: System Initialisation  (TTP)
    # ─────────────────────────────────────────────────────────────────────
    print("\n[Phase 1]  TTP generating cryptographic parameters …")
    t0 = time.perf_counter()

    ttp = TTP(n)
    sys_params = ttp.initialise()

    t_init = time.perf_counter() - t0
    print(f"           Done in {t_init:.3f}s.  TTP is now offline.\n")

    # ─────────────────────────────────────────────────────────────────────
    # Distribute keys to each entity
    # ─────────────────────────────────────────────────────────────────────
    fehh_params = sys_params["fehh_params"]

    # Create SmartMeter instances — each gets its own DH keys.
    smart_meters: list[SmartMeter] = []
    for i in range(n):
        sm_keys = ttp.get_sm_keys(i)
        sm = SmartMeter(
            slot_index=i,
            sm_dh_private=sm_keys["sm_dh_private"],
            cc_dh_public=sm_keys["cc_dh_public"],
            fehh_params=fehh_params,
        )
        smart_meters.append(sm)

    # Create the Aggregation Gateway — gets FEHH public params.
    ag = AggregationGateway(fehh_params)

    # Create the Control Center — gets CC's DH keys, SM public keys,
    # and the FEFQ params for cloud encryption.
    cc_keys = ttp.get_cc_keys()
    cc = ControlCenter(
        cc_dh_keys=cc_keys["cc_dh_keys"],
        sm_dh_publics=cc_keys["sm_dh_publics"],
        dh_p=cc_keys["dh_p"],
        dh_g=cc_keys["dh_g"],
        lhh_p=cc_keys["lhh_p"],
        lhh_g=cc_keys["lhh_g"],
        fefq_params=cc_keys["fefq_params"],
        scale=SCALE,
    )

    # Create the Cloud Server — in simulation it gets the full FEFQ params.
    cloud_keys = ttp.get_cloud_keys()
    cloud = CloudServer(sys_params["fefq_params"])

    # ─────────────────────────────────────────────────────────────────────
    # Load dataset
    # ─────────────────────────────────────────────────────────────────────
    print("[Data]     Loading dataset …")
    readings = load_readings(n)
    expected_sum = sum(readings) / SCALE
    print(f"           Loaded {n} readings.  Expected aggregate = {expected_sum:.4f}\n")

    # ─────────────────────────────────────────────────────────────────────
    # Phase 2: Data Collection  (each SM encrypts)
    # ─────────────────────────────────────────────────────────────────────
    print("[Phase 2]  Smart meters encrypting …")
    t0 = time.perf_counter()

    all_session_keys: list[int] = []
    for i, sm in enumerate(smart_meters):
        result = sm.encrypt(readings[i])
        # SM sends (ctx, h) to the AG.  ki stays with the SM.
        ag.receive({"ctx": result["ctx"], "h": result["h"]})
        all_session_keys.append(result["ki"])

    t_enc = time.perf_counter() - t0
    print(f"           Done in {t_enc:.3f}s  ({t_enc/n*1000:.2f} ms per SM).\n")

    # ─────────────────────────────────────────────────────────────────────
    # Phase 3: Aggregation  (AG)  +  Verification & Decryption  (CC)
    # ─────────────────────────────────────────────────────────────────────
    print("[Phase 3]  AG aggregating ciphertexts …")
    t0 = time.perf_counter()
    agg_result = ag.aggregate()
    t_agg = time.perf_counter() - t0
    print(f"           C' = {agg_result['C_prime']}")
    print(f"           Done in {t_agg:.3f}s.\n")

    print("           CC verifying and decrypting …")
    t0 = time.perf_counter()
    dec_result = cc.verify_and_decrypt(agg_result["C_prime"], agg_result["h_star"])
    t_dec = time.perf_counter() - t0

    status = "PASSED" if dec_result["verified"] else "FAILED"
    print(f"           Verification:  {status}")
    print(f"           True aggregate C = {dec_result['C']}")
    print(f"           Aggregate (float) = {dec_result['aggregate_float']:.4f}")
    print(f"           Expected          = {expected_sum:.4f}")
    print(f"           Done in {t_dec:.3f}s.\n")

    # ─────────────────────────────────────────────────────────────────────
    # Phase 4: Function Queries  (CC → Cloud)
    # ─────────────────────────────────────────────────────────────────────
    print("[Phase 4]  CC encrypting aggregate for cloud …")
    t0 = time.perf_counter()
    ct = cc.encrypt_for_cloud(dec_result["C"])
    cloud.store(ct)
    t_fefq = time.perf_counter() - t0
    print(f"           Done in {t_fefq:.3f}s.\n")

    # Example function queries.
    queries = [
        ("aggregate + 500",    1, 500),
        ("aggregate - 200",    1, -200),
        ("aggregate * 3",      3, 0),
    ]

    print("           Cloud answering function queries:")
    for label, a, b in queries:
        t0 = time.perf_counter()
        result = cloud.query(a=a, b=b)
        t_q = time.perf_counter() - t0
        print(f"             f(x) = {label:20s}  =>  {result}  ({t_q*1000:.2f} ms)")

    # ─────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────
    total = t_init + t_enc + t_agg + t_dec + t_fefq
    match = abs(dec_result["aggregate_float"] - expected_sum) < 1e-6
    print(f"\n{'-'*70}")
    print(f"  Total time:  {total:.3f}s")
    print(f"  Match:       {'YES' if match else 'NO'}")
    print(f"{'-'*70}\n")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        from benchmark.measure import run_benchmarks, plot_results  # noqa: E402
        results = run_benchmarks()
        plot_results(results)
    else:
        n = int(sys.argv[1]) if len(sys.argv) > 1 else N_USERS
        run_simulation(n)
