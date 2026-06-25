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
import argparse
import random
import statistics
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


def run_simulation(n: int = N_USERS, tamper: bool = False) -> None:
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

    # Create the Aggregation Gateway — gets FEHH public params and sk_y.
    ag_keys = ttp.get_ag_keys()
    ag = AggregationGateway(ag_keys)

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

    # Create the Cloud Server — receives only public FEFQ params.
    cloud_keys = ttp.get_cloud_keys()
    cloud = CloudServer(cloud_keys["fefq_public"])

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
    enc_times: list[float] = []
    for i, sm in enumerate(smart_meters):
        t_sm = time.perf_counter()
        result = sm.encrypt(readings[i])
        enc_times.append(time.perf_counter() - t_sm)
        # SM sends (ctx, h) to the AG.  ki stays with the SM.
        ag.receive({"ctx": result["ctx"], "h": result["h"]})
        all_session_keys.append(result["ki"])

    if tamper:
        tamper_idx = random.randint(0, n - 1)
        ag._collected[tamper_idx]['h'] += 1
        print(f"\n[TAMPER] AG corrupted hash at slot {tamper_idx}")

    t_enc = time.perf_counter() - t0
    avg_enc = statistics.mean(enc_times) * 1000
    min_enc = min(enc_times) * 1000
    max_enc = max(enc_times) * 1000
    std_enc = statistics.stdev(enc_times) * 1000 if len(enc_times) > 1 else 0.0
    print(f"           Done in {t_enc:.3f}s.")
    print(f"           Encrypt times — min: {min_enc:.2f} ms  |  max: {max_enc:.2f} ms  |  avg: {avg_enc:.2f} ms  |  stdev: {std_enc:.2f} ms\n")

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

    if dec_result["verified"]:
        print("           Verification:  PASSED — AG was honest.")
    else:
        print("           Verification:  FAILED — Tamper detected! AG corrupted the aggregate.")
        print("           Note: The decrypted value below is UNTRUSTWORTHY.")
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
        fk = cc.generate_function_key(a, b)
        result = cloud.query(a=a, b=b, fk=fk)
        t_q = time.perf_counter() - t0
        print(f"             f(x) = {label:20s}  =>  {result}  ({t_q*1000:.2f} ms)")

    # ─────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────
    total = t_init + t_enc + t_agg + t_dec + t_fefq
    match = abs(dec_result["aggregate_float"] - expected_sum) < 1e-6
    print(f"\n{'-'*70}")
    print(f"  Total time:  {total:.3f}s")
    if not dec_result["verified"] and tamper:
        print(f"  Match:       NO (Tamper successfully caught by LHH!)")
    else:
        print(f"  Match:       {'YES' if match else 'NO'}")
    print(f"{'-'*70}\n")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GuardGrid V1 Research Demo")
    parser.add_argument("command_or_n", nargs="?", default=str(N_USERS), 
                        help="Number of users (e.g. 10), 'benchmark', or 'sweep'")
    parser.add_argument("--tamper", action="store_true", 
                        help="Simulate AG tampering with one hash to demo LHH")
    args = parser.parse_args()

    if args.command_or_n == "benchmark":
        from benchmark.measure import run_benchmarks, plot_results  # noqa: E402
        results = run_benchmarks()
        plot_results(results)
    elif args.command_or_n == "sweep":
        from benchmark.measure import run_security_sweep
        run_security_sweep()
    else:
        n = int(args.command_or_n)
        run_simulation(n, tamper=args.tamper)
