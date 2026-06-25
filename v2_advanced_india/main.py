#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    main.py
# Purpose: Entry point for V2 multi-round simulation.
#          Integrates fault tolerance, anomaly detection, billing,
#          and credit scoring over a 96-slot day.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import sys
import time
import argparse
from pathlib import Path

# Ensure the V2 root is on the import path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import (
    N_USERS, SLOTS_PER_DAY, DEFAULT_OFFLINE_COUNT, SCALE,
    CREDIT_FLAG, CREDIT_REVOKE
)
from data.timeseries_loader import load_timeseries, get_slot_readings
from entities.ttp import TTP
from entities.smart_meter import SmartMeter
from entities.agg_gateway import AggregationGateway
from schemes.timeseries_aggregator import aggregate_time_slot
from utils.fault_handler import FaultHandler
from utils.credit_score import CreditTracker
from utils.anomaly_detector import AnomalyDetector
from utils.billing import compute_feeder_revenue


def run_simulation(n_users: int, faults: int) -> None:
    print("=" * 80)
    print(f"  GuardGrid V2 – Advanced India Version | {n_users} Meters | {faults} Faults/Round")
    print(f"  Simulating one full day ({SLOTS_PER_DAY} slots of 15 mins)")
    print("=" * 80)

    # ── Init TTP and generate keys ──
    print("\n[Phase 1] Initialising TTP and generating keys (including backups)...")
    t0 = time.perf_counter()
    ttp = TTP(n_users)
    sys_params = ttp.initialise()
    fehh_params = sys_params["fehh_params"]
    print(f"          Done in {time.perf_counter() - t0:.3f}s. TTP offline.")

    # ── Instantiate Entities & Utils ──
    smart_meters = []
    for i in range(n_users):
        sm_keys = ttp.get_sm_keys(i)
        sm = SmartMeter(i, sm_keys["sm_dh_private"], sm_keys["cc_dh_public"], fehh_params)
        smart_meters.append(sm)

    ag = AggregationGateway(fehh_params, sys_params["backup_ciphertexts"])
    
    fault_handler = FaultHandler(n_users)
    credit_tracker = CreditTracker()
    anomaly_detector = AnomalyDetector()

    # ── Load Time-Series Data ──
    print(f"\n[Data]    Loading time-series data for {n_users} users...")
    timeseries = load_timeseries(n_users, n_days=1)
    
    ag_id = "AG_Feeder_1"
    total_aggregate_kwh = 0.0
    anomalies_detected = 0

    print("\n[Phase 2 & 3] Starting 96-slot Daily Cycle...")
    t_cycle_start = time.perf_counter()

    for slot in range(SLOTS_PER_DAY):
        # 1. Fault generation
        online_mask = fault_handler.simulate_offline(faults)
        fault_handler.log_round(slot, online_mask)
        
        # 2. Extract readings for this slot
        slot_readings = get_slot_readings(timeseries, day=0, slot=slot)
        
        # 3. Smart Meters Encrypt
        for i, sm in enumerate(smart_meters):
            if online_mask[i]:
                res = sm.encrypt(slot_readings[i])
                ag.receive_or_mark_offline(res, i)
            else:
                ag.receive_or_mark_offline(None, i)
                
        # 4. Aggregation and Verification
        # In V2, aggregate_time_slot handles AG aggregation and CC verification/decryption.
        # It needs enc_results which in our OOP model the AG already collected.
        # We will extract it from the AG to pass to the scheme, simulating the network transfer.
        enc_results = ag._collected
        agg_res = aggregate_time_slot(slot, enc_results, sys_params, SCALE)
        
        # Reset AG buffer manually since we intercepted it
        ag._collected = [None] * n_users
        
        # 5. Credit Scoring
        credit_tracker.record_round(ag_id, agg_res["verified"])
        
        # 6. Anomaly Detection (only checking against past slots if we had >1 day data, 
        # but here we just record it. In a multi-day sim it would flag).
        # We can simulate by treating consecutive slots as time series for the detector.
        # Wait, the anomaly detector expects `slot_id` to mean time-of-day. 
        # Since we only have 1 day, it won't trigger. That's fine, we still record.
        anom_res = anomaly_detector.check(slot, agg_res["aggregate_float"])
        anomaly_detector.record(slot, agg_res["aggregate_float"])
        if anom_res.is_anomaly:
            anomalies_detected += 1
            print(f"          [Slot {slot}] {anom_res.message}")

        total_aggregate_kwh += agg_res["aggregate_float"]
        
        # Print progress every 16 slots
        if (slot + 1) % 16 == 0:
            print(f"          Processed {slot + 1:2d}/{SLOTS_PER_DAY} slots. "
                  f"Current AG score: {credit_tracker.get_score(ag_id)}")

    t_cycle_end = time.perf_counter()
    print(f"          Cycle complete in {t_cycle_end - t_cycle_start:.3f}s.")

    # ── Phase 4: Feeder Billing (End of Day) ──
    print("\n[Phase 4] Computing Feeder-Level Billing Estimate...")
    bill = compute_feeder_revenue(total_aggregate_kwh, n_users)
    print(f"          Total daily consumption: {total_aggregate_kwh:.2f} kWh")
    print(f"          Estimated revenue:       INR {bill.total_revenue_inr}")
    print(f"          Average per meter:       {bill.avg_per_meter_kwh:.2f} kWh (INR {bill.avg_per_meter_bill_inr})")
    print(f"          Slab applied (avg):      {bill.tariff_slab_applied}")

    # ── Final Report ──
    print("\n" + "=" * 80)
    print("  SIMULATION SUMMARY")
    print("=" * 80)
    
    # Check if there were any alerts
    # Let's check the last round as an example, or overall history
    hist = fault_handler.get_history()
    max_offline = max(h["offline_count"] for h in hist)
    alert = fault_handler.check_alert([False]*max_offline + [True]*(n_users - max_offline))
    
    print(f"  Faults:       Max {max_offline} meters offline in a single round.")
    if alert.alert:
        print(f"                {alert.message}")
    else:
        print("                Within safe limits.")
        
    print(f"  Anomalies:    {anomalies_detected} flagged.")
    
    ag_status = credit_tracker.summary(ag_id)
    print(f"  AG Score:     {ag_status.score}/100 [{ag_status.status}]")
    print(f"                ({ag_status.pass_count} passes, {ag_status.fail_count} fails)")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GuardGrid V2 Simulation")
    parser.add_argument("n_users", nargs="?", type=int, default=N_USERS,
                        help="Number of smart meters")
    parser.add_argument("--faults", type=int, default=DEFAULT_OFFLINE_COUNT,
                        help="Number of offline meters per round")
    
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        from benchmark.measure import run_benchmarks, plot_results
        results = run_benchmarks()
        plot_results(results)
    else:
        args = parser.parse_args()
        run_simulation(args.n_users, args.faults)
