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


def run_simulation(n_users: int, faults: int, n_days: int = 1, theft_meter: int = -1) -> None:
    print("=" * 80)
    print(f"  GuardGrid V2 – Advanced India Version | {n_users} Meters | {faults} Faults/Round")
    print(f"  Simulating {n_days} day(s) ({SLOTS_PER_DAY} slots of 15 mins per day)")
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

    if 0 <= theft_meter < n_users:
        smart_meters[theft_meter].theft_factor = 0.5
        print(f"\n[THEFT] SM_{theft_meter} is set to report 50% of actual reading.")

    ag_keys = ttp.get_ag_keys()
    ag = AggregationGateway(ag_keys, sys_params["backup_ciphertexts"])
    
    fault_handler = FaultHandler(n_users)
    credit_tracker = CreditTracker()
    anomaly_detector = AnomalyDetector()

    # ── Precompute Session Keys (Phase 1) ──
    print("\n[Phase 1] Precomputing CC DH Session Keys for efficiency...")
    t0_sk = time.perf_counter()
    from crypto.dh import generate_session_key
    session_keys = []
    dh_p, dh_g = fehh_params["dh_p"], fehh_params["dh_g"]
    cc_keys = fehh_params["cc_keys"]
    sm_dh_publics = sys_params["sm_dh_publics"]
    for i in range(n_users):
        cc_priv, _ = cc_keys[i]
        sm_pub = sm_dh_publics[i]
        ki = generate_session_key(cc_priv, sm_pub, dh_p, dh_g)
        session_keys.append(ki)
    print(f"          Done in {time.perf_counter() - t0_sk:.3f}s.")

    # ── Load Time-Series Data ──
    print(f"\n[Data]    Loading time-series data for {n_users} users...")
    timeseries = load_timeseries(n_users, n_days=n_days)
    
    ag_id = "AG_Feeder_1"
    anomalies_detected = 0

    print(f"\n[Phase 2 & 3] Starting {n_days}-day Cycle...")
    t_cycle_start = time.perf_counter()

    daily_totals = []
    Path('v2_outputs').mkdir(exist_ok=True)

    for day in range(n_days):
        total_for_day = 0.0
        for slot in range(SLOTS_PER_DAY):
            # 1. Fault generation
            online_mask = fault_handler.simulate_offline(faults)
        fault_handler.log_round(slot, online_mask)
        
        # 2. Extract readings for this slot
        slot_readings = get_slot_readings(timeseries, day=day, slot=slot)
        
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
        enc_results = ag.flush_collected()
        agg_res = aggregate_time_slot(slot, enc_results, sys_params, session_keys, SCALE)
        
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

        total_for_day += agg_res["aggregate_float"]
        
        # Print progress every 16 slots
        if (slot + 1) % 16 == 0 and n_days == 1:
            print(f"          Processed {slot + 1:2d}/{SLOTS_PER_DAY} slots. "
                  f"Current AG score: {credit_tracker.get_score(ag_id)}")

        daily_totals.append(total_for_day)
        print(f"  [Day {day+1}] Total: {total_for_day:.2f} kWh")

    t_cycle_end = time.perf_counter()
    print(f"          Cycle complete in {t_cycle_end - t_cycle_start:.3f}s.")
    
    for i in range(1, len(daily_totals)):
        delta = daily_totals[i] - daily_totals[i-1]
        pct = (delta / daily_totals[i-1]) * 100
        print(f"  Day {i}->{i+1}: {delta:+.2f} kWh ({pct:+.1f}%)")
    
    if n_days > 1:
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.plot(range(1, n_days + 1), daily_totals, marker='o')
        mean_kwh = sum(daily_totals) / len(daily_totals)
        ax.axhline(mean_kwh, color='r', linestyle='--', label=f'Mean ({mean_kwh:.1f})')
        ax.set_xlabel('Day')
        ax.set_ylabel('Total Daily kWh')
        ax.set_title(f'Daily Aggregate — {n_users} Meters, {n_days} Days')
        ax.legend()
        plt.tight_layout()
        plot_path = f'v2_outputs/trend_{n_users}m_{n_days}d.png'
        plt.savefig(plot_path)
        print(f"          [Plot] Saved trend to {plot_path}")
        plt.close(fig)

    # ── Phase 4: Feeder Billing (End of Day) ──
    print("\n[Phase 4] Computing Feeder-Level Billing Estimate...")
    total_consumption = sum(daily_totals)
    bill = compute_feeder_revenue(total_consumption, n_users)
    print(f"          Total overall consumption: {total_consumption:.2f} kWh")
    print(f"          Estimated revenue:       INR {bill.total_revenue_inr}")
    print(f"          Average per meter:       {bill.avg_per_meter_kwh:.2f} kWh (INR {bill.avg_per_meter_bill_inr})")
    print(f"          Slab applied (avg):      {bill.tariff_slab_applied}")

    # ── Final Report ──
    print("\n" + "=" * 80)
    print("  SIMULATION SUMMARY")
    print("=" * 80)
    
    # Check if there were any alerts
    # Pull the worst-case round from fault_handler.get_history()
    hist = fault_handler.get_history()
    if hist:
        worst_round = max(hist, key=lambda h: h["offline_count"])
        max_offline = worst_round["offline_count"]
        # Reconstruct the mask for the worst round to feed into check_alert
        # (False means offline)
        worst_mask = [True] * n_users
        for idx in worst_round["offline_indices"]:
            worst_mask[idx] = False
        alert = fault_handler.check_alert(worst_mask)
    else:
        max_offline = 0
        alert = fault_handler.check_alert([True] * n_users)
    
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
    
    if 0 <= theft_meter < n_users and n_days >= 3:
        expected_daily = (daily_totals[0] + daily_totals[1]) / 2.0
        actual_daily = daily_totals[-1]
        loss = expected_daily - actual_daily
        avg_rate = bill.total_revenue_inr / total_consumption if total_consumption > 0 else 0
        print(f"[THEFT ANALYSIS] Expected: {expected_daily:.2f} kWh | Actual: {actual_daily:.2f} kWh")
        print(f"  Estimated loss: {loss:.2f} kWh = INR {loss * avg_rate:.2f}")
        print(f"  Anomalies flagged during theft: {anomalies_detected}\n")

    credit_tracker.plot_score_history(
        ag_id, 
        save_path=f'v2_outputs/credit_{ag_id}_{n_users}m.png'
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GuardGrid V2 Simulation")
    parser.add_argument("n_users", nargs="?", type=int, default=N_USERS,
                        help="Number of smart meters")
    parser.add_argument("--faults", type=int, default=DEFAULT_OFFLINE_COUNT,
                        help="Number of offline meters per round")
    parser.add_argument("--days", type=int, default=1,
                        help="Number of days to simulate")
    parser.add_argument("--theft-meter", type=int, default=-1,
                        help="Index of meter to simulate power theft (default: -1 for none)")
    
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        from benchmark.measure import run_benchmarks, plot_results
        results = run_benchmarks()
        plot_results(results)
    else:
        args = parser.parse_args()
        run_simulation(args.n_users, args.faults, args.days, args.theft_meter)
