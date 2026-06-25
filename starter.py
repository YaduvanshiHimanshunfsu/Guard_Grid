#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid – Smart Meter Data Privacy Project
# File:    starter.py
# Purpose: Interactive entry point for the GuardGrid simulation.
# ──────────────────────────────────────────────────────────────────────

import os
import sys
import time
import random
import logging
import subprocess
import importlib.util
from pathlib import Path
import pandas as pd

# ─── Setup Logging ───
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "guard_grid_starter.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_and_print(msg: str, level: int = logging.INFO):
    """Prints to console and writes to the log file."""
    print(msg)
    logging.log(level, msg)

# ─── Display Information ───
def display_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    header = """
================================================================================
                      G U A R D   G R I D
           Privacy-Preserving Smart Meter Data Aggregation
================================================================================

[ Project Overview ]
* Goal: Ensuring data privacy and security in smart meter networks.
* Context: Summer Internship Project.
* Foundation: Built upon the "Guard Grid" cryptographic research paper.
* Objective: Evaluating practical feasibility, improving the theoretical
             solution, and simulating real-world fault tolerance.

[ Team & Mentorship ]
* Developed by: Himanshu Yadav & A.Tanmayee
* Under the Guidance of: Dr. Jayshree Gupta (Assistant Professor)
* Institution: IIIT Allahabad

================================================================================
    """
    log_and_print(header)

# ─── Dependency Management ───
REQUIRED_LIBS = {
    "pymife": "pymife",
    "gmpy2": "gmpy2",
    "pandas": "pandas",
    "matplotlib": "matplotlib"
}

def check_dependencies() -> list:
    """Checks which required libraries are missing."""
    missing = []
    for module_name in REQUIRED_LIBS.keys():
        if importlib.util.find_spec(module_name) is None:
            missing.append(REQUIRED_LIBS[module_name])
    return missing

def install_dependencies(missing_libs: list):
    """Prompts and installs missing dependencies."""
    log_and_print(f"\n[INFO] Missing libraries detected: {', '.join(missing_libs)}")
    
    # Rough estimates
    total_size_mb = len(missing_libs) * 25  # Roughly 25MB avg per heavy lib like pandas/matplotlib
    est_time_sec = len(missing_libs) * 15
    
    log_and_print(f"       Estimated Download Size: ~{total_size_mb} MB")
    log_and_print(f"       Estimated Install Time: ~{est_time_sec} seconds")
    
    choice = input("\nDo you want to install them now? (Y/n): ").strip().lower()
    if choice in ['', 'y', 'yes']:
        log_and_print("\n[INFO] Starting installation...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_libs)
            log_and_print("\n[OK] All libraries installed successfully!")
        except subprocess.CalledProcessError as e:
            log_and_print(f"\n[ERROR] Installation failed. Please install manually: pip install {' '.join(missing_libs)}", logging.ERROR)
            sys.exit(1)
    else:
        log_and_print("\n[WARN] Skipping installation. The program might crash if it attempts to use missing libraries.", logging.WARNING)

# ─── Presentation & Visualization ───
def explain_v1():
    log_and_print("\n" + "="*80)
    log_and_print("  PRE-FLIGHT BRIEFING: V1 (RESEARCH DEMO)")
    log_and_print("="*80)
    log_and_print("What you are about to see is the foundational cryptographic pipeline:")
    log_and_print("  1. Setup: The TTP generates 512-bit safe primes, DH keys, and MIFE master keys.")
    log_and_print("  2. Encryption: Each Smart Meter locally masks its reading using DH shared")
    log_and_print("     secrets, then applies Functional Encryption (MIFE) and Homomorphic Hashing.")
    log_and_print("  3. Aggregation: The Gateway (AG) blindly aggregates ciphertexts.")
    log_and_print("  4. Verification: The Control Center (CC) uses LHH to cryptographically verify")
    log_and_print("     the aggregate hasn't been tampered with, then decrypts the total sum.")
    log_and_print("  5. Queries: The CC re-encrypts the aggregate for the Cloud Server")
    log_and_print("     to evaluate specific functions blindly.")
    log_and_print("="*80)
    input("Press Enter to begin the V1 simulation... ")

def explain_v2():
    log_and_print("\n" + "="*80)
    log_and_print("  PRE-FLIGHT BRIEFING: V2 (ADVANCED INDIA VERSION)")
    log_and_print("="*80)
    log_and_print("This version simulates a real-world Smart Grid (India RDSS standard):")
    log_and_print("  1. Time-Series: Processing a full day of data (96 slots of 15-minute intervals).")
    log_and_print("  2. Fault Tolerance: We inject random meter failures. The system automatically")
    log_and_print("     substitutes pre-generated 'dummy ciphertexts' so the network doesn't crash.")
    log_and_print("  3. Anomaly Detection: A rolling z-score monitor tracks the decrypted")
    log_and_print("     aggregates to detect power spikes or potential theft.")
    log_and_print("  4. Credit Scoring: The Gateway earns or loses reputation points based on")
    log_and_print("     the cryptographic verification of its aggregations.")
    log_and_print("  5. Billing: The system calculates estimated feeder-level revenue using")
    log_and_print("     the official 3-slab DERC domestic tariff (Delhi).")
    log_and_print("="*80)
    input("Press Enter to begin the V2 full-day simulation... ")

def demo_math_v1():
    log_and_print("\n" + "="*80)
    log_and_print("  DYNAMIC MATHEMATICAL WALKTHROUGH (V1)")
    log_and_print("="*80)
    
    choice = input("\nSelect Data Source for Demo:\n1. Random sample (3-10 meters) from CSV\n2. Use full dataset (~60,000 meters)\nEnter choice (1/2): ").strip()
    
    csv_path = Path(__file__).resolve().parent / "shared" / "smart_grid_stability_augmented.csv"
    if not csv_path.exists():
        log_and_print(f"[ERROR] Dataset not found at {csv_path}", logging.ERROR)
        return
        
    df = pd.read_csv(csv_path)
    
    if choice == '1':
        n = random.randint(3, 10)
        df_sample = df.sample(n).reset_index(drop=True)
        readings = (df_sample['p1'] * 1000).astype(int).tolist()
    else:
        n = len(df)
        readings = (df['p1'] * 1000).astype(int).tolist()
        
    p, g = 23, 5
    cc_priv = random.randint(2, 20)
    cc_pub = pow(g, cc_priv, p)
    
    log_and_print(f"\n[ Dataset Prepared — {n} Smart Meters ]")
    if choice == '1':
        for i, val in enumerate(readings):
            log_and_print(f"  SM{i+1}: {(val/1000):.3f} kW  -> x{i+1} = {val}")
    else:
        log_and_print(f"  Processed {n} meters. First value: x1 = {readings[0]}")
        
    input("\n[Press Enter to execute Alg 1: DH Key Agreement] ")
    log_and_print("\n--- Alg 1: DH Key Agreement ---")
    log_and_print(f"CC  gen: priv={cc_priv} -> pub={g}^{cc_priv} mod {p} = {cc_pub}")
    
    sm_privs = [random.randint(2, 20) for _ in range(n)]
    sm_pubs = [pow(g, priv, p) for priv in sm_privs]
    session_keys = [pow(cc_pub, priv, p) for priv in sm_privs]
    
    if choice == '1':
        for i in range(n):
            log_and_print(f"SM{i+1} gen: priv={sm_privs[i]} -> pub={sm_pubs[i]}")
        log_and_print("\nShared session keys (ki):")
        for i in range(n):
            log_and_print(f"k{i+1}: {cc_pub}^{sm_privs[i]} mod {p} = {session_keys[i]}")
            
    total_mask = sum(session_keys)
    log_and_print(f"Total Mask (K) = {total_mask}")
    
    input("\n[Press Enter to execute Alg 2: FEHH Encryption] ")
    log_and_print("\n--- Alg 2: FEHH Encryption (SM side) ---")
    ciphertexts = [readings[i] + session_keys[i] for i in range(n)]
    if choice == '1':
        for i in range(n):
            log_and_print(f"SM{i+1} sends: {readings[i]} + {session_keys[i]} = {ciphertexts[i]}")
    else:
        log_and_print(f"  Encrypted {n} values. First cipher: {ciphertexts[0]}")
        
    input("\n[Press Enter to execute Alg 3: MIFE Inner Product] ")
    log_and_print("\n--- Alg 3: MIFE Inner Product (AG side) ---")
    c_prime = sum(ciphertexts)
    log_and_print("AG aggregates without seeing true values.")
    log_and_print(f"C' (sum of all ciphertexts) = {c_prime}")
    
    input("\n[Press Enter to execute Alg 4: LHH Verification] ")
    log_and_print("\n--- Alg 4: LHH Verification (CC side) ---")
    hashes = [pow(g, ct, p) for ct in ciphertexts]
    h_star = 1
    for h in hashes:
        h_star = (h_star * h) % p
        
    verify_val = pow(g, c_prime, p)
    if choice == '1':
        for i in range(n):
            log_and_print(f"h{i+1} = {g}^{ciphertexts[i]} mod {p} = {hashes[i]}")
    
    log_and_print(f"h* (product of hashes mod {p}) = {h_star}")
    log_and_print(f"Check: {g}^{c_prime} mod {p} = {verify_val}.")
    if verify_val == h_star:
        log_and_print("MATCH! [AG was honest]")
    else:
        log_and_print("MISMATCH! [Tampering detected]")
        
    input("\n[Press Enter to execute Alg 5: FEHH Decryption] ")
    log_and_print("\n--- Alg 5: FEHH Decryption ---")
    c_final = c_prime - total_mask
    log_and_print(f"C = {c_prime} - K({total_mask}) = {c_final}")
    log_and_print(f"Restored scale: {c_final} / 1000 = {c_final / 1000:.3f} kW")
    log_and_print("\nMathematical Walkthrough Complete.")

def demo_math_v2():
    log_and_print("\n" + "="*80)
    log_and_print("  DYNAMIC WALKTHROUGH (V2 - Advanced India)")
    log_and_print("="*80)
    
    mode = input("\nSelect Input Method:\n1. Use randomly sampled CSV dataset\n2. Manual Input (max 10 meters)\nEnter choice (1/2): ").strip()
    
    if mode == '1':
        csv_path = Path(__file__).resolve().parent / "shared" / "smart_grid_stability_augmented.csv"
        try:
            df = pd.read_csv(csv_path)
            n = random.randint(3, 10)
            df_sample = df.sample(n).reset_index(drop=True)
            readings = df_sample['p1'].tolist()
        except Exception:
            log_and_print("[ERROR] CSV failed to load. Falling back to defaults.")
            readings = [3.76, 5.06, 3.40]
    else:
        log_and_print("\nEnter electricity consumption for up to 10 meters in kW.")
        log_and_print("Format: comma separated values (e.g., 3.5, 4.2, 5.1)")
        user_input = input("Data: ").strip()
        try:
            readings = [float(x.strip()) for x in user_input.split(',')]
            if len(readings) > 10:
                log_and_print("[WARN] Truncating to 10 meters max.")
                readings = readings[:10]
        except Exception:
            log_and_print("[ERROR] Invalid input. Falling back to [3.5, 4.2, 5.1]")
            readings = [3.5, 4.2, 5.1]
            
    n = len(readings)
    if n == 0:
        log_and_print("[ERROR] No data provided.")
        return
        
    log_and_print(f"\n[ Working with {n} Smart Meters ]")
    for i, val in enumerate(readings):
        log_and_print(f"  SM{i+1}: {val:.3f} kW")
        
    input("\n[Press Enter to execute Fault Tolerance Demo] ")
    log_and_print("\n--- Scenario: Random Meter Goes Offline ---")
    if n > 1:
        offline_idx = random.randint(0, n-1)
        log_and_print(f"WARNING: SM{offline_idx+1} suddenly lost connection!")
        
        log_and_print("AG detects missing ciphertext. Submitting request to TTP for dummy.")
        log_and_print(f"AG substitutes TTP Dummy for SM{offline_idx+1}.")
        
        log_and_print("Dummy decrypts to 0 kW. Mask sum dynamically adjusted by CC.")
        valid_readings = [r for i, r in enumerate(readings) if i != offline_idx]
        actual_agg = sum(valid_readings)
        log_and_print(f"Decrypted Aggregate without SM{offline_idx+1} = {actual_agg:.3f} kW")
        log_and_print("Network continues functioning without crashing.")
    else:
        log_and_print("Only 1 meter. Cannot simulate a meaningful offline fault.")
        actual_agg = sum(readings)
    
    input("\n[Press Enter to execute Billing Demo] ")
    log_and_print("\n--- Feeder Billing Demo (DERC Slabs) ---")
    avg_consumption = actual_agg / max(1, n if n==1 else n-1)
    log_and_print(f"Average consumption for online meters: {avg_consumption:.3f} kW")
    log_and_print("Applying DERC Tariff:")
    if avg_consumption <= 2.0:
        rate = 3.00
    elif avg_consumption <= 4.0:
        rate = 4.50
    else:
        rate = 6.50
        
    log_and_print(f"Slab Rate: INR {rate:.2f} / kWh")
    revenue = actual_agg * rate
    log_and_print(f"Estimated Feeder Revenue: {actual_agg:.3f} * {rate:.2f} = INR {revenue:.2f}")
    log_and_print("\nDynamic Walkthrough Complete.")

# ─── Runner ───
def run_mode():
    log_and_print("\n[ Select Execution Mode ]")
    log_and_print("  1. Run V1: Research Demo")
    log_and_print("     - Pure implementation of the research paper model.")
    log_and_print("     - Validates theoretical equations with slight improvements.")
    log_and_print("  2. Run V2: Advanced India Version")
    log_and_print("     - Production-oriented, practical version.")
    log_and_print("     - Features fault tolerance, time-series intervals, and billing.")
    log_and_print("  3. Exit")
    
    choice = input("\nEnter your choice (1/2/3): ").strip()
    
    if choice == '1':
        explain_v1()
        if input("\nDo you want to see the interactive mathematical calculation demo? (Y/n): ").strip().lower() in ['', 'y', 'yes']:
            demo_math_v1()
        log_and_print("\n[INFO] Launching V1: Research Demo (Full Simulation)...", logging.INFO)
        script_dir = Path(__file__).resolve().parent / "v1_research_demo"
        subprocess.run([sys.executable, "main.py"], cwd=script_dir)
        log_and_print("[INFO] V1 Execution completed.", logging.INFO)
        
    elif choice == '2':
        explain_v2()
        if input("\nDo you want to see the interactive fault/billing calculation demo? (Y/n): ").strip().lower() in ['', 'y', 'yes']:
            demo_math_v2()
        log_and_print("\n[INFO] Launching V2: Advanced India Version (Full Simulation)...", logging.INFO)
        script_dir = Path(__file__).resolve().parent / "v2_advanced_india"
        subprocess.run([sys.executable, "main.py"], cwd=script_dir)
        log_and_print("[INFO] V2 Execution completed.", logging.INFO)
        
    elif choice == '3':
        log_and_print("\nExiting GuardGrid Starter. Goodbye!", logging.INFO)
        sys.exit(0)
    else:
        log_and_print("\n[ERROR] Invalid choice. Please enter 1, 2, or 3.", logging.WARNING)
        run_mode()

def main():
    display_header()
    
    log_and_print("[INFO] Checking system dependencies in the background...")
    missing = check_dependencies()
    
    if missing:
        install_dependencies(missing)
    else:
        log_and_print("[OK] All required libraries are already installed.")
        time.sleep(1) # Brief pause for readability
        
    while True:
        run_mode()
        
        cont = input("\nDo you want to run another mode? (Y/n): ").strip().lower()
        if cont not in ['', 'y', 'yes']:
            log_and_print("\nExiting GuardGrid Starter. Goodbye!", logging.INFO)
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Program interrupted by user. Exiting...")
        sys.exit(0)
