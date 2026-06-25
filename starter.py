#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid – Smart Meter Data Privacy Project
# File:    starter.py
# Purpose: Interactive entry point for the GuardGrid simulation.
# ──────────────────────────────────────────────────────────────────────

import os
import sys
import time
import logging
import subprocess
import importlib.util
from pathlib import Path

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
* Developed by: Himanshu Yadav & A. Tanmayye
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
        log_and_print("\n[INFO] Launching V1: Research Demo...", logging.INFO)
        script_dir = Path(__file__).resolve().parent / "v1_research_demo"
        subprocess.run([sys.executable, "main.py"], cwd=script_dir)
        log_and_print("[INFO] V1 Execution completed.", logging.INFO)
        
    elif choice == '2':
        log_and_print("\n[INFO] Launching V2: Advanced India Version...", logging.INFO)
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
