"""
loader.py – Dataset reader for the Smart Grid Stability CSV.
==============================================================

Dataset overview
----------------
Name:    Smart Grid Stability Augmented Dataset
Source:  UCI ML Repository / Kaggle
Rows:    60,000
Columns: 14
Missing: None

The dataset contains simulated readings from a 4-node power grid:

    Node 1 (Producer)  ──┬── Node 2 (Consumer)
                         ├── Node 3 (Consumer)
                         └── Node 4 (Consumer)

Column reference
----------------
    tau1–tau4  : Reaction time of each node (0.5–10 seconds).
    p1         : Producer power output (+1.58 to +5.86 kW).  Always positive.
    p2, p3, p4 : Consumer power draw (−2.0 to −0.5 kW).  Always negative.
                 Conservation law:  p1 + p2 + p3 + p4 = 0.
    g1–g4      : Price sensitivity / demand elasticity (0.05–1.0).
    stab       : Stability score (continuous; positive = stable).
    stabf      : Binary label — "stable" or "unstable".

What we use
-----------
ONLY the p1 column.  It gives us realistic, always-positive power values
that look like smart meter readings.  We take the first n rows (one per
meter), multiply by 1000 to get clean integers, and feed them into the
encryption pipeline.

Why only p1?
    The paper treats each meter reading as a single scalar.  The p1
    column provides exactly that — a realistic, bounded, positive float.
    The other columns (consumer draws, stability scores) are not relevant
    to the cryptographic demonstration.

Why multiply by 1000?
    Cryptographic operations require integers.  Multiplying 3.763 by
    1000 gives 3763 — an integer with three decimal places of precision
    preserved.  After decryption the CC divides by 1000 to recover the
    original float.  This is a common pattern in financial cryptography
    where fixed-point representations replace floats.

Dataset location
----------------
The CSV lives in ../shared/ so both V1 and V2 can read it without
duplication.  The path is resolved relative to this file's location
using the DATA_PATH constant from config.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

# Make sure the V1 root is importable regardless of the working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SCALE, DATA_PATH  # noqa: E402


def load_readings(n_users: int, col: str = "p1") -> list[int]:
    """Load n_users integer-scaled meter readings from the CSV.

    Example:
        >>> load_readings(3)
        [3763, 5067, 3405]
        # Original p1 values: 3.763, 5.067, 3.405

    Parameters
    ----------
    n_users : int – number of rows (smart meters) to load.
    col     : str – column to extract (default "p1").

    Returns
    -------
    list[int] – integer-scaled readings, one per meter.

    Raises
    ------
    FileNotFoundError – if the dataset CSV is not found.
    KeyError          – if the specified column does not exist.
    """
    # Resolve the CSV path relative to this file's directory.
    csv_path = Path(__file__).resolve().parent.parent / DATA_PATH
    if not csv_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {csv_path}.  "
            "Ensure 'smart_grid_stability_augmented.csv' is in the shared/ folder."
        )

    df = pd.read_csv(csv_path)

    if col not in df.columns:
        raise KeyError(
            f"Column '{col}' not found.  Available: {list(df.columns)}"
        )

    # Take the first n_users rows, scale by 1000, cast to int.
    readings = df[col].head(n_users)
    scaled = (readings * SCALE).astype(int)
    return scaled.tolist()
