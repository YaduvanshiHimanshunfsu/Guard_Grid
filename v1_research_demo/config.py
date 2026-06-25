"""
config.py – Central configuration for the V1 Research Demo.
============================================================

Every constant that controls the behaviour of the simulation lives in
this single file.  Other modules pull values from here so a change
in one place ripples through the entire codebase automatically.

The design goal: anyone reading the paper can match a constant here
to a symbol in the paper and know exactly what it controls.

Paper reference map
-------------------
    LAMBDA  ↔  λ   (security parameter, bit-length of primes)
    N_USERS ↔  n   (count of smart meters in the network)
    SCALE   ↔  -   (not in the paper; our trick to turn floats into ints)

Why frozen dataclass?
    Because configuration should never mutate mid-run.  A frozen
    dataclass gives us named fields, immutability, and a clean repr()
    for debug output — all without writing boilerplate __init__ logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class GuardGridConfig:
    """Immutable project-wide settings.

    These defaults are deliberately small to keep setup and encryption
    times within seconds, not minutes.

    ===================================================================
    WARNING: The 512-bit primes are NOT cryptographically secure for
    real deployment. Production systems MUST use at least 2048 bits
    for discrete-log based cryptography. We use 512 purely so
    benchmarks finish in reasonable wall-clock time on a laptop.
    ===================================================================

    Attributes
    ----------
    security_parameter_bits : int
        Bit-length of the safe primes generated for DH and LHH groups.
        Controls the hardness of the discrete logarithm problem that
        underpins every cryptographic operation in the scheme.

    default_user_count : int
        How many smart meters to simulate when the user does not pass
        an explicit count on the command line.  10 is small enough for
        quick smoke tests; the benchmark module sweeps larger values.

    scale_factor : int
        The CSV contains floating-point power readings (e.g. 3.763 kW).
        Cryptographic primitives (MIFE, DH masking) require integers.
        We multiply every reading by this factor before encryption and
        divide by the same factor after decryption to recover the float.
        1000 preserves three decimal places of precision.

    dh_group_bits : int
        Bit-length of the DH group prime.  Kept equal to
        security_parameter_bits for simplicity in V1.

    data_path : Path
        Relative path from *this* file's directory to the shared CSV.
        Both V1 and V2 read from the same dataset in ../shared/ to
        avoid duplicating a 14 MB file.
    """

    security_parameter_bits: int = 512
    default_user_count:      int = 10
    scale_factor:            int = 1000
    dh_group_bits:           int = 512
    data_path:              Path = Path("../shared/smart_grid_stability_augmented.csv")


# Instantiate once at import time; every other module reads from this.
CONFIG = GuardGridConfig()


# ---------------------------------------------------------------------------
# Backward-compatible module-level aliases.
#
# The rest of the codebase does:
#     from config import N_USERS, SCALE, ...
#
# These aliases keep import lines short while still routed through
# the single CONFIG object above.
# ---------------------------------------------------------------------------
LAMBDA     = CONFIG.security_parameter_bits
N_USERS    = CONFIG.default_user_count
SCALE      = CONFIG.scale_factor
GROUP_BITS = CONFIG.dh_group_bits
DATA_PATH  = str(CONFIG.data_path)
