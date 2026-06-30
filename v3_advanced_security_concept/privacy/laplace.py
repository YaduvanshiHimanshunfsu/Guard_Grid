#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    privacy/laplace.py
# Purpose: Core Differential Privacy engine using the Laplace mechanism.
# ──────────────────────────────────────────────────────────────────────

import numpy as np

def add_laplace_noise(value: float, sensitivity: float, epsilon: float, clip_min: float = 0.0, clip_max: float = None) -> int:
    """
    Inject calibrated Laplace noise into a value to satisfy epsilon-DP.
    
    Args:
        value (float): The raw reading (e.g. scaled kW).
        sensitivity (float): Maximum possible change one user can cause.
        epsilon (float): The privacy budget. Smaller = more private/noisy.
        clip_min (float): Minimum bound to prevent negative readings.
        
    Returns:
        int: The noisy value, rounded to integer for MIFE compatibility.
    """
    if epsilon <= 0:
        raise ValueError("Epsilon must be strictly positive.")
        
    scale = sensitivity / epsilon
    noise = np.random.laplace(loc=0.0, scale=scale)
    
    noisy_value = value + noise
    
    # Clip to minimum to prevent negative values which might break billing logic
    if clip_min is not None:
        noisy_value = max(clip_min, noisy_value)
    if clip_max is not None:
        noisy_value = min(clip_max, noisy_value)
        
    # MIFE requires integers
    return round(noisy_value)

def compute_aggregate_error_std(n_meters: int, sensitivity: float, epsilon: float) -> float:
    """
    Compute the standard deviation of the error on the aggregate sum.
    
    Because the sum of n independent Laplace(b) variables is not exactly
    Laplace(n*b), its variance is n * 2b^2.
    So std_dev = sqrt(n * 2b^2) = b * sqrt(2n) = (sensitivity/epsilon) * sqrt(2n).
    
    This shows how aggregate error scales with sqrt(n), proving that relative
    error shrinks as the neighborhood size n increases.
    """
    b = sensitivity / epsilon
    variance = n_meters * 2 * (b ** 2)
    return np.sqrt(variance)
