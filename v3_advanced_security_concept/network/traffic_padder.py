#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    network/traffic_padder.py
# Purpose: Generates adaptive Poisson-scheduled dummy traffic to
#          prevent pattern analysis (e.g., vacation detection).
# ──────────────────────────────────────────────────────────────────────

import numpy as np
import time
from network.packet import NetworkPacket

class TrafficPadder:
    def __init__(self, lambda_rate_per_hour: float = 50.0, size_range: tuple = (1000, 2000)):
        """
        Args:
            lambda_rate_per_hour (float): Average dummy packets per hour.
            size_range (tuple): (min, max) bytes for dummy payloads.
        """
        self.lambda_rate = lambda_rate_per_hour
        # Convert to rate per second
        self.rate_per_sec = self.lambda_rate / 3600.0
        self.size_range = size_range

    def generate_dummy_schedule(self, duration_sec: float) -> list[float]:
        """
        Generates a schedule of dummy transmission times over a given duration.
        Uses an exponential distribution (Poisson process).
        
        Returns:
            list[float]: Relative timestamps (in seconds) for dummy packets.
        """
        schedule = []
        current_time = 0.0
        
        while True:
            # Wait time until next event: Exponential(1/lambda)
            wait_time = np.random.exponential(scale=1.0/self.rate_per_sec)
            current_time += wait_time
            
            if current_time >= duration_sec:
                break
                
            schedule.append(current_time)
            
        return schedule

    def create_dummy_packet(self, timestamp: float) -> NetworkPacket:
        """
        Creates a dummy packet of random size within the configured range.
        """
        size = int(np.random.uniform(self.size_range[0], self.size_range[1]))
        return NetworkPacket(is_dummy=True, payload_size_bytes=size, timestamp=timestamp)

def estimate_bandwidth_cost(n_meters: int, lambda_rate: float, days: int = 30) -> float:
    """
    Estimate the total bandwidth used by dummy packets over a period.
    Returns size in Megabytes.
    """
    hours = days * 24
    expected_dummies_per_meter = lambda_rate * hours
    avg_size_bytes = 1500 # mid of (1000, 2000)
    
    total_bytes = n_meters * expected_dummies_per_meter * avg_size_bytes
    return total_bytes / (1024 * 1024)
