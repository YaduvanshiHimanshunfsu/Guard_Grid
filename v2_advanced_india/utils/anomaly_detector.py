#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    utils/anomaly_detector.py
# Purpose: Rolling-window anomaly detector for aggregate readings.
#          Operates entirely on decrypted aggregates at the CC level.
#          Flags sudden drops (theft), spikes (faults), or drift.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class AnomalyResult:
    """Result of an anomaly check."""
    is_anomaly: bool
    z_score: float | None
    current_value: float
    expected_mean: float | None
    expected_std: float | None
    expected_range: tuple[float, float] | None
    message: str


class AnomalyDetector:
    """Rolling-window anomaly detector for aggregate readings.

    Keeps history per time slot (e.g. 0-95 for a 15-minute 96-slot day).
    """

    def __init__(self, window_days: int = 7, z_threshold: float = 2.0):
        self._window = window_days
        self._threshold = z_threshold
        # Maps slot_id (0-95) -> list of historical aggregate values
        self._history: dict[int, list[float]] = {}

    def _ensure_slot(self, slot_id: int) -> None:
        if slot_id not in self._history:
            self._history[slot_id] = []

    def record(self, slot_id: int, value: float) -> None:
        """Append a reading for a specific time-of-day slot."""
        self._ensure_slot(slot_id)
        # Keep only the most recent `_window` days
        self._history[slot_id].append(value)
        if len(self._history[slot_id]) > self._window:
            self._history[slot_id].pop(0)

    def check(self, slot_id: int, value: float) -> AnomalyResult:
        """Check whether `value` is anomalous for this slot."""
        self._ensure_slot(slot_id)
        history = self._history[slot_id]

        if len(history) < 2:
            return AnomalyResult(
                is_anomaly=False,
                z_score=None,
                current_value=value,
                expected_mean=None,
                expected_std=None,
                expected_range=None,
                message="Not enough historical data (need at least 2 days)."
            )

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / (len(history) - 1)
        std_dev = math.sqrt(variance)

        # Avoid division by zero if all historical values are identical
        if std_dev < 1e-6:
            if abs(value - mean) > 1e-6:
                z_score = float('inf') # Definite anomaly if it deviates from a constant history
                is_anomaly = True
            else:
                z_score = 0.0
                is_anomaly = False
        else:
            z_score = abs(value - mean) / std_dev
            is_anomaly = z_score > self._threshold

        expected_range = (mean - self._threshold * std_dev, mean + self._threshold * std_dev)

        if is_anomaly:
            msg = f"⚠ ANOMALY: {value:.2f} deviates significantly from expected {mean:.2f} ± {self._threshold * std_dev:.2f} (z-score: {z_score:.2f})"
        else:
            msg = f"✓ Normal: {value:.2f} is within expected {mean:.2f} ± {self._threshold * std_dev:.2f}"

        return AnomalyResult(
            is_anomaly=is_anomaly,
            z_score=z_score,
            current_value=value,
            expected_mean=mean,
            expected_std=std_dev,
            expected_range=expected_range,
            message=msg
        )

    def get_history(self, slot_id: int) -> list[float]:
        """Return all recorded values for a slot."""
        self._ensure_slot(slot_id)
        return list(self._history[slot_id])
