#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    utils/fault_handler.py
# Purpose: Manage meter availability across simulation rounds.
#          When meters go offline, this module decides which ones
#          are down, checks if the offline count is within tolerance,
#          and logs patterns for trend analysis.
#
# Alert logic: if more than MAX_OFFLINE_PCT of meters are offline in
#              a single round, it could indicate a coordinated attack
#              on the feeder (ref: paper [7] — Gunduz & Das).
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class FaultAlert:
    """Result of an offline-count check."""
    alert: bool
    offline_count: int
    offline_pct: float
    message: str


class FaultHandler:
    """Tracks meter availability and manages offline scenarios."""

    def __init__(self, n_users: int, max_offline_pct: float = 0.30):
        """
        Parameters
        ----------
        n_users         : int – total meters in the network.
        max_offline_pct : float – threshold for raising an alert.
        """
        if n_users < 1:
            raise ValueError(f"n_users must be >= 1, got {n_users}")
        if not 0.0 <= max_offline_pct <= 1.0:
            raise ValueError(f"max_offline_pct must be in [0, 1], got {max_offline_pct}")

        self.n_users = n_users
        self.max_offline_pct = max_offline_pct
        self._history: list[dict] = []

    def simulate_offline(self, n_offline: int, seed: int | None = None) -> list[bool]:
        """Randomly select n_offline meters to mark as offline.

        Parameters
        ----------
        n_offline : int – how many meters to take offline.
        seed      : int | None – for reproducible tests.

        Returns
        -------
        list[bool] – online_mask.  True = online, False = offline.
        """
        n_offline = max(0, min(n_offline, self.n_users))

        if seed is not None:
            rng = random.Random(seed)
        else:
            rng = random.Random()

        offline_indices = set(rng.sample(range(self.n_users), n_offline))
        return [i not in offline_indices for i in range(self.n_users)]

    def check_alert(self, online_mask: list[bool]) -> FaultAlert:
        """Determine if the offline count exceeds the safety threshold.

        Returns
        -------
        FaultAlert – with alert=True if threshold exceeded.
        """
        offline_count = online_mask.count(False)
        offline_pct = offline_count / len(online_mask)

        if offline_pct > self.max_offline_pct:
            msg = (f"⚠ ALERT: {offline_count}/{len(online_mask)} meters offline "
                   f"({offline_pct:.0%}) — exceeds {self.max_offline_pct:.0%} threshold. "
                   f"Possible coordinated attack on feeder.")
        elif offline_count > 0:
            msg = (f"ℹ {offline_count}/{len(online_mask)} meters offline "
                   f"({offline_pct:.0%}) — within tolerance.")
        else:
            msg = "✓ All meters online."

        return FaultAlert(
            alert=offline_pct > self.max_offline_pct,
            offline_count=offline_count,
            offline_pct=offline_pct,
            message=msg,
        )

    def log_round(self, round_id: int, online_mask: list[bool]) -> None:
        """Record this round's offline pattern for trend analysis."""
        offline_indices = [i for i, v in enumerate(online_mask) if not v]
        self._history.append({
            "round_id": round_id,
            "offline_count": len(offline_indices),
            "offline_indices": offline_indices,
        })

    def get_history(self) -> list[dict]:
        """Return the full log of offline events."""
        return list(self._history)

    def get_frequently_offline(self, threshold: int = 3) -> list[int]:
        """Find meters that have gone offline more than `threshold` times.

        Useful for identifying consistently faulty hardware.
        """
        counts: dict[int, int] = {}
        for entry in self._history:
            for idx in entry["offline_indices"]:
                counts[idx] = counts.get(idx, 0) + 1
        return [idx for idx, cnt in counts.items() if cnt >= threshold]
