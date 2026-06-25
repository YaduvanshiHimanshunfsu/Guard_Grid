#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    utils/credit_score.py
# Purpose: AG reputation tracker based on LHH verification outcomes.
#          Implements the credit-score adjustment described in
#          Section VI-A of the paper — which the paper mentions but
#          never actually builds.
#
# Scoring rules:
#   Start    : 100 points
#   Pass     : +2  (capped at 100)
#   Fail     : −15
#   Flagged  : score < 50  (under review)
#   Revoked  : score < 20  (key should be rotated)
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class CreditStatus:
    """Snapshot of an AG's reputation."""
    ag_id: str
    score: int
    status: str          # "active", "flagged", "revoked"
    total_rounds: int
    pass_count: int
    fail_count: int


class CreditTracker:
    """In-memory AG reputation system."""

    def __init__(self, initial_score: int = 100,
                 pass_bonus: int = 2,
                 fail_penalty: int = 15,
                 flag_threshold: int = 50,
                 revoke_threshold: int = 20):
        self._initial = initial_score
        self._pass_bonus = pass_bonus
        self._fail_penalty = fail_penalty
        self._flag_at = flag_threshold
        self._revoke_at = revoke_threshold
        self._scores: dict[str, int] = {}
        self._history: dict[str, list[dict]] = {}

    def _ensure_ag(self, ag_id: str) -> None:
        """Lazily initialize an AG's entry."""
        if ag_id not in self._scores:
            self._scores[ag_id] = self._initial
            self._history[ag_id] = []

    def record_round(self, ag_id: str, verified: bool) -> int:
        """Record a round outcome and return the updated score.

        Parameters
        ----------
        ag_id    : str – unique identifier for the AG.
        verified : bool – True if LHH verification passed.

        Returns
        -------
        int – the new score after adjustment.
        """
        self._ensure_ag(ag_id)

        if verified:
            self._scores[ag_id] = min(self._initial, self._scores[ag_id] + self._pass_bonus)
            delta = self._pass_bonus
        else:
            self._scores[ag_id] = max(0, self._scores[ag_id] - self._fail_penalty)
            delta = -self._fail_penalty

        self._history[ag_id].append({
            "verified": verified,
            "delta": delta,
            "score_after": self._scores[ag_id],
        })
        return self._scores[ag_id]

    def get_score(self, ag_id: str) -> int:
        self._ensure_ag(ag_id)
        return self._scores[ag_id]

    def is_flagged(self, ag_id: str) -> bool:
        return self.get_score(ag_id) < self._flag_at

    def is_revoked(self, ag_id: str) -> bool:
        return self.get_score(ag_id) < self._revoke_at

    def summary(self, ag_id: str) -> CreditStatus:
        """Return a summary of the AG's reputation."""
        self._ensure_ag(ag_id)
        history = self._history[ag_id]

        if self.is_revoked(ag_id):
            status = "REVOKED"
        elif self.is_flagged(ag_id):
            status = "FLAGGED"
        else:
            status = "ACTIVE"

        return CreditStatus(
            ag_id=ag_id,
            score=self._scores[ag_id],
            status=status,
            total_rounds=len(history),
            pass_count=sum(1 for h in history if h["verified"]),
            fail_count=sum(1 for h in history if not h["verified"]),
        )

    def get_score_history(self, ag_id: str) -> list[int]:
        self._ensure_ag(ag_id)
        return [h['score_after'] for h in self._history[ag_id]]

    def plot_score_history(self, ag_id: str, save_path: str = None) -> None:
        scores = self.get_score_history(ag_id)
        if len(scores) == 0:
            print("No history to plot.")
            return
        
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(scores, color='steelblue', linewidth=1.5, label='Credit Score')
        ax.axhline(y=50, color='orange', linestyle='--', linewidth=1, label='Flag threshold (50)')
        ax.axhline(y=20, color='red', linestyle='--', linewidth=1, label='Revoke threshold (20)')
        ax.axhline(y=100, color='green', linestyle=':', linewidth=0.8, label='Max (100)')
        
        # Shade regions where score is below flag threshold
        for i, s in enumerate(scores):
            if s < 50:
                ax.axvspan(i-0.5, i+0.5, alpha=0.15, color='orange')
        
        ax.set_xlabel('Round Number')
        ax.set_ylabel('Credit Score')
        ax.set_title(f'AG Credit Score Trajectory — {ag_id}')
        ax.legend(loc='lower left')
        ax.set_ylim(0, 110)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150)
            print(f"[Plot] Saved to {save_path}")
        plt.close(fig)

    def export_json(self, path: str) -> None:
        """Persist scores and history to a JSON file."""
        data = {}
        for ag_id in self._scores:
            s = self.summary(ag_id)
            data[ag_id] = {
                "score": s.score,
                "status": s.status,
                "total_rounds": s.total_rounds,
                "pass_count": s.pass_count,
                "fail_count": s.fail_count,
                "history": self._history[ag_id],
            }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
