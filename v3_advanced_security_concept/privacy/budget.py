#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    privacy/budget.py
# Purpose: Privacy budget accountant for sequential composition.
# ──────────────────────────────────────────────────────────────────────

class BudgetAccountant:
    """
    Tracks the expenditure of the privacy budget (epsilon) across time.
    Uses basic sequential composition: total loss is the sum of slot losses.
    """
    def __init__(self, daily_epsilon: float, slots_per_day: int = 96):
        self.daily_epsilon = daily_epsilon
        self.slots_per_day = slots_per_day
        self.epsilon_per_slot = daily_epsilon / slots_per_day
        
        self.consumed_epsilon = 0.0
        self.slots_consumed = 0

    def allocate_slot(self) -> float:
        """
        Consume and return the epsilon budget for a single time slot.
        """
        if self.consumed_epsilon + self.epsilon_per_slot > self.daily_epsilon + 1e-9: # tiny float tolerance
             # In a real system, we might refuse to answer or reduce accuracy.
             # For simulation, we warn but allow.
             print(f"WARNING: Privacy budget exceeded! ({self.consumed_epsilon:.3f} > {self.daily_epsilon:.3f})")
             
        self.consumed_epsilon += self.epsilon_per_slot
        self.slots_consumed += 1
        return self.epsilon_per_slot

    def remaining_budget(self) -> float:
        return max(0.0, self.daily_epsilon - self.consumed_epsilon)

    def composition_loss(self) -> float:
        """Returns the total privacy loss so far."""
        return self.consumed_epsilon
