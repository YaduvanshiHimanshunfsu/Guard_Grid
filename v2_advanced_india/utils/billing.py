#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V2 – Advanced India Version
# File:    utils/billing.py
# Purpose: Feeder-level revenue estimation using Indian tariff slabs.
#
# Design: The CC only sees the TOTAL aggregate across all meters.
#         Individual household consumption is never revealed.
#         Therefore billing operates on the aggregate, reframed as
#         distribution-company-level revenue estimation.
#
# Tariff source: Delhi Electricity Regulatory Commission (DERC)
#                Tariff Order 2023-24, domestic category.
#                https://www.derc.gov.in
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BillResult:
    """Result of a billing computation."""
    total_revenue_inr: float
    avg_per_meter_kwh: float
    avg_per_meter_bill_inr: float
    effective_rate_per_kwh: float
    tariff_slab_applied: str
    n_meters: int


def tariff_profile_derc_2024() -> dict:
    """Return the DERC domestic tariff structure (2023-24).

    Three-slab progressive pricing:
        0–200 units   : INR 3.00 / kWh
        201–400 units : INR 4.50 / kWh
        401+ units    : INR 6.50 / kWh
    Fixed charge: INR 125 per connection per month.
    """
    return {
        "slabs": [
            {"lo": 0, "hi": 200, "rate": 3.00},
            {"lo": 201, "hi": 400, "rate": 4.50},
            {"lo": 401, "hi": float("inf"), "rate": 6.50},
        ],
        "fixed_charge": 125.0,
        "currency": "INR",
        "source": "DERC Tariff Order 2023-24",
    }


def compute_slab_bill(consumption_kwh: float, tariff: dict | None = None) -> float:
    """Compute the electricity bill for a single consumption value.

    Applies progressive slab rates.  This is a utility function for
    demonstration — in the privacy model, it would only be applied to
    aggregated or estimated per-meter averages, never to individually
    decrypted readings (which the CC cannot access).

    Parameters
    ----------
    consumption_kwh : float – energy consumed in kWh.
    tariff          : dict | None – tariff profile.  None → DERC default.

    Returns
    -------
    float – total bill in INR.
    """
    if tariff is None:
        tariff = tariff_profile_derc_2024()

    if consumption_kwh < 0:
        raise ValueError(f"Consumption cannot be negative: {consumption_kwh}")

    remaining = consumption_kwh
    total = tariff["fixed_charge"]

    for slab in tariff["slabs"]:
        lo, hi, rate = slab["lo"], slab["hi"], slab["rate"]
        slab_width = hi - lo if hi != float("inf") else remaining
        units_in_slab = min(remaining, slab_width)

        if units_in_slab <= 0:
            break

        total += units_in_slab * rate
        remaining -= units_in_slab

    return round(total, 2)


def compute_feeder_revenue(aggregate_kwh: float, n_meters: int,
                           tariff: dict | None = None) -> BillResult:
    """Estimate total feeder revenue from the decrypted aggregate.

    Method: compute average per-meter consumption from the aggregate,
    apply tariff slabs to the average, then scale back up by n_meters.

    This is an estimation — individual households may fall in different
    slabs.  The aggregate-based estimate is what a distribution company
    would use for feeder-level financial planning.

    Parameters
    ----------
    aggregate_kwh : float – total consumption across all meters (kWh).
    n_meters      : int – number of meters on this feeder.
    tariff        : dict | None – tariff profile.

    Returns
    -------
    BillResult – revenue estimate and breakdown.
    """
    if n_meters <= 0:
        raise ValueError(f"n_meters must be > 0, got {n_meters}")

    if tariff is None:
        tariff = tariff_profile_derc_2024()

    avg_kwh = aggregate_kwh / n_meters
    avg_bill = compute_slab_bill(avg_kwh, tariff)
    total_revenue = avg_bill * n_meters

    # Determine which slab the average falls in.
    slab_name = "unknown"
    for slab in tariff["slabs"]:
        if slab["lo"] <= avg_kwh <= slab["hi"]:
            slab_name = f"{slab['lo']}–{slab['hi']} units @ INR {slab['rate']}/kWh"
            break

    effective_rate = (total_revenue - tariff["fixed_charge"] * n_meters) / max(aggregate_kwh, 0.01)

    return BillResult(
        total_revenue_inr=round(total_revenue, 2),
        avg_per_meter_kwh=round(avg_kwh, 4),
        avg_per_meter_bill_inr=round(avg_bill, 2),
        effective_rate_per_kwh=round(effective_rate, 4),
        tariff_slab_applied=slab_name,
        n_meters=n_meters,
    )
