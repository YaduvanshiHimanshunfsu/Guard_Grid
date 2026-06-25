"""
agg_gateway.py – Aggregation Gateway entity.
===============================================

Role in the protocol
--------------------
The AG is the **untrusted** edge server that sits between the smart
meters and the Control Center.  Think of it as a neighbourhood router
that collects encrypted data from all the meters on a single feeder.

It performs two operations:
    1. Collects all n ciphertexts and hashes from the SMs.
    2. Uses the MIFE functional decryption key sk_y to compute
       C' = Σ mi  (the masked aggregate).
    3. Multiplies all LHH hashes into h* = ∏ hi mod p'.
    4. Forwards (C', h*) to the CC.

What the AG CANNOT do
----------------------
    - It cannot learn any individual reading xi because each mi = xi + ki
      and the AG does not know any session key ki.
    - It cannot tamper with C' or h* without being caught — the CC will
      check g'^{C'} == h* and detect any inconsistency.
    - It cannot forge a valid h* for a fabricated C'' because that would
      require solving the discrete log in the LHH group.

Why the AG is "untrusted" but still useful
-------------------------------------------
In a centralised model, every SM would send directly to the CC.  With
thousands of meters, this creates a bottleneck.  The AG offloads the
aggregation work to edge servers — the CC only processes one message
(C', h*) per round instead of n messages.

The entire FEHH scheme is designed so that this delegation is safe:
the AG handles encrypted data, does useful work on it (aggregation),
and cannot cheat.  This is the core value proposition of the paper.

Stateful design note
--------------------
The AG accumulates ciphertexts in a buffer (_collected) and clears
it after each aggregate() call.  This models the round-by-round
operation of the real system.
"""

from __future__ import annotations

from schemes.fehh import fehh_agg


class AggregationGateway:
    """Simulates the aggregation gateway."""

    def __init__(self, fehh_params: dict):
        """
        Parameters
        ----------
        fehh_params : dict – output of fehh_setup.
                      Needs: mife, master_key, sk_y, lhh_p, lhh_g.
        """
        self.fehh_params = fehh_params
        self._collected: list[dict] = []

    def receive(self, enc_result: dict) -> None:
        """Accept a single SM's encrypted bundle.

        In the real world this would arrive over a network connection.
        Here we model it as a method call.

        Parameters
        ----------
        enc_result : dict – {ctx, h} from a SmartMeter.
        """
        self._collected.append(enc_result)

    def aggregate(self) -> dict:
        """Run FEHH.Agg after all n ciphertexts have been received.

        Produces the masked aggregate C' and the hash product h*.
        Clears the internal buffer so the AG is ready for the next round.

        Returns
        -------
        dict with:
            C_prime – the masked aggregate (int).
            h_star  – the evaluated hash product (int).

        Raises
        ------
        RuntimeError – if no ciphertexts have been collected yet.
        """
        if not self._collected:
            raise RuntimeError("No ciphertexts received yet.")

        result = fehh_agg(self._collected, self.fehh_params)
        self._collected = []        # Clear for the next round.
        return result
