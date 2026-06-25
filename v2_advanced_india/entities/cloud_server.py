"""
cloud_server.py – Cloud Server entity.
=========================================

Role in the protocol
--------------------
The Cloud Server is the third-party analytics provider.  It never sees
the raw aggregate — only an FEFQ ciphertext.  When it needs to compute
something (e.g., billing adjustment, statistical scaling), it derives
a function key and evaluates the function on the ciphertext.

Supported queries: any linear function f(x) = a·x + b.
    Examples:
        f(x) = x + 500     → add a fixed offset (e.g., standing charge)
        f(x) = x - 200     → subtract a baseline
        f(x) = 3·x         → multiply (e.g., tariff rate)
        f(x) = 2·x + 100   → combine both

Threat model
------------
The Cloud is honest-but-curious: it follows the protocol correctly
but tries to learn as much as possible from the data it handles.

What the Cloud can learn:
    - The function result f(C) for any function it holds a key for.
    - If a = 1, it can trivially recover C from f(C) = C + b by
      subtracting b.  This is a known limitation of linear FE.

What the Cloud cannot learn (when a ≠ 1 and b ≠ 0):
    - The raw aggregate C (without solving the linear equation,
      which requires knowing both a and b — the Cloud has these in
      the function key, so in practice it CAN recover C for any
      non-zero a).

Honestly, the FEFQ layer provides *computational indistinguishability*
of the ciphertext but NOT semantic security against the key holder.
The value of FEFQ is in the *key issuance model*: the CC controls
which function keys the Cloud receives, and a well-designed deployment
would only issue keys for non-invertible aggregated functions.

Simulation simplification
--------------------------
In this simulation the Cloud holds the full FEFQ secret key (sk) and
derives its own function keys.  A real deployment would have the CC
issue per-query keys instead.
"""

from __future__ import annotations

from crypto.fefq import fefq_keygen, fefq_decrypt


class CloudServer:
    """Simulates the cloud server that answers function queries."""

    def __init__(self, fefq_params: dict):
        """
        Parameters
        ----------
        fefq_params : dict – full FEFQ params (in simulation includes sk).
        """
        self.fefq_params = fefq_params
        self.stored_ct: tuple[int, int] | None = None

    def store(self, ct: tuple[int, int]) -> None:
        """Receive and store the FEFQ ciphertext from the CC.

        In a real system this would arrive over TLS.  The Cloud stores
        it and waits for query requests.

        Parameters
        ----------
        ct : tuple[int, int] – the encrypted aggregate (c1, c2).
        """
        self.stored_ct = ct

    def query(self, a: int = 1, b: int = 0) -> int:
        """Evaluate f(x) = a·x + b on the stored ciphertext.

        Derives a function key for the specific (a, b) pair, then runs
        FEFQ decryption to get the result.  The Cloud sees f(C) but
        not C itself (with the caveats noted in the module docstring).

        Parameters
        ----------
        a : int – multiplicative coefficient (default 1).
        b : int – additive constant (default 0).

        Returns
        -------
        int – the result f(aggregate) = a * aggregate + b.

        Raises
        ------
        RuntimeError – if no ciphertext has been stored yet.
        """
        if self.stored_ct is None:
            raise RuntimeError("No ciphertext stored.  Call store() first.")

        fk = fefq_keygen(self.fefq_params, a=a, b=b)
        return fefq_decrypt(self.stored_ct, fk, self.fefq_params)
