#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    entities/dkg_committee.py
# Purpose: Wrapper for the DKG Orchestrator to act as the Setup phase.
# ──────────────────────────────────────────────────────────────────────

from crypto.pedersen_dkg import DKGOrchestrator

class DKGCommittee:
    def __init__(self, K: int, T: int, p: int, g: int):
        self.orchestrator = DKGOrchestrator(K, T, p, g)
        
    def setup_system(self) -> int:
        """
        Run the DKG to produce the global public key.
        Returns the global public key.
        """
        return self.orchestrator.run_dkg()
