#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    network/packet.py
# Purpose: Defines the network packet structure, combining real ciphertexts
#          with dummy traffic metadata.
# ──────────────────────────────────────────────────────────────────────

from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class NetworkPacket:
    """
    Represents a packet transmitted from a Smart Meter to the AG/CC.
    All packets (real or dummy) must look identical from the outside.
    """
    is_dummy: bool
    payload_size_bytes: int
    data: Optional[Dict[str, Any]] = None  # MIFE ciphertext, LHH hash, ZKP
    timestamp: float = 0.0
    
    def serialize_size(self) -> int:
        """
        Simulates the serialized size of the packet.
        If it's a dummy, returns the randomized payload size.
        If real, calculates approximate size based on contents.
        """
        if self.is_dummy:
            return self.payload_size_bytes
            
        # Very rough approximation for simulation:
        # ML-KEM encapsulation ~ 1088 bytes
        # MIFE ciphertext ~ 512 bytes
        # ZKP range proof ~ 256 bytes
        # LHH Hash ~ 64 bytes
        return 1920
