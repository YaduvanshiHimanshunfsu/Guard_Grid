#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    crypto/pedersen_dkg.py
# Purpose: Pedersen Distributed Key Generation (DKG) Protocol.
#          Combines multiple instances of Feldman VSS to jointly
#          generate a shared public/private keypair without a TTP.
# ──────────────────────────────────────────────────────────────────────

import gmpy2
import random
from typing import Dict, List, Tuple
from crypto.feldman_vss import FeldmanVSS

class DKGNode:
    def __init__(self, node_id: int, p: int, g: int, t: int, n: int):
        self.node_id = node_id
        self.vss = FeldmanVSS(p, g, t, n)
        self.p = p
        self.q = self.vss.q
        self.g = g
        
        # Local secrets
        self.secret_contribution = random.randint(1, int(self.q - 1))
        self.local_shares_generated = []      # Shares to send to others
        self.local_commitments = []           # Commitments to broadcast
        
        # State received from others
        self.received_shares: Dict[int, int] = {}       # node_id -> share value
        self.received_commitments: Dict[int, List[int]] = {} # node_id -> list of commitments
        
        # Final outputs
        self.final_secret_share = None
        self.global_public_key = None

    def run_round1(self) -> Tuple[List[Tuple[int, int]], List[int]]:
        """
        Round 1: Generate polynomial, shares, and commitments.
        Returns:
            (shares_to_distribute, commitments_to_broadcast)
        """
        shares, commitments = self.vss.deal(self.secret_contribution)
        self.local_shares_generated = shares
        self.local_commitments = commitments
        
        # Keep our own share
        our_share = next(s[1] for s in shares if s[0] == self.node_id)
        self.received_shares[self.node_id] = our_share
        self.received_commitments[self.node_id] = commitments
        
        return shares, commitments

    def receive_round1_data(self, from_node: int, share: Tuple[int, int], commitments: List[int]) -> bool:
        """
        Round 2: Receive share and commitments from another node, and verify.
        """
        # We expect the share to be for our node_id
        assert share[0] == self.node_id
        
        is_valid = self.vss.verify_share(share, commitments)
        if is_valid:
            self.received_shares[from_node] = share[1]
            self.received_commitments[from_node] = commitments
            return True
        else:
            # In a full implementation, we would broadcast a complaint here.
            # For simulation, we just return False and exclude the dishonest node.
            return False

    def finalize(self):
        """
        Finalize the DKG process to compute the local secret share and global public key.
        """
        # Sum up all valid received shares
        total_share = 0
        for share_val in self.received_shares.values():
            total_share = (total_share + share_val) % self.q
        self.final_secret_share = total_share
        
        # Multiply the constant term commitments from all valid nodes to get the Global PK
        global_pk = 1
        for comms in self.received_commitments.values():
            C_0 = comms[0] # Commitment to the constant term (secret)
            global_pk = (global_pk * C_0) % self.p
        self.global_public_key = global_pk

class DKGOrchestrator:
    """
    Simulates the network orchestrating the DKG rounds among nodes.
    """
    def __init__(self, num_nodes: int, threshold: int, p: int, g: int):
        self.nodes = [DKGNode(i+1, p, g, threshold, num_nodes) for i in range(num_nodes)]
        self.num_nodes = num_nodes
        self.threshold = threshold

    def run_dkg(self):
        """Run the full simulated DKG protocol."""
        # --- Round 1: Generate and Distribute ---
        all_shares = {}       # from_node -> [(to_node, share_val), ...]
        all_commitments = {}  # from_node -> [C_0, C_1, ...]
        
        for node in self.nodes:
            shares, comms = node.run_round1()
            all_shares[node.node_id] = shares
            all_commitments[node.node_id] = comms
            
        # --- Round 2: Receive and Verify ---
        # Simulate network delivery
        for receiver in self.nodes:
            for sender_id, shares in all_shares.items():
                if sender_id == receiver.node_id:
                    continue # Already processed own share
                
                # Find the share meant for this receiver
                my_share = next(s for s in shares if s[0] == receiver.node_id)
                sender_comms = all_commitments[sender_id]
                
                valid = receiver.receive_round1_data(sender_id, my_share, sender_comms)
                if not valid:
                    print(f"Node {receiver.node_id} rejected share from Node {sender_id}!")

        # --- Finalize ---
        for node in self.nodes:
            node.finalize()
            
        # Verify all nodes agree on the global public key
        pk_0 = self.nodes[0].global_public_key
        for node in self.nodes:
            assert node.global_public_key == pk_0, "Nodes disagree on Global PK!"
            
        return pk_0
