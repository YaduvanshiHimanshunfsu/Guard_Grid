#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    crypto/feldman_vss.py
# Purpose: Feldman's Verifiable Secret Sharing.
#          Allows a dealer to share a secret and broadcast commitments
#          so receivers can verify their shares.
# ──────────────────────────────────────────────────────────────────────

import gmpy2
import random

class FeldmanVSS:
    def __init__(self, p: int, g: int, t: int, n: int):
        """
        Initialize the VSS parameters.
        
        Args:
            p (int): A safe prime (modulus).
            g (int): A generator for the subgroup of order q = (p-1)/2.
            t (int): The threshold of shares required to reconstruct.
            n (int): The total number of shares to generate.
        """
        self.p = p
        self.g = g
        self.t = t
        self.n = n
        self.q = (p - 1) // 2

    def deal(self, secret: int):
        """
        Deal a secret into n shares and generate commitments.
        
        Args:
            secret (int): The secret value to share (must be < q).
            
        Returns:
            tuple: (shares, commitments)
                   shares is a list of (x, y) tuples.
                   commitments is a list of C_k = g^{a_k} mod p.
        """
        # 1. Choose random polynomial f(x) = s + a_1*x + ... + a_{t-1}*x^{t-1} mod q
        coefficients = [secret % self.q]
        for _ in range(1, self.t):
            # Random coefficient in [1, q-1]
            a_k = random.randint(1, int(self.q - 1))
            coefficients.append(a_k)
            
        # 2. Generate commitments C_k = g^{a_k} mod p
        commitments = []
        for a_k in coefficients:
            C_k = int(gmpy2.powmod(self.g, a_k, self.p))
            commitments.append(C_k)
            
        # 3. Evaluate polynomial at x = 1..n to create shares
        shares = []
        for x in range(1, self.n + 1):
            y = 0
            x_pow = 1
            for a_k in coefficients:
                y = (y + a_k * x_pow) % self.q
                x_pow = (x_pow * x) % self.q
            shares.append((x, int(y)))
            
        return shares, commitments

    def verify_share(self, share: tuple[int, int], commitments: list[int]) -> bool:
        """
        Verify that a share is consistent with the public commitments.
        
        Args:
            share (tuple): (x, y)
            commitments (list): The list of C_k commitments.
            
        Returns:
            bool: True if valid, False otherwise.
        """
        x, y = share
        
        # Calculate g^y mod p
        lhs = int(gmpy2.powmod(self.g, y, self.p))
        
        # Calculate Product_{k=0}^{t-1} (C_k)^{x^k} mod p
        rhs = 1
        x_pow = 1
        for C_k in commitments:
            # (C_k)^{x^k} mod p
            term = int(gmpy2.powmod(C_k, x_pow, self.p))
            rhs = (rhs * term) % self.p
            x_pow = (x_pow * x) % self.q
            
        return lhs == rhs

    def reconstruct(self, shares: list[tuple[int, int]]) -> int:
        """
        Reconstruct the secret from at least t shares using Lagrange interpolation.
        
        Args:
            shares (list): A list of (x, y) tuples.
            
        Returns:
            int: The reconstructed secret.
        """
        if len(shares) < self.t:
            raise ValueError(f"Need at least {self.t} shares to reconstruct, got {len(shares)}")
            
        # Use the first t shares
        shares = shares[:self.t]
        secret = 0
        
        for i in range(self.t):
            x_i, y_i = shares[i]
            
            # Compute Lagrange basis polynomial l_i(0)
            numerator = 1
            denominator = 1
            for j in range(self.t):
                if i != j:
                    x_j, _ = shares[j]
                    numerator = (numerator * (0 - x_j)) % self.q
                    denominator = (denominator * (x_i - x_j)) % self.q
                    
            # l_i(0) = numerator * denominator^-1 mod q
            inv_denominator = int(gmpy2.invert(denominator, self.q))
            l_i_0 = (numerator * inv_denominator) % self.q
            
            # Add to secret
            secret = (secret + y_i * l_i_0) % self.q
            
        return int(secret)
