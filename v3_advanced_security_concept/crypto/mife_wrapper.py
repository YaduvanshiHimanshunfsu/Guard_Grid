#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    crypto/mife_wrapper.py
# Purpose: Static wrapper for PyMIFE to support V3's architecture.
# ──────────────────────────────────────────────────────────────────────

from Crypto.Util.number import getPrime
from mife.data.zmod import Zmod
from mife.multi.damgard import FeDamgardMulti

class MIFEWrapper:
    @staticmethod
    def setup(n_users: int, key_bits: int = 512):
        p = getPrime(key_bits)
        F = Zmod(p)
        master_key = FeDamgardMulti.generate(n=n_users, m=1, F=F)
        sk_y = FeDamgardMulti.keygen([[1] for _ in range(n_users)], master_key)
        slot_keys = [master_key.get_enc_key(i) for i in range(n_users)]
        
        return {
            "pk": master_key.get_public_key(),
            "sk": sk_y,
            "slot_keys": slot_keys
        }

    @staticmethod
    def encrypt(msg_list: list, slot_key):
        """msg_list should be a list of 1 integer"""
        return FeDamgardMulti.encrypt(msg_list, slot_key)

    @staticmethod
    def decrypt(pk, sk_y, ciphertexts, bound=(-10**9, 10**9)):
        return FeDamgardMulti.decrypt(ciphertexts, pk, sk_y, bound)
