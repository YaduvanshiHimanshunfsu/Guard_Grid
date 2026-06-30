#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────
# GuardGrid V3 – Advanced Security Concept
# File:    crypto/mlkem.py
# Purpose: Post-Quantum Key Encapsulation (replaces Diffie-Hellman)
#          Uses NIST FIPS 203 standardized ML-KEM-768.
# ──────────────────────────────────────────────────────────────────────

from kyber_py.ml_kem import ML_KEM_768

def mlkem_keygen():
    """
    Generate an ML-KEM-768 key pair.
    
    Returns:
        tuple: (ek, dk) - Encapsulation Key (public), Decapsulation Key (private)
    """
    # ek (Encapsulation Key) is the public key
    # dk (Decapsulation Key) is the private key
    ek, dk = ML_KEM_768.keygen()
    return ek, dk

def mlkem_encaps(ek):
    """
    Encapsulate a shared secret against a public encapsulation key.
    
    Args:
        ek: The public encapsulation key.
        
    Returns:
        tuple: (shared_secret, ciphertext)
    """
    shared_secret, ciphertext = ML_KEM_768.encaps(ek)
    return shared_secret, ciphertext

def mlkem_decaps(dk, ciphertext):
    """
    Decapsulate a shared secret using a private decapsulation key.
    
    Args:
        dk: The private decapsulation key.
        ciphertext: The encapsulated ciphertext.
        
    Returns:
        bytes: The recovered shared secret.
    """
    shared_secret = ML_KEM_768.decaps(dk, ciphertext)
    return shared_secret

def derive_session_mask(shared_secret: bytes, mask_bound: int) -> int:
    """
    Derive an integer mask from the shared secret, bounded for MIFE.
    We take the first 8 bytes of the shared secret to create an integer.
    
    Args:
        shared_secret (bytes): The 32-byte shared secret from ML-KEM.
        mask_bound (int): The upper bound for the mask.
        
    Returns:
        int: The session mask.
    """
    # Use first 8 bytes (64 bits) as the mask integer, modulo the bound.
    mask_int = int.from_bytes(shared_secret[:8], byteorder='big')
    return mask_int % mask_bound
