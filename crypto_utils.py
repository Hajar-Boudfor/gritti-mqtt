#crypto_utils.py

import os
import hmac
import hashlib

def generate_nonce():
    """Generate a random nonce of 32 bytes."""
    return os.urandom(32)

def derive_key(ss_e, ss_s):
    """
    Derives a single shared key from ss_e and ss_s.
    """
    combined = ss_e + ss_s
    return hashlib.sha256(combined).digest()

def compute_hmac(key, message):
    """
    Compute HMAC-SHA256.
    Used for handshake verification (Finished messages).
    """
    return hmac.new(key, message, hashlib.sha256).digest()
