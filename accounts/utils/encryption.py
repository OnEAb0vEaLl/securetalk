"""
Encryption utilities for SecureTalk.
AES-256-CBC encryption for sensitive data like TOTP secrets.
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.conf import settings


def get_encryption_key():
    """Get the encryption key from settings."""
    key_hex = settings.TOTP_ENCRYPTION_KEY
    return bytes.fromhex(key_hex)


def encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext using AES-256-CBC.
    Returns: iv_hex:ciphertext_hex
    """
    key = get_encryption_key()
    iv = os.urandom(16)
    
    # Pad plaintext to 16-byte boundary (PKCS7)
    plaintext_bytes = plaintext.encode('utf-8')
    padding_length = 16 - (len(plaintext_bytes) % 16)
    padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Return as hex string: iv:ciphertext
    return f"{iv.hex()}:{ciphertext.hex()}"


def decrypt(token: str) -> str:
    """
    Decrypt token using AES-256-CBC.
    Token format: iv_hex:ciphertext_hex
    """
    key = get_encryption_key()
    
    # Parse token
    parts = token.split(':')
    if len(parts) != 2:
        raise ValueError("Invalid token format")
    
    iv = bytes.fromhex(parts[0])
    ciphertext = bytes.fromhex(parts[1])
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    
    return plaintext.decode('utf-8')


def hash_sha256(text: str) -> str:
    """Hash text using SHA-256."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()