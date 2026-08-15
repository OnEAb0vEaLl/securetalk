"""
Password hashing utilities for SecureTalk.
Uses bcrypt directly for better compatibility with newer Python versions.
"""

import bcrypt


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt with 12 rounds.
    
    Args:
        password: Plain text password
    
    Returns:
        Hashed password string
    """
    # Encode password to bytes, truncate to 72 bytes (bcrypt limit)
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a hash.
    
    Args:
        password: Plain text password to verify
        hashed: Hashed password to compare against
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        password_bytes = password.encode('utf-8')[:72]
        hashed_bytes = hashed.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def dummy_password_check():
    """
    Perform a dummy password check to prevent timing attacks.
    Used when a user is not found to maintain constant response time.
    """
    dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G8v9p8uE4J5XOi"
    verify_password("dummy_password_for_timing", dummy_hash)