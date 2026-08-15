"""
JWT token utilities for SecureTalk.
"""

import jwt
from datetime import datetime, timedelta
from django.conf import settings


def issue_jwt(user_id: str) -> str:
    """
    Issue a JWT token for authenticated user.
    
    Args:
        user_id: User's MongoDB ObjectId as string
    
    Returns:
        Signed JWT token string
    """
    payload = {
        'id': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRY_SECONDS),
        'type': 'access'
    }
    
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def issue_mfa_temp_jwt(user_id: str, mfa_methods: list) -> str:
    """
    Issue a temporary JWT token for MFA verification flow.
    
    Args:
        user_id: User's MongoDB ObjectId as string
        mfa_methods: List of MFA methods enabled for user
    
    Returns:
        Signed JWT token string
    """
    payload = {
        'id': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_MFA_EXPIRY_SECONDS),
        'type': 'mfa_temp',
        'mfa_methods': mfa_methods
    }
    
    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def decode_jwt(token: str) -> dict:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload dict
    
    Raises:
        jwt.ExpiredSignatureError: If token is expired
        jwt.InvalidTokenError: If token is invalid
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )


def set_jwt_cookie(response, token: str):
    """
    Set JWT token as httpOnly cookie on response.
    
    Args:
        response: Django HttpResponse object
        token: JWT token string
    """
    response.set_cookie(
        'token',
        token,
        httponly=settings.JWT_COOKIE_SETTINGS['httponly'],
        samesite=settings.JWT_COOKIE_SETTINGS['samesite'],
        secure=settings.JWT_COOKIE_SETTINGS['secure'],
        max_age=settings.JWT_COOKIE_SETTINGS['max_age']
    )


def set_mfa_temp_cookie(response, token: str):
    """
    Set MFA temp token as httpOnly cookie on response.
    
    Args:
        response: Django HttpResponse object
        token: JWT token string
    """
    response.set_cookie(
        'mfa_temp',
        token,
        httponly=True,
        samesite='Strict',
        secure=settings.JWT_COOKIE_SETTINGS['secure'],
        max_age=settings.JWT_MFA_EXPIRY_SECONDS
    )


def clear_auth_cookies(response):
    """
    Clear all authentication cookies.
    
    Args:
        response: Django HttpResponse object
    """
    response.delete_cookie('token')
    response.delete_cookie('mfa_temp')