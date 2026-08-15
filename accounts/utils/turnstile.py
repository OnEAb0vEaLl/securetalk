"""
Cloudflare Turnstile verification utility.
"""

import requests
from django.conf import settings


def verify_turnstile(request) -> bool:
    """
    Verify Cloudflare Turnstile response.
    
    Args:
        request: Django HTTP request object
    
    Returns:
        bool: True if verification successful, False otherwise
    """
    token = request.POST.get('cf-turnstile-response', '')
    
    if not token:
        return False
    
    try:
        response = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': settings.TURNSTILE_SECRET_KEY,
                'response': token,
                'remoteip': get_client_ip(request)
            },
            timeout=10
        )
        
        result = response.json()
        return result.get('success', False)
    
    except requests.RequestException:
        # If Turnstile service is unavailable, fail open in debug mode
        return settings.DEBUG


def get_client_ip(request) -> str:
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip