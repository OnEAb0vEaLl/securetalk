"""
Audit logging utilities.
"""

from datetime import datetime
from .models import AuditLog


# Action constants
AUTH_ACTIONS = [
    'LOGIN_SUCCESS', 'LOGIN_FAIL', 'LOGOUT', 'REGISTER',
    'PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_SUCCESS',
    'EMAIL_VERIFY_SUCCESS', 'ACCOUNT_LOCKED',
    'ACCOUNT_UNLOCKED_EMAIL', 'ACCOUNT_UNLOCKED_ADMIN'
]

MFA_ACTIONS = [
    'MFA_TOTP_ENABLED', 'MFA_EMAIL_ENABLED', 'MFA_METHOD_REMOVED',
    'MFA_VERIFY_SUCCESS', 'MFA_VERIFY_FAIL', 'MFA_LOCKED', 'MFA_BYPASS_SUCCESS'
]

ACCOUNT_ACTIONS = [
    'PROFILE_UPDATE', 'AVATAR_UPLOAD', 'PASSWORD_CHANGE',
    'ACCOUNT_DELETED_SELF', 'EMAIL_CHANGED'
]

ROOM_ACTIONS = [
    'ROOM_CREATE', 'ROOM_JOIN', 'ROOM_LEAVE', 'ROOM_DELETE', 'ROOM_ARCHIVE',
    'ROOM_JOIN_PRIVATE', 'ROOM_PASSWORD_FAIL'
]

MESSAGE_ACTIONS = [
    'MESSAGE_SENT', 'MESSAGE_DELETED', 'MESSAGE_EDITED'
]

ADMIN_ACTIONS = [
    'ADMIN_LOCK_USER', 'ADMIN_UNLOCK_USER', 'ADMIN_DELETE_USER',
    'ADMIN_FORCE_RESET', 'ADMIN_ROLE_CHANGE', 'ADMIN_VIEW_LOGS',
    'ADMIN_VIEW_USERS', 'ADMIN_ARCHIVE_ROOM', 'ADMIN_RESTORE_ROOM'
]

SECURITY_ACTIONS = [
    'RATE_LIMIT_HIT', 'CSRF_FAIL', 'INVALID_TOKEN', 'SUSPICIOUS_ACTIVITY'
]


def get_client_ip(request):
    """Extract client IP from request."""
    if not request:
        return None
    
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip


def get_user_agent(request):
    """Extract user agent from request."""
    if not request:
        return None
    return request.META.get('HTTP_USER_AGENT', '')[:500]  # Limit length


def log_event(
    action: str,
    category: str,
    request=None,
    actor=None,
    target_user=None,
    details: dict = None,
    severity: str = 'INFO'
):
    """
    Create an audit log entry.
    
    Args:
        action: Action identifier (e.g., 'LOGIN_SUCCESS')
        category: Category (AUTH, MFA, ACCOUNT, ROOM, MESSAGE, ADMIN, SECURITY)
        request: Django HTTP request object (optional)
        actor: User performing the action (optional)
        target_user: User affected by the action (optional)
        details: Additional details as dict (optional)
        severity: Severity level (INFO, WARNING, CRITICAL)
    """
    try:
        log = AuditLog(
            timestamp=datetime.utcnow(),
            action=action,
            category=category,
            severity=severity,
            details=details or {}
        )
        
        # Set IP and user agent from request
        if request:
            log.ip_address = get_client_ip(request)
            log.user_agent = get_user_agent(request)
        
        # Set actor
        if actor:
            log.actor = actor
            log.actor_username = actor.username
        
        # Set target user
        if target_user:
            log.target_user = target_user
            log.target_username = target_user.username
        
        log.save()
        
    except Exception as e:
        # Never raise - just log to console
        print(f"Audit log error: {e}")