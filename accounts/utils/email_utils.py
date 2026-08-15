"""
Email utilities for SecureTalk.
"""

from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def send_email_verification_code(to: str, code: str, expiry_minutes: int = 10):
    """Send email verification code."""
    subject = 'SecureTalk - Email Verification Code'
    message = f"""
Hello,

Welcome to SecureTalk! Your email verification code is:

    {code}

This code will expire in {expiry_minutes} minutes.

If you did not create an account, please ignore this email.

Best regards,
The SecureTalk Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            fail_silently=False
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send verification code email: {e}")
        return False


def send_password_reset(to: str, reset_link: str, expiry_minutes: int = 15):
    """Send password reset email."""
    subject = 'SecureTalk - Password Reset Request'
    message = f"""
Hello,

You requested a password reset for your SecureTalk account.

Click the link below to reset your password:
{reset_link}

This link will expire in {expiry_minutes} minutes.

If you did not request this reset, please ignore this email.

Best regards,
The SecureTalk Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            fail_silently=False
        )
    except Exception as e:
        logger.error(f"Failed to send password reset email: {e}")


def send_otp(to: str, code: str, expiry_minutes: int = 10):
    """Send OTP code via email for MFA login."""
    subject = 'SecureTalk - Your Login Code'
    message = f"""
Hello,

Your SecureTalk login verification code is:

    {code}

This code will expire in {expiry_minutes} minutes.

If you did not attempt to log in, please secure your account immediately.

Best regards,
The SecureTalk Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            fail_silently=False
        )
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")


def send_unlock_email(to: str, unlock_link: str, expiry_hours: int = 1):
    """Send account unlock email."""
    subject = 'SecureTalk - Unlock Your Account'
    message = f"""
Hello,

Your SecureTalk account has been locked due to multiple failed login attempts.

Click the link below to unlock your account:
{unlock_link}

This link will expire in {expiry_hours} hour(s).

If you did not attempt to log in, we recommend changing your password after unlocking.

Best regards,
The SecureTalk Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            fail_silently=False
        )
    except Exception as e:
        logger.error(f"Failed to send unlock email: {e}")


def send_mfa_bypass_otp(to: str, code: str):
    """Send MFA bypass OTP code."""
    subject = 'SecureTalk - MFA Bypass Code'
    message = f"""
Hello,

You requested to bypass MFA authentication. Your bypass code is:

    {code}

This code will expire in 10 minutes.

After using this code, we strongly recommend reconfiguring your MFA settings.

If you did not request this code, please secure your account immediately.

Best regards,
The SecureTalk Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            fail_silently=False
        )
    except Exception as e:
        logger.error(f"Failed to send MFA bypass email: {e}")


def send_admin_action_notice(to: str, action: str, details: dict):
    """Notify user of admin action on their account."""
    subject = f'SecureTalk - Account Notice: {action}'
    
    details_str = '\n'.join([f"- {k}: {v}" for k, v in details.items()])
    
    message = f"""
Hello,

An administrator has performed the following action on your SecureTalk account:

Action: {action}

Details:
{details_str}

If you have any questions, please contact support.

Best regards,
The SecureTalk Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            fail_silently=False
        )
    except Exception as e:
        logger.error(f"Failed to send admin action notice: {e}")