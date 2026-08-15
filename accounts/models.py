"""
User model and related documents for SecureTalk.
"""

from datetime import datetime, timedelta
from mongoengine import (
    Document, StringField, EmailField, BooleanField, IntField,
    DateTimeField, ListField, ObjectIdField, DictField
)
from django.conf import settings


class User(Document):
    """User document for authentication and profile."""
    
    username = StringField(
        unique=True, 
        required=True, 
        regex=r'^[a-zA-Z0-9_]{3,30}$'
    )
    email = EmailField(unique=True, required=True)
    display_name = StringField(max_length=50, default='')
    bio = StringField(max_length=300, default='')
    avatar_gridfs_id = ObjectIdField(null=True)
    password_hash = StringField(required=True)
    password_history = ListField(StringField(), max_length=5)
    role = StringField(choices=['user', 'moderator', 'admin'], default='user')
    
    # Account state
    is_locked = BooleanField(default=False)
    is_deleted = BooleanField(default=False)
    failed_logins = IntField(default=0)
    lock_until = DateTimeField(null=True)
    lockout_level = IntField(default=0)
    force_password_change = BooleanField(default=False)
    password_changed_at = DateTimeField(null=True)
    
    # Email verification
    email_verified = BooleanField(default=False)
    email_verify_token = StringField(null=True)
    email_verify_expiry = DateTimeField(null=True)
    
    # MFA - supports MULTIPLE simultaneous methods
    mfa_methods = ListField(StringField(choices=['totp', 'email']))
    totp_secret = StringField(null=True)
    email_otp_hash = StringField(null=True)
    email_otp_expiry = DateTimeField(null=True)
    mfa_failed_attempts = IntField(default=0)
    
    # Password reset
    reset_token = StringField(null=True)
    reset_token_expiry = DateTimeField(null=True)
    
    # Session metadata
    last_login_ip = StringField(null=True)
    last_login_time = DateTimeField(null=True)
    last_seen = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)
    
    # Preferences
    theme = StringField(choices=['light', 'dark'], default='dark')
    notification_sounds = BooleanField(default=True)
    show_online_status = BooleanField(default=True)
    
    meta = {
        'collection': 'users',
        'indexes': ['username', 'email', 'reset_token', 'email_verify_token']
    }
    
    @classmethod
    def mask_email(cls, email):
        """Show first 2 chars + *** + @domain."""
        if not email or '@' not in email:
            return '***@***.***'
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked_local = local[0] + '***' if local else '***'
        else:
            masked_local = local[:2] + '***'
        return f"{masked_local}@{domain}"
    
    def add_password_to_history(self, hash_str):
        """Keep max 5 passwords in history, drop oldest."""
        if hash_str not in self.password_history:
            self.password_history.append(hash_str)
            if len(self.password_history) > 5:
                self.password_history = self.password_history[-5:]
    
    @property
    def is_online(self):
        """Check if user was seen within the last 3 minutes."""
        if not self.last_seen:
            return False
        timeout = timedelta(seconds=settings.ONLINE_TIMEOUT_SECONDS)
        return (datetime.utcnow() - self.last_seen) < timeout
    
    def get_display_name(self):
        """Return display name or username."""
        return self.display_name if self.display_name else self.username
    
    def has_mfa_enabled(self):
        """Check if any MFA method is enabled."""
        return len(self.mfa_methods) > 0
    
    def __str__(self):
        return self.username