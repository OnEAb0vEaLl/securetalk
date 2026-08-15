"""
Audit log models for SecureTalk.
"""

from datetime import datetime
from mongoengine import (
    Document, StringField, DateTimeField, ReferenceField, DictField
)
from accounts.models import User


class AuditLog(Document):
    """Audit log entry document."""
    
    timestamp = DateTimeField(default=datetime.utcnow, required=True)
    actor = ReferenceField(User, null=True)
    actor_username = StringField(null=True)
    target_user = ReferenceField(User, null=True)
    target_username = StringField(null=True)
    action = StringField(required=True)
    category = StringField(
        choices=['AUTH', 'MFA', 'ACCOUNT', 'ROOM', 'MESSAGE', 'ADMIN', 'SECURITY'],
        required=True
    )
    ip_address = StringField(null=True)
    user_agent = StringField(null=True)
    details = DictField(default=dict)
    severity = StringField(
        choices=['INFO', 'WARNING', 'CRITICAL'],
        default='INFO'
    )
    
    meta = {
        'collection': 'audit_logs',
        'indexes': [
            '-timestamp',
            'actor',
            'action',
            'category',
            'severity',
            'ip_address'
        ],
        'ordering': ['-timestamp']
    }
    
    def __str__(self):
        return f"[{self.severity}] {self.action} by {self.actor_username} at {self.timestamp}"