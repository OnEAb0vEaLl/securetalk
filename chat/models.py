"""
Chat models for SecureTalk.
"""

from datetime import datetime
from mongoengine import (
    Document, StringField, BooleanField, IntField,
    DateTimeField, ListField, ReferenceField, ObjectIdField
)
from accounts.models import User


class Room(Document):
    """Chat room document."""
    
    name = StringField(
        unique=True,
        required=True,
        regex=r'^[a-zA-Z0-9 _-]{3,50}$'
    )
    slug = StringField(unique=True, required=True)
    description = StringField(max_length=300, default='')
    room_type = StringField(choices=['public', 'private'], default='public')
    password_hash = StringField(null=True)
    owner = ReferenceField(User, required=True)
    moderators = ListField(ReferenceField(User))
    members = ListField(ReferenceField(User))
    member_count = IntField(default=0)
    is_archived = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)
    banner_color = StringField(default='#6c5ce7')
    
    meta = {
        'collection': 'rooms',
        'indexes': ['slug', 'room_type', '-created_at', 'owner']
    }
    
    @property
    def is_private(self):
        """Check if room is private."""
        return self.room_type == 'private'
    
    def __str__(self):
        return self.name


class Message(Document):
    """Chat message document."""
    
    room = ReferenceField(Room, required=True)
    author = ReferenceField(User, required=True)
    content = StringField(required=True, max_length=2000)
    msg_type = StringField(choices=['text', 'system', 'image'], default='text')
    is_deleted = BooleanField(default=False)
    edited_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'messages',
        'indexes': [('room', '-created_at'), 'author']
    }
    
    def __str__(self):
        return f"{self.author.username}: {self.content[:50]}"


class RoomJoinRequest(Document):
    """Room join request for invite-only extension."""
    
    room = ReferenceField(Room, required=True)
    user = ReferenceField(User, required=True)
    status = StringField(
        choices=['pending', 'approved', 'rejected'],
        default='pending'
    )
    created_at = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'room_join_requests',
        'indexes': ['room', 'user', 'status']
    }