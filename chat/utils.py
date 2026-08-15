"""
Utility functions for chat app.
"""

from datetime import datetime, timedelta
from .models import Room, Message
from accounts.models import User


def get_room_stats(room):
    """Get statistics for a room."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    messages_today = Message.objects(
        room=room,
        created_at__gte=today
    ).count()
    
    total_messages = Message.objects(room=room).count()
    
    online_count = sum(1 for m in room.members if m.is_online)
    
    return {
        'messages_today': messages_today,
        'total_messages': total_messages,
        'online_count': online_count,
        'member_count': room.member_count
    }


def get_trending_rooms(limit=10):
    """Get trending rooms based on recent activity."""
    recent_cutoff = datetime.utcnow() - timedelta(hours=24)
    
    # Get rooms with recent messages
    rooms_with_activity = []
    
    for room in Room.objects(is_archived=False, room_type='public'):
        recent_messages = Message.objects(
            room=room,
            created_at__gte=recent_cutoff
        ).count()
        
        if recent_messages > 0:
            rooms_with_activity.append({
                'room': room,
                'recent_messages': recent_messages
            })
    
    # Sort by recent message count
    rooms_with_activity.sort(key=lambda x: x['recent_messages'], reverse=True)
    
    return [r['room'] for r in rooms_with_activity[:limit]]


def format_message_for_display(message):
    """Format a message for display."""
    if message.is_deleted:
        return {
            'id': str(message.id),
            'content': 'Message deleted',
            'is_deleted': True,
            'author': message.author.get_display_name(),
            'timestamp': message.created_at
        }
    
    return {
        'id': str(message.id),
        'content': message.content,
        'is_deleted': False,
        'author': message.author.get_display_name(),
        'author_id': str(message.author.id),
        'timestamp': message.created_at,
        'edited': message.edited_at is not None
    }