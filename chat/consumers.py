"""
WebSocket consumers for real-time chat.
"""

import json
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
import bleach

from .models import Room, Message
from accounts.models import User
from audit.utils import log_event


class ChatConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for chat rooms."""
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.room_slug = self.scope['url_route']['kwargs']['room_slug']
        self.room_group_name = f'room_{self.room_slug}'
        self.user = self.scope.get('user')
        
        # Reject if not authenticated
        if not self.user:
            await self.close()
            return
        
        # Verify room membership
        is_member = await self.check_membership()
        if not is_member:
            await self.close()
            return
        
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Update last seen
        await self.update_last_seen()
        
        # Send message history
        history = await self.get_message_history()
        await self.send(text_data=json.dumps({
            'type': 'history',
            'messages': history
        }))
        
        # Broadcast join message
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'system_message',
                'content': f'{self.user.get_display_name()} joined the room',
                'timestamp': datetime.utcnow().isoformat()
            }
        )
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'room_group_name'):
            # Broadcast leave message
            if self.user:
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'system_message',
                        'content': f'{self.user.get_display_name()} left the room',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                )
            
            # Leave room group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages."""
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            return
        
        msg_type = data.get('type')
        
        if msg_type == 'message':
            await self.handle_message(data)
        elif msg_type == 'typing':
            await self.handle_typing(data)
        elif msg_type == 'ping':
            await self.handle_ping()
    
    async def handle_message(self, data):
        """Handle chat message."""
        content = data.get('content', '').strip()
        
        if not content:
            return
        
        # Sanitize content - no HTML allowed
        content = bleach.clean(content, tags=[], strip=True)
        
        # Enforce max length
        if len(content) > 2000:
            content = content[:2000]
        
        # Save message
        message = await self.save_message(content)
        
        if message:
            # Broadcast to room
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message_id': str(message.id),
                    'author_id': str(self.user.id),
                    'author_name': self.user.get_display_name(),
                    'author_username': self.user.username,
                    'content': content,
                    'timestamp': message.created_at.isoformat()
                }
            )
    
    async def handle_typing(self, data):
        """Handle typing indicator."""
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'typing_indicator',
                'user_id': str(self.user.id),
                'username': self.user.get_display_name()
            }
        )
    
    async def handle_ping(self):
        """Handle keepalive ping."""
        await self.update_last_seen()
        await self.send(text_data=json.dumps({
            'type': 'pong',
            'timestamp': datetime.utcnow().isoformat()
        }))
    
    async def chat_message(self, event):
        """Forward chat message to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'message',
            'message_id': event['message_id'],
            'author_id': event['author_id'],
            'author_name': event['author_name'],
            'author_username': event['author_username'],
            'content': event['content'],
            'timestamp': event['timestamp']
        }))
    
    async def system_message(self, event):
        """Forward system message to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'system',
            'content': event['content'],
            'timestamp': event['timestamp']
        }))
    
    async def typing_indicator(self, event):
        """Forward typing indicator to WebSocket (exclude sender)."""
        if event['user_id'] != str(self.user.id):
            await self.send(text_data=json.dumps({
                'type': 'typing',
                'user_id': event['user_id'],
                'username': event['username']
            }))
    
    @database_sync_to_async
    def check_membership(self):
        """Check if user is a member of the room."""
        room = Room.objects(slug=self.room_slug, is_archived=False).first()
        if not room:
            return False
        self.room = room
        return self.user in room.members
    
    @database_sync_to_async
    def update_last_seen(self):
        """Update user's last seen timestamp."""
        self.user.last_seen = datetime.utcnow()
        self.user.save()
    
    @database_sync_to_async
    def save_message(self, content):
        """Save message to database."""
        try:
            room = Room.objects(slug=self.room_slug).first()
            if not room:
                return None
            
            message = Message(
                room=room,
                author=self.user,
                content=content,
                msg_type='text',
                created_at=datetime.utcnow()
            )
            message.save()
            
            # Log message sent
            log_event(
                action='MESSAGE_SENT',
                category='MESSAGE',
                actor=self.user,
                details={'room': room.name, 'message_length': len(content)},
                severity='INFO'
            )
            
            return message
        except Exception as e:
            print(f"Error saving message: {e}")
            return None
    
    @database_sync_to_async
    def get_message_history(self):
        """Get last 50 messages from room."""
        room = Room.objects(slug=self.room_slug).first()
        if not room:
            return []
        
        messages = Message.objects(
            room=room,
            is_deleted=False
        ).order_by('-created_at')[:50]
        
        # Reverse to get chronological order
        messages = list(reversed(messages))
        
        return [
            {
                'message_id': str(msg.id),
                'author_id': str(msg.author.id),
                'author_name': msg.author.get_display_name(),
                'author_username': msg.author.username,
                'content': msg.content if not msg.is_deleted else 'Message deleted',
                'msg_type': msg.msg_type,
                'timestamp': msg.created_at.isoformat()
            }
            for msg in messages
        ]