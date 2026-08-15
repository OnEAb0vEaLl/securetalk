"""
WebSocket URL routing for SecureTalk.
"""

from django.urls import re_path
from chat.consumers import ChatConsumer

websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<room_slug>[\w-]+)/$', ChatConsumer.as_asgi()),
]