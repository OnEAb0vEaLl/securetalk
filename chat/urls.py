"""
URL patterns for chat app.
"""

from django.urls import path
from . import views

urlpatterns = [
    path('', views.lobby_view, name='lobby'),
    path('create/', views.create_room_view, name='create_room'),
    path('room/<str:room_slug>/', views.room_view, name='room'),
    path('room/<str:room_slug>/join/', views.join_private_room_view, name='join_private_room'),
    path('room/<str:room_slug>/leave/', views.leave_room_view, name='leave_room'),
    path('room/<str:room_slug>/delete/', views.delete_room_view, name='delete_room'),
]