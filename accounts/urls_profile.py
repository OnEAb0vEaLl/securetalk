"""
URL patterns for profile-related routes.
"""

from django.urls import path
from . import views

urlpatterns = [
    path('edit/', views.profile_edit_view, name='profile_edit'),
    path('avatar/<str:user_id>/', views.avatar_view, name='avatar'),
    path('<str:username>/', views.profile_view, name='profile'),
]