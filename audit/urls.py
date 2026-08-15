"""
URL patterns for audit/admin app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Admin Users
    path('users/', views.admin_users_view, name='admin_users'),
    path('users/<str:user_id>/lock/', views.admin_lock_user_view, name='admin_lock_user'),
    path('users/<str:user_id>/unlock/', views.admin_unlock_user_view, name='admin_unlock_user'),
    path('users/<str:user_id>/delete/', views.admin_delete_user_view, name='admin_delete_user'),
    path('users/<str:user_id>/force-reset/', views.admin_force_reset_view, name='admin_force_reset'),
    path('users/<str:user_id>/role/', views.admin_change_role_view, name='admin_change_role'),
    
    # Admin Rooms
    path('rooms/', views.admin_rooms_view, name='admin_rooms'),
    path('rooms/<str:room_slug>/archive/', views.admin_archive_room_view, name='admin_archive_room'),
    path('rooms/<str:room_slug>/restore/', views.admin_restore_room_view, name='admin_restore_room'),
    
    # Admin Audit
    path('audit/', views.audit_log_view, name='admin_audit'),
    path('audit/export/', views.audit_export_view, name='admin_audit_export'),
    path('audit/<str:log_id>/', views.audit_detail_view, name='admin_audit_detail'),
]