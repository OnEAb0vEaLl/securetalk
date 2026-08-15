"""
URL patterns for accounts app - authentication routes.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Password reset
    path('forgot/', views.forgot_view, name='forgot'),
    path('reset/<str:token>/', views.reset_view, name='reset'),
    
    # Email verification (CODE-BASED)
    path('verify-pending/', views.verify_pending_view, name='verify_pending'),
    path('verify-code/', views.verify_code_view, name='verify_code'),
    path('resend-verification/', views.resend_verification_view, name='resend_verification'),
    
    # Account unlock
    path('unlock-request/', views.unlock_request_view, name='unlock_request'),
    path('unlock/<str:token>/', views.unlock_account_view, name='unlock_account'),
    
    # MFA
    path('mfa/suggest/', views.mfa_suggest_view, name='mfa_suggest'),
    path('mfa/skip/', views.mfa_skip_view, name='mfa_skip'),
    path('mfa/manage/', views.mfa_manage_view, name='mfa_manage'),
    path('mfa/setup/totp/', views.mfa_setup_totp_view, name='mfa_setup_totp'),
    path('mfa/setup/totp/confirm/', views.mfa_setup_totp_confirm_view, name='mfa_setup_totp_confirm'),
    path('mfa/setup/email/', views.mfa_setup_email_view, name='mfa_setup_email'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa/verify/submit/', views.mfa_verify_submit_view, name='mfa_verify_submit'),
    path('mfa/bypass/', views.mfa_bypass_view, name='mfa_bypass'),
    path('mfa/remove/', views.mfa_remove_view, name='mfa_remove'),
    
    # Password change
    path('password/change/', views.change_password_view, name='change_password'),
    
    # Username availability check (AJAX)
    path('check-username/', views.check_username_view, name='check_username'),
]