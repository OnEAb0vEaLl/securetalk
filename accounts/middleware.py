"""
JWT Authentication Middleware for SecureTalk.
"""

from django.shortcuts import redirect
from django.http import JsonResponse
from django.conf import settings
from functools import wraps
import jwt
from datetime import datetime
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware

from .models import User
from .utils.tokens import issue_jwt, set_jwt_cookie


# Paths that don't require authentication (no token needed at all)
PUBLIC_PATHS = [
    '/auth/login/',
    '/auth/register/',
    '/auth/forgot/',
    '/auth/reset/',
    '/auth/unlock-request/',
    '/auth/unlock/',
    '/auth/check-username/',
    '/auth/mfa/verify/',
    '/auth/mfa/verify/submit/',
    '/auth/mfa/bypass/',
    '/static/',
    '/profile/avatar/',  # Allow avatar images without auth
    '/ws/',  # Allow WebSocket connections (handled by Channels)
]

# Paths allowed without email verification (user has JWT but email not verified)
UNVERIFIED_ALLOWED_PATHS = [
    '/auth/verify-pending/',
    '/auth/verify-code/',
    '/auth/resend-verification/',
    '/auth/logout/',
]

# Paths allowed during force password change
FORCE_RESET_ALLOWED_PATHS = [
    '/auth/reset/',
    '/auth/logout/',
    '/auth/password/change/',
]


class JWTAuthMiddleware:
    """Django middleware for JWT authentication."""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        path = request.path
        
        # Allow public paths (no authentication needed)
        if self._is_public_path(path):
            request.user = None
            return self.get_response(request)
        
        # Get token from cookie
        token = request.COOKIES.get('token')
        
        if not token:
            # Check if user has mfa_temp cookie and is trying to access non-MFA page
            mfa_temp = request.COOKIES.get('mfa_temp')
            if mfa_temp:
                # User is in MFA flow, redirect to MFA verify
                return redirect('mfa_verify')
            return redirect('login')
        
        try:
            # Decode JWT
            decoded = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            
            # Reject MFA temp tokens used as full tokens
            if decoded.get('type') == 'mfa_temp':
                response = redirect('mfa_verify')
                response.delete_cookie('token')
                return response
            
            # Load user
            user = User.objects.get(id=decoded['id'])
            
            # Check if user is locked
            if user.is_locked:
                response = redirect('login')
                response.delete_cookie('token')
                response.delete_cookie('mfa_temp')
                return self._add_error_param(response, 'locked')
            
            # Check if user is deleted
            if user.is_deleted:
                response = redirect('login')
                response.delete_cookie('token')
                response.delete_cookie('mfa_temp')
                return self._add_error_param(response, 'deleted')
            
            # Check force password change
            if user.force_password_change and not self._is_force_reset_allowed(path):
                return redirect('change_password')
            
            # *** ENFORCE EMAIL VERIFICATION ***
            if not user.email_verified and not self._is_unverified_allowed(path):
                return redirect('verify_pending')
            
            # Set user on request
            request.user = user
            
            # Update last seen
            user.last_seen = datetime.utcnow()
            user.save()
            
            # Process request
            response = self.get_response(request)
            
            # Sliding refresh - reissue JWT
            if hasattr(request, 'user') and request.user:
                new_token = issue_jwt(str(request.user.id))
                set_jwt_cookie(response, new_token)
            
            return response
            
        except jwt.ExpiredSignatureError:
            response = redirect('login')
            response.delete_cookie('token')
            response.delete_cookie('mfa_temp')
            return response
        except (jwt.InvalidTokenError, User.DoesNotExist):
            response = redirect('login')
            response.delete_cookie('token')
            response.delete_cookie('mfa_temp')
            return response
    
    def _is_public_path(self, path):
        """
        Check if path is public.
        Handles WebSocket paths, static files, and avatar images.
        """
        # 1. WebSocket paths (handled by Channels, not this middleware)
        if path.startswith('/ws/'):
            return True
        
        # 2. Static file extensions (bypass for all static assets)
        static_extensions = ['.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', 
                           '.css', '.js', '.ico', '.woff', '.woff2', '.ttf', '.eot']
        if any(path.endswith(ext) for ext in static_extensions):
            return True
        
        # 3. Check configured public paths
        for public_path in PUBLIC_PATHS:
            if path.startswith(public_path):
                return True
        
        return False
    
    def _is_unverified_allowed(self, path):
        """Check if path is allowed without email verification."""
        for allowed_path in UNVERIFIED_ALLOWED_PATHS:
            if path.startswith(allowed_path):
                return True
        return False
    
    def _is_force_reset_allowed(self, path):
        """Check if path is allowed during force password change."""
        for allowed_path in FORCE_RESET_ALLOWED_PATHS:
            if path.startswith(allowed_path):
                return True
        return False
    
    def _add_error_param(self, response, error):
        """Add error parameter to redirect URL."""
        if hasattr(response, 'url'):
            separator = '&' if '?' in response.url else '?'
            response['Location'] = f"{response.url}{separator}error={error}"
        return response


class JWTAuthMiddlewareStack(BaseMiddleware):
    """Channels middleware for WebSocket JWT authentication."""
    
    async def __call__(self, scope, receive, send):
        # Get cookies from scope
        cookies = {}
        headers = dict(scope.get('headers', []))
        cookie_header = headers.get(b'cookie', b'').decode()
        
        if cookie_header:
            for item in cookie_header.split(';'):
                if '=' in item:
                    key, value = item.strip().split('=', 1)
                    cookies[key] = value
        
        token = cookies.get('token')
        
        if token:
            try:
                decoded = jwt.decode(
                    token,
                    settings.JWT_SECRET_KEY,
                    algorithms=[settings.JWT_ALGORITHM]
                )
                
                # Only accept full access tokens for WebSocket
                if decoded.get('type') == 'mfa_temp':
                    scope['user'] = None
                else:
                    user = await self._get_user(decoded['id'])
                    # Also check email verification for WebSocket
                    if user and not user.is_locked and not user.is_deleted and user.email_verified:
                        scope['user'] = user
                    else:
                        scope['user'] = None
            except (jwt.InvalidTokenError, Exception):
                scope['user'] = None
        else:
            scope['user'] = None
        
        return await super().__call__(scope, receive, send)
    
    @database_sync_to_async
    def _get_user(self, user_id):
        """Get user from database."""
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None


def login_required(view_func):
    """Decorator to require authentication."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'user') or request.user is None:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper


def email_verified_required(view_func):
    """Decorator to require verified email."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'user') or request.user is None:
            return redirect('login')
        if not request.user.email_verified:
            return redirect('verify_pending')
        return view_func(request, *args, **kwargs)
    return wrapper


def admin_required(view_func):
    """Decorator to require admin role."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'user') or request.user is None:
            return redirect('login')
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Admin access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def moderator_required(view_func):
    """Decorator to require moderator or admin role."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'user') or request.user is None:
            return redirect('login')
        if request.user.role not in ['admin', 'moderator']:
            return JsonResponse({'error': 'Moderator access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper