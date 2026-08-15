"""
Views for accounts app - authentication, MFA, and profile management.
"""

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_protect
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from datetime import datetime, timedelta
import secrets
import pyotp
import qrcode
import qrcode.image.pil
from io import BytesIO
import base64
from bson import ObjectId
import pymongo
from gridfs import GridFS

from .models import User
from .forms import (
    RegisterForm, LoginForm, ForgotPasswordForm, ResetPasswordForm,
    ChangePasswordForm, ProfileEditForm, MFAVerifyForm, EmailVerifyForm
)
from .utils.password_strength import score_password
from .utils.turnstile import verify_turnstile
from .utils.email_utils import (
    send_password_reset, send_email_verification_code, send_otp,
    send_unlock_email, send_mfa_bypass_otp
)
from .utils.tokens import (
    issue_jwt, issue_mfa_temp_jwt, decode_jwt, set_jwt_cookie,
    set_mfa_temp_cookie, clear_auth_cookies
)
from .utils.encryption import encrypt, decrypt, hash_sha256
from .utils.password_hashing import hash_password, verify_password, dummy_password_check
from .middleware import login_required, email_verified_required, admin_required
from audit.utils import log_event


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _generate_verification_code():
    """Generate a 6-digit verification code."""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])


def _send_verification_code(user, request=None):
    """Generate and send a new verification code to user."""
    code = _generate_verification_code()
    user.email_verify_token = hash_sha256(code)
    user.email_verify_expiry = datetime.utcnow() + timedelta(minutes=10)
    user.save()
    
    send_email_verification_code(user.email, code)
    
    if request:
        log_event(
            action='VERIFICATION_CODE_SENT',
            category='AUTH',
            request=request,
            target_user=user,
            severity='INFO'
        )
    
    return True


# ============================================================
# AUTHENTICATION VIEWS
# ============================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='20/h', method='POST', block=True)
def register_view(request):
    """User registration view."""
    if request.method == 'GET':
        form = RegisterForm()
        return render(request, 'auth/register.html', {
            'form': form,
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    form = RegisterForm(request.POST)

    # Verify Turnstile
    if not verify_turnstile(request):
        return render(request, 'auth/register.html', {
            'form': form,
            'error': 'Please complete the security check.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    if not form.is_valid():
        return render(request, 'auth/register.html', {
            'form': form,
            'error': form.errors.as_text(),
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    username = form.cleaned_data['username']
    email = form.cleaned_data['email'].lower()
    display_name = form.cleaned_data.get('display_name', '')
    password = form.cleaned_data['password']

    # Check username uniqueness
    if User.objects(username__iexact=username).first():
        return render(request, 'auth/register.html', {
            'form': form,
            'error': 'Username is already taken.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    # Check email uniqueness
    if User.objects(email__iexact=email).first():
        return render(request, 'auth/register.html', {
            'form': form,
            'error': 'Email is already registered.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    # Check password strength
    strength = score_password(password)
    if strength['score'] < 40:
        return render(request, 'auth/register.html', {
            'form': form,
            'error': f"Password is too weak: {strength['feedback']}",
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    # Hash password
    password_hash = hash_password(password)

    # Create user (email NOT verified yet)
    user = User(
        username=username,
        email=email,
        display_name=display_name if display_name else username,
        password_hash=password_hash,
        email_verified=False,
        created_at=datetime.utcnow()
    )
    user.add_password_to_history(password_hash)
    user.save()

    # Send verification CODE (not link)
    _send_verification_code(user, request)

    # Log registration
    log_event(
        action='REGISTER',
        category='AUTH',
        request=request,
        actor=user,
        details={'username': username, 'email': User.mask_email(email)},
        severity='INFO'
    )

    # Issue JWT and redirect to verification page
    token = issue_jwt(str(user.id))
    response = redirect('verify_pending')
    set_jwt_cookie(response, token)

    return response


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='50/15m', method='POST', block=True)
def login_view(request):
    """User login view with progressive lockout."""
    error_param = request.GET.get('error')
    error_messages = {
        'locked': 'Your account has been locked. Please check your email for unlock instructions.',
        'deleted': 'This account has been deleted.',
    }

    if request.method == 'GET':
        form = LoginForm()
        return render(request, 'auth/login.html', {
            'form': form,
            'error': error_messages.get(error_param),
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    form = LoginForm(request.POST)

    # Verify Turnstile
    if not verify_turnstile(request):
        return render(request, 'auth/login.html', {
            'form': form,
            'error': 'Please complete the security check.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    if not form.is_valid():
        return render(request, 'auth/login.html', {
            'form': form,
            'error': 'Please fill in all fields.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    username = form.cleaned_data['username']
    password = form.cleaned_data['password']

    # Find user
    user = User.objects(username__iexact=username).first()

    if not user:
        dummy_password_check()
        log_event(
            action='LOGIN_FAIL',
            category='AUTH',
            request=request,
            details={'username': username, 'reason': 'user_not_found'},
            severity='WARNING'
        )
        return render(request, 'auth/login.html', {
            'form': form,
            'error': 'Invalid username or password.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    # Check permanent lock
    if user.is_locked or user.lockout_level >= 5:
        if not user.reset_token or (user.reset_token_expiry and user.reset_token_expiry < datetime.utcnow()):
            unlock_token = secrets.token_hex(32)
            user.reset_token = hash_sha256(unlock_token)
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            user.save()
            
            unlock_link = f"{request.scheme}://{request.get_host()}/auth/unlock/{unlock_token}/"
            send_unlock_email(user.email, unlock_link)
        
        return redirect(f"/auth/unlock-request/?email={User.mask_email(user.email)}")

    # Check temporary lock
    if user.lock_until and user.lock_until > datetime.utcnow():
        remaining = (user.lock_until - datetime.utcnow()).total_seconds()
        return render(request, 'auth/login.html', {
            'form': form,
            'error': 'Account temporarily locked.',
            'lock_until': user.lock_until.isoformat(),
            'lock_seconds': int(remaining),
            'lockout_level': user.lockout_level,
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    # Verify password
    if not verify_password(password, user.password_hash):
        user.failed_logins += 1
        
        # Apply progressive lockout
        if user.failed_logins >= 25:
            user.lockout_level = 5
            user.is_locked = True
            
            unlock_token = secrets.token_hex(32)
            user.reset_token = hash_sha256(unlock_token)
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            user.save()
            
            unlock_link = f"{request.scheme}://{request.get_host()}/auth/unlock/{unlock_token}/"
            send_unlock_email(user.email, unlock_link)
            
            log_event(
                action='ACCOUNT_LOCKED',
                category='AUTH',
                request=request,
                target_user=user,
                details={'level': 5, 'permanent': True},
                severity='CRITICAL'
            )
            
            return redirect(f"/auth/unlock-request/?email={User.mask_email(user.email)}")
        
        elif user.failed_logins >= 20:
            user.lockout_level = 4
            user.lock_until = datetime.utcnow() + timedelta(minutes=15)
        elif user.failed_logins >= 15:
            user.lockout_level = 3
            user.lock_until = datetime.utcnow() + timedelta(minutes=5)
        elif user.failed_logins >= 10:
            user.lockout_level = 2
            user.lock_until = datetime.utcnow() + timedelta(minutes=2)
        elif user.failed_logins >= 5:
            user.lockout_level = 1
            user.lock_until = datetime.utcnow() + timedelta(seconds=30)
        
        user.save()
        
        log_event(
            action='LOGIN_FAIL',
            category='AUTH',
            request=request,
            target_user=user,
            details={
                'failed_logins': user.failed_logins,
                'lockout_level': user.lockout_level
            },
            severity='WARNING'
        )
        
        if user.lock_until and user.lock_until > datetime.utcnow():
            remaining = (user.lock_until - datetime.utcnow()).total_seconds()
            return render(request, 'auth/login.html', {
                'form': form,
                'error': 'Too many failed attempts. Account temporarily locked.',
                'lock_until': user.lock_until.isoformat(),
                'lock_seconds': int(remaining),
                'lockout_level': user.lockout_level,
                'turnstile_site_key': settings.TURNSTILE_SITE_KEY
            })
        
        return render(request, 'auth/login.html', {
            'form': form,
            'error': 'Invalid username or password.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    # Password correct - check email verification FIRST
    if not user.email_verified:
        # Send a new verification code if expired or not exists
        if not user.email_verify_expiry or user.email_verify_expiry < datetime.utcnow():
            _send_verification_code(user, request)
        
        # Issue JWT so they can access verify_pending page
        token = issue_jwt(str(user.id))
        response = redirect('verify_pending')
        set_jwt_cookie(response, token)
        
        log_event(
            action='LOGIN_BLOCKED_UNVERIFIED',
            category='AUTH',
            request=request,
            target_user=user,
            severity='INFO'
        )
        
        return response

    # Reset lockout
    user.failed_logins = 0
    user.lockout_level = 0
    user.lock_until = None
    user.is_locked = False
    user.last_login_ip = request.META.get('REMOTE_ADDR', '')
    user.last_login_time = datetime.utcnow()
    user.last_seen = datetime.utcnow()
    user.save()

    log_event(
        action='LOGIN_SUCCESS',
        category='AUTH',
        request=request,
        actor=user,
        severity='INFO'
    )

    # Check if MFA is required
    if user.has_mfa_enabled():
        mfa_token = issue_mfa_temp_jwt(str(user.id), user.mfa_methods)
        response = redirect('mfa_verify')
        set_mfa_temp_cookie(response, mfa_token)
        return response

    # No MFA - issue full JWT and go to lobby
    token = issue_jwt(str(user.id))
    response = redirect('lobby')
    set_jwt_cookie(response, token)

    return response


@require_http_methods(["GET", "POST"])
def logout_view(request):
    """User logout view."""
    if hasattr(request, 'user') and request.user:
        log_event(
            action='LOGOUT',
            category='AUTH',
            request=request,
            actor=request.user,
            severity='INFO'
        )

    response = redirect('login')
    clear_auth_cookies(response)
    return response


# ============================================================
# EMAIL VERIFICATION (CODE-BASED)
# ============================================================

@login_required
@require_GET
def verify_pending_view(request):
    """View shown when email is not yet verified."""
    user = request.user
    
    # If already verified, redirect appropriately
    if user.email_verified:
        if not user.has_mfa_enabled():
            return redirect('mfa_suggest')
        return redirect('lobby')
    
    # Check if code exists and is still valid
    code_sent = False
    remaining_seconds = 0
    
    if user.email_verify_expiry and user.email_verify_expiry > datetime.utcnow():
        code_sent = True
        remaining_seconds = int((user.email_verify_expiry - datetime.utcnow()).total_seconds())
    
    return render(request, 'auth/verify_pending.html', {
        'email': User.mask_email(user.email),
        'code_sent': code_sent,
        'remaining_seconds': remaining_seconds,
        'form': EmailVerifyForm()
    })


@login_required
@csrf_protect
@require_POST
@ratelimit(key='user', rate='5/h', method='POST', block=True)
def resend_verification_view(request):
    """Resend email verification code."""
    user = request.user

    if user.email_verified:
        return redirect('lobby')

    # Send new code
    _send_verification_code(user, request)

    return render(request, 'auth/verify_pending.html', {
        'email': User.mask_email(user.email),
        'success': 'A new verification code has been sent to your email.',
        'code_sent': True,
        'remaining_seconds': 600,  # 10 minutes
        'form': EmailVerifyForm()
    })


@login_required
@csrf_protect
@require_POST
@ratelimit(key='user', rate='10/h', method='POST', block=True)
def verify_code_view(request):
    """Verify the email verification code."""
    user = request.user
    
    if user.email_verified:
        return redirect('lobby')
    
    form = EmailVerifyForm(request.POST)
    
    if not form.is_valid():
        remaining_seconds = 0
        if user.email_verify_expiry and user.email_verify_expiry > datetime.utcnow():
            remaining_seconds = int((user.email_verify_expiry - datetime.utcnow()).total_seconds())
        
        return render(request, 'auth/verify_pending.html', {
            'email': User.mask_email(user.email),
            'error': 'Please enter a valid 6-digit code.',
            'code_sent': True,
            'remaining_seconds': remaining_seconds,
            'form': form
        })
    
    code = form.cleaned_data['code']
    
    # Check if code exists
    if not user.email_verify_token or not user.email_verify_expiry:
        return render(request, 'auth/verify_pending.html', {
            'email': User.mask_email(user.email),
            'error': 'No verification code found. Please request a new one.',
            'code_sent': False,
            'form': EmailVerifyForm()
        })
    
    # Check if code is expired
    if user.email_verify_expiry < datetime.utcnow():
        return render(request, 'auth/verify_pending.html', {
            'email': User.mask_email(user.email),
            'error': 'Verification code has expired. Please request a new one.',
            'code_sent': False,
            'form': EmailVerifyForm()
        })
    
    # Verify the code
    if hash_sha256(code) != user.email_verify_token:
        log_event(
            action='EMAIL_VERIFY_FAIL',
            category='AUTH',
            request=request,
            target_user=user,
            details={'reason': 'invalid_code'},
            severity='WARNING'
        )
        
        remaining = int((user.email_verify_expiry - datetime.utcnow()).total_seconds())
        return render(request, 'auth/verify_pending.html', {
            'email': User.mask_email(user.email),
            'error': 'Invalid verification code. Please try again.',
            'code_sent': True,
            'remaining_seconds': remaining,
            'form': EmailVerifyForm()
        })
    
    # Success - verify email
    user.email_verified = True
    user.email_verify_token = None
    user.email_verify_expiry = None
    user.save()
    
    log_event(
        action='EMAIL_VERIFY_SUCCESS',
        category='AUTH',
        request=request,
        actor=user,
        severity='INFO'
    )
    
    # Redirect to MFA suggestion
    return redirect('mfa_suggest')


# ============================================================
# MFA SUGGESTION (shown after email verification)
# ============================================================

@login_required
@email_verified_required
@require_GET
def mfa_suggest_view(request):
    """MFA setup suggestion view - shown after email verification."""
    return render(request, 'mfa/suggest.html')


@login_required
@email_verified_required
@csrf_protect
@require_POST
def mfa_skip_view(request):
    """Skip MFA setup."""
    return redirect('lobby')


# ============================================================
# MFA MANAGEMENT (requires verified email)
# ============================================================

@login_required
@email_verified_required
@require_GET
def mfa_manage_view(request):
    """MFA management view."""
    user = request.user
    return render(request, 'mfa/manage.html', {
        'user': user,
        'totp_enabled': 'totp' in user.mfa_methods,
        'email_enabled': 'email' in user.mfa_methods
    })


@login_required
@email_verified_required
@require_GET
def mfa_setup_totp_view(request):
    """TOTP setup view - generate QR code."""
    user = request.user

    secret = pyotp.random_base32()

    encrypted_secret = encrypt(secret)
    user.totp_secret = encrypted_secret
    user.save()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name='SecureTalk')

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color='black', back_color='white')
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'mfa/setup_totp.html', {
        'qr_code': f'data:image/png;base64,{qr_base64}',
        'secret': secret
    })


@login_required
@email_verified_required
@csrf_protect
@require_POST
def mfa_setup_totp_confirm_view(request):
    """Confirm TOTP setup with test code."""
    user = request.user
    code = request.POST.get('code', '').strip()

    if not user.totp_secret:
        return redirect('mfa_setup_totp')

    try:
        secret = decrypt(user.totp_secret)
    except Exception:
        return render(request, 'mfa/setup_totp.html', {
            'error': 'Error setting up TOTP. Please try again.'
        })

    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        uri = totp.provisioning_uri(name=user.email, issuer_name='SecureTalk')
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return render(request, 'mfa/setup_totp.html', {
            'qr_code': f'data:image/png;base64,{qr_base64}',
            'secret': secret,
            'error': 'Invalid code. Please try again.'
        })

    if 'totp' not in user.mfa_methods:
        user.mfa_methods.append('totp')
    user.save()

    log_event(
        action='MFA_TOTP_ENABLED',
        category='MFA',
        request=request,
        actor=user,
        severity='INFO'
    )

    return redirect('mfa_manage')


@login_required
@email_verified_required
@csrf_protect
@require_POST
def mfa_setup_email_view(request):
    """Enable email MFA."""
    user = request.user

    if 'email' not in user.mfa_methods:
        user.mfa_methods.append('email')
        user.save()
        
        log_event(
            action='MFA_EMAIL_ENABLED',
            category='MFA',
            request=request,
            actor=user,
            severity='INFO'
        )

    return redirect('mfa_manage')


@login_required
@email_verified_required
@csrf_protect
@require_POST
def mfa_remove_view(request):
    """Remove an MFA method."""
    user = request.user
    method = request.POST.get('method')

    if method not in ['totp', 'email']:
        return redirect('mfa_manage')

    if method in user.mfa_methods:
        user.mfa_methods.remove(method)
        
        if method == 'totp':
            user.totp_secret = None
        
        user.save()
        
        log_event(
            action='MFA_METHOD_REMOVED',
            category='MFA',
            request=request,
            actor=user,
            details={'method': method},
            severity='INFO'
        )

    return redirect('mfa_manage')


# ============================================================
# MFA VERIFICATION (login flow - uses mfa_temp cookie)
# ============================================================

@require_http_methods(["GET", "POST"])
def mfa_verify_view(request):
    """MFA verification view."""
    mfa_token = request.COOKIES.get('mfa_temp')
    if not mfa_token:
        return redirect('login')

    try:
        decoded = decode_jwt(mfa_token)
        user = User.objects.get(id=decoded['id'])
    except Exception:
        response = redirect('login')
        response.delete_cookie('mfa_temp')
        return response

    mfa_methods = decoded.get('mfa_methods', [])
    selected_method = request.GET.get('method') or request.POST.get('method')

    if len(mfa_methods) > 1 and not selected_method:
        return render(request, 'mfa/verify.html', {
            'show_selection': True,
            'methods': mfa_methods
        })

    method = selected_method or mfa_methods[0] if mfa_methods else None

    if not method:
        return redirect('login')

    if request.method == 'GET' or request.POST.get('send_code'):
        if method == 'email':
            otp = _generate_verification_code()
            user.email_otp_hash = hash_sha256(otp)
            user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
            user.save()
            
            send_otp(user.email, otp)
        
        form = MFAVerifyForm()
        return render(request, 'mfa/verify.html', {
            'form': form,
            'method': method,
            'email': User.mask_email(user.email) if method == 'email' else None
        })

    return redirect('mfa_verify')


@csrf_protect
@require_POST
@ratelimit(key='ip', rate='10/15m', method='POST', block=True)
def mfa_verify_submit_view(request):
    """Submit MFA verification code."""
    mfa_token = request.COOKIES.get('mfa_temp')
    if not mfa_token:
        return redirect('login')

    try:
        decoded = decode_jwt(mfa_token)
        user = User.objects.get(id=decoded['id'])
    except Exception:
        response = redirect('login')
        response.delete_cookie('mfa_temp')
        return response

    method = request.POST.get('method')
    
    form = MFAVerifyForm(request.POST)

    if not form.is_valid():
        return render(request, 'mfa/verify.html', {
            'form': form,
            'method': method,
            'error': 'Please enter a valid 6-digit code.',
            'email': User.mask_email(user.email) if method == 'email' else None
        })

    code = form.cleaned_data['code']
    verified = False

    if method == 'totp' and user.totp_secret:
        try:
            secret = decrypt(user.totp_secret)
            totp = pyotp.TOTP(secret)
            verified = totp.verify(code)
        except Exception:
            pass

    elif method == 'email':
        if user.email_otp_hash and user.email_otp_expiry:
            if user.email_otp_expiry > datetime.utcnow():
                verified = hash_sha256(code) == user.email_otp_hash

    if not verified:
        user.mfa_failed_attempts += 1
        
        if user.mfa_failed_attempts >= 3:
            user.is_locked = True
            user.save()
            
            log_event(
                action='MFA_LOCKED',
                category='MFA',
                request=request,
                target_user=user,
                severity='CRITICAL'
            )
            
            response = redirect('login')
            response.delete_cookie('mfa_temp')
            return response
        
        user.save()
        
        log_event(
            action='MFA_VERIFY_FAIL',
            category='MFA',
            request=request,
            target_user=user,
            details={'method': method, 'attempts': user.mfa_failed_attempts},
            severity='WARNING'
        )
        
        return render(request, 'mfa/verify.html', {
            'form': MFAVerifyForm(),
            'method': method,
            'error': f'Invalid code. {3 - user.mfa_failed_attempts} attempts remaining.',
            'email': User.mask_email(user.email) if method == 'email' else None
        })

    user.mfa_failed_attempts = 0
    user.email_otp_hash = None
    user.email_otp_expiry = None
    user.last_login_time = datetime.utcnow()
    user.last_seen = datetime.utcnow()
    user.save()

    log_event(
        action='MFA_VERIFY_SUCCESS',
        category='MFA',
        request=request,
        actor=user,
        details={'method': method},
        severity='INFO'
    )

    token = issue_jwt(str(user.id))
    response = redirect('lobby')
    set_jwt_cookie(response, token)
    response.delete_cookie('mfa_temp')

    return response


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='5/h', method='POST', block=True)
def mfa_bypass_view(request):
    """MFA bypass for locked out users."""
    mfa_token = request.COOKIES.get('mfa_temp')
    if not mfa_token:
        return redirect('login')

    try:
        decoded = decode_jwt(mfa_token)
        user = User.objects.get(id=decoded['id'])
    except Exception:
        response = redirect('login')
        response.delete_cookie('mfa_temp')
        return response

    if request.method == 'GET':
        otp = _generate_verification_code()
        user.email_otp_hash = hash_sha256(otp)
        user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
        user.save()
        
        send_mfa_bypass_otp(user.email, otp)
        
        return render(request, 'mfa/bypass.html', {
            'email': User.mask_email(user.email)
        })

    code = request.POST.get('code', '').strip()

    if not code or len(code) != 6:
        return render(request, 'mfa/bypass.html', {
            'email': User.mask_email(user.email),
            'error': 'Please enter a valid 6-digit code.'
        })

    if not user.email_otp_hash or not user.email_otp_expiry:
        return render(request, 'mfa/bypass.html', {
            'email': User.mask_email(user.email),
            'error': 'No bypass code found. Please request a new one.'
        })

    if user.email_otp_expiry < datetime.utcnow():
        return render(request, 'mfa/bypass.html', {
            'email': User.mask_email(user.email),
            'error': 'Bypass code has expired. Please request a new one.'
        })

    if hash_sha256(code) != user.email_otp_hash:
        return render(request, 'mfa/bypass.html', {
            'email': User.mask_email(user.email),
            'error': 'Invalid bypass code.'
        })

    user.email_otp_hash = None
    user.email_otp_expiry = None
    user.mfa_failed_attempts = 0
    user.save()

    log_event(
        action='MFA_BYPASS_SUCCESS',
        category='MFA',
        request=request,
        actor=user,
        severity='WARNING'
    )

    token = issue_jwt(str(user.id))
    response = redirect('mfa_manage')
    set_jwt_cookie(response, token)
    response.delete_cookie('mfa_temp')

    return response


# ============================================================
# PASSWORD MANAGEMENT
# ============================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='10/h', method='POST', block=True)
def forgot_view(request):
    """Forgot password view."""
    if request.method == 'GET':
        form = ForgotPasswordForm()
        return render(request, 'auth/forgot.html', {
            'form': form,
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    form = ForgotPasswordForm(request.POST)

    if not verify_turnstile(request):
        return render(request, 'auth/forgot.html', {
            'form': form,
            'error': 'Please complete the security check.',
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    success_message = 'If an account exists with that email, you will receive password reset instructions.'

    if not form.is_valid():
        return render(request, 'auth/forgot.html', {
            'form': form,
            'success': success_message,
            'turnstile_site_key': settings.TURNSTILE_SITE_KEY
        })

    email = form.cleaned_data['email'].lower()
    user = User.objects(email__iexact=email).first()

    if user and not user.is_deleted:
        reset_token = secrets.token_hex(32)
        user.reset_token = hash_sha256(reset_token)
        user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=15)
        user.save()
        
        reset_link = f"{request.scheme}://{request.get_host()}/auth/reset/{reset_token}/"
        send_password_reset(email, reset_link)
        
        log_event(
            action='PASSWORD_RESET_REQUEST',
            category='AUTH',
            request=request,
            target_user=user,
            severity='INFO'
        )

    return render(request, 'auth/forgot.html', {
        'form': ForgotPasswordForm(),
        'success': success_message,
        'turnstile_site_key': settings.TURNSTILE_SITE_KEY
    })


@csrf_protect
@require_http_methods(["GET", "POST"])
def reset_view(request, token):
    """Password reset view."""
    token_hash = hash_sha256(token)
    user = User.objects(
        reset_token=token_hash,
        reset_token_expiry__gt=datetime.utcnow()
    ).first()

    if not user:
        return render(request, 'auth/reset.html', {
            'error': 'Invalid or expired reset link. Please request a new one.',
            'invalid_token': True
        })

    if request.method == 'GET':
        form = ResetPasswordForm()
        return render(request, 'auth/reset.html', {
            'form': form,
            'token': token
        })

    form = ResetPasswordForm(request.POST)

    if not form.is_valid():
        return render(request, 'auth/reset.html', {
            'form': form,
            'error': form.errors.as_text(),
            'token': token
        })

    password = form.cleaned_data['password']

    strength = score_password(password)
    if strength['score'] < 40:
        return render(request, 'auth/reset.html', {
            'form': form,
            'error': f"Password is too weak: {strength['feedback']}",
            'token': token
        })

    new_hash = hash_password(password)
    for old_hash in user.password_history:
        if verify_password(password, old_hash):
            return render(request, 'auth/reset.html', {
                'form': form,
                'error': 'Cannot reuse a recent password. Please choose a different password.',
                'token': token
            })

    user.password_hash = new_hash
    user.add_password_to_history(new_hash)
    user.reset_token = None
    user.reset_token_expiry = None
    user.force_password_change = False
    user.password_changed_at = datetime.utcnow()

    user.failed_logins = 0
    user.lockout_level = 0
    user.lock_until = None
    user.is_locked = False

    user.save()

    log_event(
        action='PASSWORD_RESET_SUCCESS',
        category='AUTH',
        request=request,
        target_user=user,
        severity='INFO'
    )

    return render(request, 'auth/reset.html', {
        'success': 'Your password has been reset successfully. You can now log in.',
        'redirect_login': True
    })


@login_required
@email_verified_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def change_password_view(request):
    """Change password view."""
    user = request.user

    if request.method == 'GET':
        form = ChangePasswordForm()
        return render(request, 'auth/change_password.html', {
            'form': form,
            'force_change': user.force_password_change
        })

    form = ChangePasswordForm(request.POST)

    if not form.is_valid():
        return render(request, 'auth/change_password.html', {
            'form': form,
            'error': form.errors.as_text(),
            'force_change': user.force_password_change
        })

    current_password = form.cleaned_data['current_password']
    new_password = form.cleaned_data['new_password']

    if not verify_password(current_password, user.password_hash):
        return render(request, 'auth/change_password.html', {
            'form': form,
            'error': 'Current password is incorrect.',
            'force_change': user.force_password_change
        })

    strength = score_password(new_password)
    if strength['score'] < 40:
        return render(request, 'auth/change_password.html', {
            'form': form,
            'error': f"New password is too weak: {strength['feedback']}",
            'force_change': user.force_password_change
        })

    new_hash = hash_password(new_password)
    for old_hash in user.password_history:
        if verify_password(new_password, old_hash):
            return render(request, 'auth/change_password.html', {
                'form': form,
                'error': 'Cannot reuse a recent password.',
                'force_change': user.force_password_change
            })

    user.password_hash = new_hash
    user.add_password_to_history(new_hash)
    user.force_password_change = False
    user.password_changed_at = datetime.utcnow()
    user.save()

    log_event(
        action='PASSWORD_CHANGE',
        category='ACCOUNT',
        request=request,
        actor=user,
        severity='INFO'
    )

    return render(request, 'auth/change_password.html', {
        'form': ChangePasswordForm(),
        'success': 'Password changed successfully.'
    })


# ============================================================
# ACCOUNT UNLOCK
# ============================================================

@require_GET
def unlock_request_view(request):
    """View shown when account is locked."""
    email = request.GET.get('email', '***@***.***')
    return render(request, 'auth/unlock_request.html', {
        'email': email
    })


@require_GET
def unlock_account_view(request, token):
    """Unlock account view."""
    token_hash = hash_sha256(token)
    user = User.objects(
        reset_token=token_hash,
        reset_token_expiry__gt=datetime.utcnow()
    ).first()

    if not user:
        return render(request, 'auth/unlock_account.html', {
            'error': 'Invalid or expired unlock link.',
            'invalid_token': True
        })

    user.is_locked = False
    user.failed_logins = 0
    user.lockout_level = 0
    user.lock_until = None
    user.reset_token = None
    user.reset_token_expiry = None
    user.mfa_failed_attempts = 0
    user.save()

    log_event(
        action='ACCOUNT_UNLOCKED_EMAIL',
        category='AUTH',
        request=request,
        target_user=user,
        severity='INFO'
    )

    return render(request, 'auth/unlock_account.html', {
        'success': 'Your account has been unlocked. You can now log in.'
    })


# ============================================================
# PROFILE VIEWS (require verified email)
# ============================================================

@login_required
@email_verified_required
@require_GET
def profile_view(request, username):
    """View user profile."""
    user = User.objects(username__iexact=username).first()

    if not user:
        return render(request, 'profile/view.html', {
            'error': 'User not found.'
        })

    if user.is_deleted:
        return render(request, 'profile/view.html', {
            'error': 'This account has been deleted.'
        })

    from chat.models import Room
    room_count = Room.objects(members=user, is_archived=False).count()

    return render(request, 'profile/view.html', {
        'profile_user': user,
        'room_count': room_count,
        'is_own_profile': request.user.id == user.id,
        'show_online': user.show_online_status
    })


@login_required
@email_verified_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def profile_edit_view(request):
    """Edit own profile."""
    user = request.user

    if request.method == 'GET':
        form = ProfileEditForm(initial={
            'display_name': user.display_name,
            'bio': user.bio,
            'theme': user.theme,
            'notification_sounds': user.notification_sounds,
            'show_online_status': user.show_online_status
        })
        return render(request, 'profile/edit.html', {'form': form})

    form = ProfileEditForm(request.POST)

    if not form.is_valid():
        return render(request, 'profile/edit.html', {
            'form': form,
            'error': form.errors.as_text()
        })

    if 'avatar' in request.FILES:
        avatar_file = request.FILES['avatar']
        
        if avatar_file.content_type not in settings.ALLOWED_AVATAR_TYPES:
            return render(request, 'profile/edit.html', {
                'form': form,
                'error': 'Invalid file type. Allowed: JPEG, PNG, GIF, WebP'
            })
        
        if avatar_file.size > settings.MAX_AVATAR_SIZE:
            return render(request, 'profile/edit.html', {
                'form': form,
                'error': 'File too large. Maximum size is 2MB.'
            })
        
        client = pymongo.MongoClient(settings.MONGODB_URI)
        db = client.get_default_database()
        fs = GridFS(db)
        
        if user.avatar_gridfs_id:
            try:
                fs.delete(user.avatar_gridfs_id)
            except Exception:
                pass
        
        avatar_id = fs.put(
            avatar_file.read(),
            filename=f"{user.id}_{avatar_file.name}",
            content_type=avatar_file.content_type
        )
        user.avatar_gridfs_id = avatar_id
        
        log_event(
            action='AVATAR_UPLOAD',
            category='ACCOUNT',
            request=request,
            actor=user,
            severity='INFO'
        )

    user.display_name = form.cleaned_data['display_name']
    user.bio = form.cleaned_data['bio']
    user.theme = form.cleaned_data['theme']
    user.notification_sounds = form.cleaned_data['notification_sounds']
    user.show_online_status = form.cleaned_data['show_online_status']
    user.save()

    log_event(
        action='PROFILE_UPDATE',
        category='ACCOUNT',
        request=request,
        actor=user,
        severity='INFO'
    )

    return render(request, 'profile/edit.html', {
        'form': form,
        'success': 'Profile updated successfully.'
    })


@login_required
@require_GET
def avatar_view(request, user_id):
    """Serve avatar from GridFS."""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return redirect('/static/images/default-avatar.svg')

    if not user.avatar_gridfs_id:
        return redirect('/static/images/default-avatar.svg')

    try:
        client = pymongo.MongoClient(settings.MONGODB_URI)
        db = client.get_default_database()
        fs = GridFS(db)
        
        grid_out = fs.get(user.avatar_gridfs_id)
        response = HttpResponse(
            grid_out.read(),
            content_type=grid_out.content_type or 'image/png'
        )
        response['Cache-Control'] = 'public, max-age=86400'
        return response
    except Exception:
        return redirect('/static/images/default-avatar.svg')


# ============================================================
# AJAX / UTILITIES
# ============================================================

@require_GET
def check_username_view(request):
    """AJAX endpoint to check username availability."""
    username = request.GET.get('username', '').strip()

    if not username or len(username) < 3:
        return JsonResponse({'available': False, 'message': 'Username too short'})

    import re
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return JsonResponse({'available': False, 'message': 'Invalid characters'})

    exists = User.objects(username__iexact=username).first()

    if exists:
        return JsonResponse({'available': False, 'message': 'Username is taken'})

    return JsonResponse({'available': True, 'message': 'Username is available'})