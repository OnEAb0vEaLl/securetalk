"""
Django settings for SecureTalk project.
"""

import os
from pathlib import Path
from decouple import config, Csv
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
def env(key, default=None, cast=None):
    """Helper function to get environment variables."""
    value = config(key, default=default, cast=cast if cast else str)
    return value

# Required environment variables check
REQUIRED_ENV_VARS = [
    'MONGODB_URI', 'DJANGO_SECRET_KEY', 'REDIS_URL',
    'TURNSTILE_SECRET_KEY', 'TURNSTILE_SITE_KEY',
    'EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD',
    'TOTP_ENCRYPTION_KEY', 'ADMIN_USERNAME', 'ADMIN_EMAIL', 'ADMIN_PASSWORD'
]

for var in REQUIRED_ENV_VARS:
    if not config(var, default=None):
        raise ImproperlyConfigured(f'Missing required environment variable: {var}')

# Validate TOTP_ENCRYPTION_KEY
TOTP_ENCRYPTION_KEY = config('TOTP_ENCRYPTION_KEY')
if len(TOTP_ENCRYPTION_KEY) != 64:
    raise ImproperlyConfigured('TOTP_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)')
try:
    bytes.fromhex(TOTP_ENCRYPTION_KEY)
except ValueError:
    raise ImproperlyConfigured('TOTP_ENCRYPTION_KEY must be valid hexadecimal')

# Core settings
SECRET_KEY = config('DJANGO_SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# Application definition
INSTALLED_APPS = [
    'django.contrib.staticfiles',
    'django.contrib.contenttypes',
    'channels',
    'accounts',
    'chat',
    'audit',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'accounts.middleware.JWTAuthMiddleware',
    'django.middleware.common.CommonMiddleware',
    'csp.middleware.CSPMiddleware',
]

ROOT_URLCONF = 'securetalk.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
            ],
        },
    },
]

WSGI_APPLICATION = 'securetalk.wsgi.application'
ASGI_APPLICATION = 'securetalk.asgi.application'

# No Django ORM - using MongoDB
DATABASES = {}

# MongoDB settings
MONGODB_URI = config('MONGODB_URI')

# Redis / Channels
REDIS_URL = config('REDIS_URL')
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [REDIS_URL],
        },
    }
}

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# CSP Settings
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "https://challenges.cloudflare.com")
CSP_FRAME_SRC = ("https://challenges.cloudflare.com",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'", "wss:", "ws:")
CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com")

# Security headers
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
X_FRAME_OPTIONS = 'DENY'
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True

# JWT Settings
JWT_SECRET_KEY = SECRET_KEY
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_SECONDS = 1800  # 30 minutes
JWT_MFA_EXPIRY_SECONDS = 600  # 10 minutes
JWT_COOKIE_SETTINGS = {
    'httponly': True,
    'samesite': 'Strict',
    'secure': not DEBUG,
    'max_age': JWT_EXPIRY_SECONDS,
}

# Turnstile
TURNSTILE_SITE_KEY = config('TURNSTILE_SITE_KEY')
TURNSTILE_SECRET_KEY = config('TURNSTILE_SECRET_KEY')

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', cast=int)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# Admin credentials
ADMIN_USERNAME = config('ADMIN_USERNAME')
ADMIN_EMAIL = config('ADMIN_EMAIL')
ADMIN_PASSWORD = config('ADMIN_PASSWORD')

# File upload limits
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2MB
ALLOWED_AVATAR_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']

# Online presence timeout
ONLINE_TIMEOUT_SECONDS = 180

# Rate limiting
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}