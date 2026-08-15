# SecureTalk - Secure Community Chat Platform

A secure, real-time community chat application built with Django, MongoDB, and WebSockets for a university cybersecurity assignment.

---

## Features

| Feature | Details |
|---|---|
| Real-time chat | Django Channels + Redis WebSockets |
| Authentication | JWT (httpOnly cookie), bcrypt 12 rounds |
| Multi-factor auth | TOTP (authenticator app) + Email OTP — both can be active simultaneously |
| Progressive lockout | 5 tiers: 30s → 2min → 5min → 15min → permanent |
| Email account unlock | No recovery codes — email-based unlock only |
| Public/Private rooms | Password-protected private rooms |
| Audit logging | Every action logged with IP, actor, severity, details |
| Admin panel | User management, room control, filterable audit log, CSV export |
| Profile system | Avatars stored in GridFS, bio, theme preference |
| Security headers | CSP, X-Frame-Options DENY, HSTS (production) |
| Cloudflare Turnstile | CAPTCHA on register and login |

---

## Prerequisites

- Python 3.11+
- MongoDB 6.0+
- Redis 7+
- pip / virtualenv

---

## Quick Start

```bash

cd securetalk

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and fill in environment variables
cp .env.example .env
# Edit .env — fill in ALL values before proceeding

# 5. Collect static files
python manage.py collectstatic --noinput

# 6. Run the development server (ASGI via Daphne for WebSocket support)
python -m daphne -b 0.0.0.0 -p 8000 securetalk.asgi:application
```

The admin account is automatically created on first startup using `ADMIN_USERNAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` from your `.env`.

---

## Generating Secrets

```bash
# DJANGO_SECRET_KEY (50 chars)
python -c "import secrets; print(secrets.token_urlsafe(50))"

# TOTP_ENCRYPTION_KEY (64 hex chars = 32 bytes)
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `MONGODB_URI` | MongoDB connection string (include database name) |
| `REDIS_URL` | Redis URL for Django Channels |
| `DJANGO_SECRET_KEY` | 50+ char random secret |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile secret key |
| `TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key |
| `EMAIL_HOST` | SMTP server (e.g. smtp.gmail.com) |
| `EMAIL_PORT` | SMTP port (587 for TLS) |
| `EMAIL_HOST_USER` | SMTP username / from address |
| `EMAIL_HOST_PASSWORD` | SMTP password or app password |
| `TOTP_ENCRYPTION_KEY` | 64 hex chars for AES-256 TOTP secret encryption |
| `ADMIN_USERNAME` | Bootstrap admin username |
| `ADMIN_EMAIL` | Bootstrap admin email |
| `ADMIN_PASSWORD` | Bootstrap admin password |
| `DEBUG` | `True` for development, `False` for production |

---

## Architecture

```
securetalk/
├── accounts/       Auth, MFA, profiles, lockout, email verification
├── chat/           Rooms, messages, WebSocket consumer (Django Channels)
├── audit/          Audit logging, admin panel views
├── templates/      Django HTML templates
└── static/         CSS + JavaScript
```

### Security Model

- **JWT auth**: Signed HS256 tokens in `httpOnly; SameSite=Strict` cookies, 30-minute expiry with sliding refresh
- **MFA temp cookie**: Separate 10-minute cookie during MFA verification flow
- **TOTP secrets**: AES-256-CBC encrypted at rest in MongoDB
- **Passwords**: bcrypt (12 rounds), history of last 5 stored
- **Tokens**: `secrets.token_hex(32)` → SHA-256 hash stored, plaintext never persisted
- **WebSocket auth**: JWT validated on connect; unauthenticated connections rejected
- **Message content**: `bleach.clean()` strips all HTML before save and broadcast

### Progressive Lockout

| Failed Logins | Action |
|---|---|
| ≥ 5 | Lock for 30 seconds |
| ≥ 10 | Lock for 2 minutes |
| ≥ 15 | Lock for 5 minutes |
| ≥ 20 | Lock for 15 minutes |
| ≥ 25 | Permanent lock + unlock email sent |

---

## Production Deployment

```bash
# Set DEBUG=False in .env
# Use a proper WSGI/ASGI server:
python -m daphne -b 0.0.0.0 -p 8000 securetalk.asgi:application

# Or with gunicorn + uvicorn workers:
gunicorn securetalk.asgi:application -w 4 -k uvicorn.workers.UvicornWorker

# Ensure MongoDB and Redis are running
# Set up a reverse proxy (nginx) for HTTPS and static file serving
```

---

## Cloudflare Turnstile

Get your free keys at: https://dash.cloudflare.com → Turnstile

For local development, use the test keys:
- Site key: `1x00000000000000000000AA`
- Secret key: `1x0000000000000000000000000000000AA`

---


## Features

### Security Features
- 🔐 **JWT Authentication** - Secure token-based authentication with httpOnly cookies
- 🛡️ **Multi-Factor Authentication** - TOTP (Authenticator App) and Email OTP support
- 🔒 **Password Security** - bcrypt hashing with 12 rounds, password strength meter, history check
- 🚫 **Progressive Lockout** - 5-level lockout system with email-based unlock
- 📝 **Audit Logging** - Comprehensive logging of all security events
- 🌐 **CSP & Security Headers** - Content Security Policy, XSS protection, HSTS
- ✅ **Cloudflare Turnstile** - Bot protection on forms
- 🔑 **Encrypted Secrets** - AES-256-CBC encryption for TOTP secrets

### Chat Features
- 💬 **Real-time Messaging** - WebSocket-based instant messaging
- 🏠 **Public & Private Rooms** - Password-protected private rooms
- 👥 **Online Presence** - Real-time online status indicators
- ⌨️ **Typing Indicators** - See when others are typing
- 📜 **Message History** - Persistent message storage in MongoDB
- 🧹 **Content Sanitization** - bleach-based HTML sanitization

### User Features
- 👤 **User Profiles** - Customizable display names, bios, avatars
- 🖼️ **GridFS Avatars** - MongoDB GridFS for file storage
- 🌙 **Dark/Light Theme** - User-selectable themes
- 🔔 **Notification Preferences** - Sound and online status settings

### Admin Features
- 👥 **User Management** - Lock, unlock, delete, role changes
- 🏠 **Room Management** - Archive, restore rooms
- 📊 **Audit Dashboard** - Filterable, exportable audit logs

## Tech Stack

- **Backend**: Python 3.11+, Django 5.x
- **Database**: MongoDB via mongoengine
- **Real-time**: Django Channels + Redis
- **Authentication**: PyJWT, passlib (bcrypt)
- **MFA**: pyotp, qrcode
- **Security**: django-csp, django-ratelimit, cryptography
- **Email**: django.core.mail (SMTP)


*SecureTalk — Built with Django 5, MongoDB, and Django Channels*
# securetalk
# securetalk
