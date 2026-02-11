"""
Django settings for barge2rail-camera project.

Dock Camera + Claude Vision Classification Service
"""

import os
from pathlib import Path
from decouple import config
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

# Security Settings
SECRET_KEY = config('SECRET_KEY', default='django-insecure-dev-key-change-in-production')
DEBUG = config('DEBUG', default=True, cast=bool)

# Validate SECRET_KEY length in production
if not DEBUG and len(SECRET_KEY) < 50:
    raise ImproperlyConfigured(
        f"SECRET_KEY must be at least 50 characters in production (current: {len(SECRET_KEY)}). "
        "Generate a secure key with: python -c 'from django.core.management.utils import "
        "get_random_secret_key; print(get_random_secret_key())'"
    )

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')

# SSO Configuration
SSO_BASE_URL = config('SSO_BASE_URL', default='https://sso.barge2rail.com')
SSO_CLIENT_ID = config('SSO_CLIENT_ID', default=None)
SSO_CLIENT_SECRET = config('SSO_CLIENT_SECRET', default=None)
SSO_REDIRECT_URI = config('SSO_REDIRECT_URI', default='http://localhost:8000/api/auth/callback/')
SSO_SCOPES = config('SSO_SCOPES', default='openid email profile roles')

# Application identifier for role-based access
APP_IDENTIFIER = config('APP_IDENTIFIER', default='cams')

# Debug logging control for authentication flow
DEBUG_AUTH_FLOW = config('DEBUG_AUTH_FLOW', default=False, cast=bool)

# Validate SSO credentials are configured
if not SSO_CLIENT_ID or not SSO_CLIENT_SECRET:
    import warnings
    warnings.warn(
        "SSO credentials not configured! "
        "Copy .env.example to .env and add your credentials from SSO admin panel.",
        UserWarning
    )

# Google SDM (Smart Device Management) Configuration
GOOGLE_SDM_PROJECT_ID = config('GOOGLE_SDM_PROJECT_ID', default='')
GOOGLE_CLOUD_PROJECT_ID = config('GOOGLE_CLOUD_PROJECT_ID', default='')
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID', default='')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET', default='')
SDM_OAUTH_REDIRECT_URI = os.environ.get('SDM_OAUTH_REDIRECT_URI', 'http://localhost:8000/api/oauth/callback/')

# Anthropic API
ANTHROPIC_API_KEY = config('ANTHROPIC_API_KEY', default='')
ANTHROPIC_MODEL = config('ANTHROPIC_MODEL', default='claude-sonnet-4-5-20250929')

# Default camera device ID
DEFAULT_CAMERA_DEVICE_ID = config('DEFAULT_CAMERA_DEVICE_ID', default='')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'camera',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'camera_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'camera_project.wsgi.application'

# Database - SQLite for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Cache configuration for OAuth state storage
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'camera_cache_table',
        'TIMEOUT': 600,
        'OPTIONS': {
            'MAX_ENTRIES': 10000
        }
    }
}

# Authentication URLs
LOGIN_URL = '/api/auth/login/'
LOGIN_REDIRECT_URL = '/api/status/'
LOGOUT_REDIRECT_URL = '/auth/login/'

# CSRF and Session Security
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_HTTPONLY = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Build CSRF_TRUSTED_ORIGINS dynamically
from urllib.parse import urlsplit

trusted_origins = set()
for host in ALLOWED_HOSTS:
    host = host.strip()
    if host:
        trusted_origins.add(f"https://{host}")
        if DEBUG:
            trusted_origins.add(f"http://{host}")
try:
    sso_parts = urlsplit(SSO_BASE_URL)
    if sso_parts.scheme and sso_parts.netloc:
        trusted_origins.add(f"{sso_parts.scheme}://{sso_parts.netloc}")
except Exception:
    pass
CSRF_TRUSTED_ORIGINS = sorted(trusted_origins)

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_SAVE_EVERY_REQUEST = False
SESSION_COOKIE_NAME = 'camera_sessionid'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'America/New_York'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

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
    'loggers': {
        'camera_project': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'camera': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'oauth.security': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}

# Production Database Configuration (Coolify PostgreSQL)
import dj_database_url
if config('DATABASE_URL', default=None):
    DATABASES['default'] = dj_database_url.parse(
        config('DATABASE_URL'),
        conn_max_age=600,
        conn_health_checks=True,
    )

# Production HTTPS Security Settings
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
