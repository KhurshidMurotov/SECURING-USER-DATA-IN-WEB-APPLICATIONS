"""
Django settings for secure_web project.

Security-focused configuration for demonstrating best practices.
"""

import os
import sys
import importlib.util
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'django-insecure-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party
    'axes',
    # Local apps
    'apps.accounts',
    'apps.profiles',
    'apps.security',
    'apps.pages',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'axes.middleware.AxesMiddleware',  # Rate limiting
    'apps.security.middleware.SecurityHeadersMiddleware',  # Custom security headers
]

if importlib.util.find_spec('whitenoise'):
    MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')

ROOT_URLCONF = 'secure_web.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
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

WSGI_APPLICATION = 'secure_web.wsgi.application'

# Database
DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL', 'sqlite:///db.sqlite3'),
        conn_max_age=600,
    )
}

# Custom User Model
AUTH_USER_MODEL = 'accounts.User'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
if importlib.util.find_spec('whitenoise'):
    STORAGES = {
        'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
        'staticfiles': {
            'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'
        },
    }
else:
    STORAGES = {
        'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
        'staticfiles': {
            'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'
        },
    }

# Media files
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ============================================================================
# SECURITY SETTINGS
# ============================================================================

# Session Security
SESSION_COOKIE_SECURE = not DEBUG  # True in production (HTTPS only)
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
SESSION_COOKIE_AGE = 1800  # 30 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # Expire on browser close

# CSRF Security
CSRF_COOKIE_SECURE = not DEBUG  # True in production (HTTPS only)
CSRF_COOKIE_HTTPONLY = False  # Must be False for AJAX
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',') if os.getenv('CSRF_TRUSTED_ORIGINS') else []

# Security Headers (handled by custom middleware)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Rate Limiting (django-axes)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 5  # Lock after 5 failed attempts
AXES_COOLOFF_TIME = 0.5  # 30 minutes lockout
AXES_LOCKOUT_PARAMETERS = [['username', 'ip_address']]  # Track by email + IP
AXES_USERNAME_FORM_FIELD = 'username'
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = 'accounts/locked_out.html'
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Encryption Key for sensitive fields
# Note: In development, you can generate a key temporarily, but in production
# this must come from environment variable
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # For development/testing only - generate a temporary key
    # WARNING: This key will change on each server restart in dev mode
    # In production, always set ENCRYPTION_KEY in environment
    if DEBUG:
        from cryptography.fernet import Fernet
        ENCRYPTION_KEY = Fernet.generate_key().decode()
        print("WARNING: Using auto-generated encryption key. This is for development only!")
    else:
        raise ValueError(
            "ENCRYPTION_KEY environment variable is required in production. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )

# Login URLs
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'profiles:dashboard'
LOGOUT_REDIRECT_URL = 'pages:home'

# Email settings
# For local development, default to console backend so emails are written
# to the terminal instead of being sent via SMTP. During tests we prefer
# the in-memory backend so django.core.mail.outbox works as expected.
DEFAULT_EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
if 'test' in sys.argv:
    DEFAULT_EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', DEFAULT_EMAIL_BACKEND)
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '25'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'False') == 'True'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv(
    'DEFAULT_FROM_EMAIL',
    EMAIL_HOST_USER or 'webmaster@localhost',
)

