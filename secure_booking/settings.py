"""
Secure Django Settings — IKB21503 Secure Software Development
Implements: OWASP ASVS, Secure Coding Best Practices, SSDF
"""

import environ
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Environment Variables (SSDF PW.6 / OWASP A05) ---
env = environ.Env(DEBUG=(bool, False))
environ.Env.read_env(BASE_DIR / '.env', overwrite=True)

SECRET_KEY = env('SECRET_KEY', default='django-insecure-securebus-ikb21503-project-key-change-this-2024')
DEBUG = env.bool('DEBUG', default=True)   # Set to False in production via .env
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1', 'localhost'])

# --- Application Definition ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'axes',       # brute-force protection (OWASP A07)
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',        # CSRF Protection (OWASP A01)
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',                   # Brute-force lockout
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'core.middleware.SecurityHeadersMiddleware',        # Custom security headers
    'core.middleware.AuditLogMiddleware',               # Activity logging
]

ROOT_URLCONF = 'secure_booking.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'core' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            # Auto-escaping enabled by default — prevents XSS (OWASP A03)
        },
    },
]

WSGI_APPLICATION = 'secure_booking.wsgi.application'

# --- Database (SQLite for dev — switch to PostgreSQL in prod) ---
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# --- Password Hashing — bcrypt (OWASP ASVS V2.4) ---
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

# --- Password Validation (OWASP ASVS V2.1) ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- Internationalisation ---
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kuala_Lumpur'
USE_I18N = True
USE_TZ = True

# --- Static & Media Files ---
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# File uploads stored OUTSIDE web root (OWASP A04 / File Upload Security)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# --- Session Security (OWASP ASVS V3) ---
SESSION_COOKIE_HTTPONLY = True       # Prevent JS access to session cookie
SESSION_COOKIE_SECURE = False        # Set True when using HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 1800            # 30-minute timeout

# --- CSRF (OWASP ASVS V4.2) ---
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = False           # Set True when using HTTPS
CSRF_COOKIE_SAMESITE = 'Lax'

# --- Security Headers (OWASP A05) ---
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# HTTPS settings — uncomment in production
# SECURE_SSL_REDIRECT = True
# SECURE_HSTS_SECONDS = 31536000
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True

# --- Django-Axes: Brute Force Protection (OWASP A07) ---
AXES_FAILURE_LIMIT = 5              # Lock after 5 failed attempts
AXES_COOLOFF_TIME = 1               # 1 hour lockout
AXES_LOCKOUT_TEMPLATE = 'errors/locked_out.html'
AXES_RESET_ON_SUCCESS = True
AXES_ENABLED = True

AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# --- File Upload Security (OWASP A04) ---
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024   # 5MB max
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.pdf']
ALLOWED_UPLOAD_MIMETYPES = ['image/jpeg', 'image/png', 'application/pdf']

# --- Logging (OWASP ASVS V7) ---
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'secure': {
            'format': '[{asctime}] [{levelname}] [{module}] {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(BASE_DIR / 'logs' / 'security.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'secure',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'secure',
        },
    },
    'loggers': {
        'security': {
            'handlers': ['security_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'core.CustomUser'
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'
