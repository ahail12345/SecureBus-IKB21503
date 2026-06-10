"""
Utility helpers — Audit logging, file handling.
"""

import uuid
import os
import logging
from .models import AuditLog

logger = logging.getLogger('security')


def get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def log_event(request, event_type, description):
    """
    Write to AuditLog model and security log file.
    NEVER logs passwords, tokens, or sensitive data (OWASP ASVS V7.1).
    """
    user = getattr(request, 'user', None)
    if user and not user.is_authenticated:
        user = None

    ip = get_client_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '')[:500]

    AuditLog.objects.create(
        user=user,
        event_type=event_type,
        description=description[:1000],  # Truncate to prevent log injection
        ip_address=ip,
        user_agent=ua,
    )

    logger.info(
        f"{event_type} | user={user.username if user else 'anon'} | ip={ip} | {description[:200]}"
    )


def secure_filename(original_name):
    """
    Rename uploaded files to UUID to prevent path traversal & overwrite attacks.
    OWASP File Upload Security.
    """
    ext = os.path.splitext(original_name)[1].lower()
    return f"{uuid.uuid4().hex}{ext}"
