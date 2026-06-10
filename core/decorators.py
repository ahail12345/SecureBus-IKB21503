"""
RBAC Decorators — Role-Based Access Control
OWASP ASVS V4 (Access Control), A01
"""

from functools import wraps
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from .utils import log_event
from .models import AuditLog


def admin_required(view_func):
    """Only allow users with ADMIN role. Raises 403 for others."""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_admin():
            log_event(
                request,
                AuditLog.EventType.ACCESS_DENIED,
                f"Non-admin '{request.user.username}' attempted to access admin resource: {request.path}"
            )
            raise PermissionDenied("You do not have permission to access this resource.")
        return view_func(request, *args, **kwargs)
    return wrapper


def user_required(view_func):
    """Only allow authenticated regular users (not admin-only routes)."""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        return view_func(request, *args, **kwargs)
    return wrapper
