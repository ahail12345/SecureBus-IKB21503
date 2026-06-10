"""
Custom Security Middleware
- Security headers (OWASP A05)
- Audit logging for sensitive actions (OWASP ASVS V7)
"""

import logging
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('security')


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Adds security headers to every response.
    OWASP ASVS V14.4 — HTTP Security Headers
    """
    def process_response(self, request, response):
        # Content Security Policy — prevent XSS/injection
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "frame-ancestors 'none';"
        )
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        # Remove server header info leakage
        if 'Server' in response:
            del response['Server']
        return response


class AuditLogMiddleware(MiddlewareMixin):
    """
    Logs access denials (403) and suspicious patterns.
    OWASP ASVS V7.2
    """
    SENSITIVE_PATHS = ['/admin/', '/audit-logs/', '/manage-bus/']

    def get_client_ip(self, request):
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def process_response(self, request, response):
        ip = self.get_client_ip(request)
        user = getattr(request, 'user', None)
        username = user.username if user and user.is_authenticated else 'anonymous'

        # Log 403 Access Denied events
        if response.status_code == 403:
            logger.warning(
                f"ACCESS_DENIED | user={username} | ip={ip} | path={request.path}"
            )

        # Log access to sensitive admin paths by non-admins
        if any(request.path.startswith(p) for p in self.SENSITIVE_PATHS):
            if user and not user.is_authenticated:
                logger.warning(
                    f"UNAUTHENTICATED_SENSITIVE_ACCESS | ip={ip} | path={request.path}"
                )

        return response
