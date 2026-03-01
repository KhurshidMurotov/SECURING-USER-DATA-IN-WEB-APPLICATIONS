"""
Utilities for consistent client IP extraction across security controls.
"""

import ipaddress

from django.conf import settings


def _sanitize_ip(value):
    """Return valid IP string or empty string."""

    candidate = (value or '').strip()
    if not candidate:
        return ''
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return ''


def get_raw_remote_addr(request):
    """Raw REMOTE_ADDR from WSGI environ."""

    return (request.META.get('REMOTE_ADDR', '') or '').strip()


def get_x_forwarded_for(request):
    """Raw X-Forwarded-For header value."""

    return (request.META.get('HTTP_X_FORWARDED_FOR', '') or '').strip()


def get_client_ip(request):
    """
    Resolve client IP deterministically.

    Honors X-Forwarded-For only when TRUST_PROXY_HEADERS=True.
    """

    raw_remote_addr = _sanitize_ip(get_raw_remote_addr(request))
    if not getattr(settings, 'TRUST_PROXY_HEADERS', False):
        return raw_remote_addr

    xff = get_x_forwarded_for(request)
    if not xff:
        return raw_remote_addr

    # Standard XFF format is "client, proxy1, proxy2". We trust the left-most.
    first_hop = _sanitize_ip(xff.split(',')[0])
    return first_hop or raw_remote_addr


def get_axes_client_ip(request):
    """Axes hook for IP detection."""

    return get_client_ip(request)

