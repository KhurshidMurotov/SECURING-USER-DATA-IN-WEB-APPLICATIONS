"""Utilities for client IP extraction."""

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
    Resolve client IP for logging/debug behind reverse proxy.

    Order: X-Forwarded-For first hop -> X-Real-IP -> REMOTE_ADDR.
    Note: in cloud environments this can still be a proxy/NAT address.
    """

    xff = get_x_forwarded_for(request)
    if xff:
        first_ip = _sanitize_ip(xff.split(',')[0])
        if first_ip:
            return first_ip

    x_real_ip = _sanitize_ip(request.META.get('HTTP_X_REAL_IP', ''))
    if x_real_ip:
        return x_real_ip

    return _sanitize_ip(get_raw_remote_addr(request))


def _get_trusted_proxy_client_ip(request):
    """Resolver for security controls (axes): trust headers only when enabled."""

    if getattr(settings, 'TRUST_PROXY_HEADERS', False):
        return get_client_ip(request)
    return _sanitize_ip(get_raw_remote_addr(request))


def get_axes_client_ip(request):
    """Axes hook for IP detection (trusted proxy mode only)."""

    return _get_trusted_proxy_client_ip(request)
