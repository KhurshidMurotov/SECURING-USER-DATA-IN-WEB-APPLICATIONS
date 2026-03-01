"""
Security dashboard views (staff only)
"""

from datetime import timedelta
import re

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone

from .models import SecurityEvent


IP_DETAIL_PATTERN = re.compile(
    r'client_ip=(?P<client>[^;|]+);\s*raw_remote_addr=(?P<raw>[^;|]+)'
)


def _extract_ip_info(details, fallback_client_ip):
    """Extract parsed/raw IPs from event details."""

    client_ip = fallback_client_ip or 'N/A'
    raw_remote_addr = 'N/A'
    if not details:
        return client_ip, raw_remote_addr

    match = IP_DETAIL_PATTERN.search(details)
    if not match:
        return client_ip, raw_remote_addr

    parsed_client = match.group('client').strip()
    parsed_raw = match.group('raw').strip()
    if parsed_client and parsed_client != '-':
        client_ip = parsed_client
    if parsed_raw and parsed_raw != '-':
        raw_remote_addr = parsed_raw
    return client_ip, raw_remote_addr


@login_required
def security_dashboard(request):
    """Admin security dashboard showing recent events and statistics."""
    if not request.user.is_staff:
        return HttpResponseForbidden()

    # Get recent events (last 24 hours)
    last_24h = timezone.now() - timedelta(hours=24)
    recent_events = list(SecurityEvent.objects.filter(timestamp__gte=last_24h)[:50])
    for event in recent_events:
        client_ip, raw_remote_addr = _extract_ip_info(event.details, event.ip_address)
        event.client_ip_display = client_ip
        event.raw_remote_addr_display = raw_remote_addr
    
    # Event type counts
    event_counts = SecurityEvent.objects.filter(
        timestamp__gte=last_24h
    ).values('event_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Top failing IPs
    top_failing_ips = SecurityEvent.objects.filter(
        event_type__in=['LOGIN_FAILURE', 'RATE_LIMIT_EXCEEDED'],
        timestamp__gte=last_24h,
        ip_address__isnull=False
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Suspicious activity (multiple failures from same IP)
    suspicious_ips = SecurityEvent.objects.filter(
        event_type='LOGIN_FAILURE',
        timestamp__gte=last_24h,
        ip_address__isnull=False
    ).values('ip_address').annotate(
        count=Count('id')
    ).filter(count__gte=5).order_by('-count')
    
    context = {
        'recent_events': recent_events,
        'event_counts': event_counts,
        'top_failing_ips': top_failing_ips,
        'suspicious_ips': suspicious_ips,
        'time_range': 'Last 24 hours',
    }
    
    return render(request, 'security/dashboard.html', context)

