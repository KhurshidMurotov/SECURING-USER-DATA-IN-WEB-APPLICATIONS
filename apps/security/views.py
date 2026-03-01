"""
Security dashboard views (staff only)
"""

import re
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render
from django.utils import timezone

from .models import SecurityEvent


IP_DETAIL_PATTERN = re.compile(
    r'client_ip=(?P<client>[^;|]+);\s*raw_remote_addr=(?P<raw>[^;|]+)'
)

EVENT_TYPE_HELP = {
    'LOGIN_FAILURE': 'Failed authentication attempts. High numbers may indicate brute-force activity.',
    'LOGIN_SUCCESS': 'Successful user logins.',
    'CAPTCHA_REQUIRED': 'CAPTCHA step was enforced because repeated failures were detected.',
    'CAPTCHA_FAILED': 'CAPTCHA submission was empty/invalid.',
    'CAPTCHA_PASSED': 'CAPTCHA challenge was solved successfully.',
    'ACCOUNT_LOCKED': 'Temporary lockout activated after too many failures.',
    'REGISTRATION': 'New account registrations.',
    'LOGOUT': 'User logout events.',
    'PROFILE_UPDATE': 'Profile changes made by users.',
}

EVENT_TYPE_SEVERITY = {
    'LOGIN_FAILURE': 'high',
    'ACCOUNT_LOCKED': 'high',
    'CAPTCHA_FAILED': 'medium',
    'CAPTCHA_REQUIRED': 'medium',
    'CAPTCHA_PASSED': 'low',
    'LOGIN_SUCCESS': 'low',
    'LOGOUT': 'low',
    'REGISTRATION': 'low',
    'PROFILE_UPDATE': 'low',
}

TIME_RANGE_OPTIONS = {
    '1h': ('Last 1 hour', timedelta(hours=1)),
    '24h': ('Last 24 hours', timedelta(hours=24)),
    '7d': ('Last 7 days', timedelta(days=7)),
}


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

    selected_time_range = (request.GET.get('range') or '24h').strip().lower()
    if selected_time_range not in TIME_RANGE_OPTIONS:
        selected_time_range = '24h'
    time_range_label, time_delta = TIME_RANGE_OPTIONS[selected_time_range]

    selected_event_type = (request.GET.get('event_type') or '').strip()
    valid_event_types = {choice[0] for choice in SecurityEvent.EVENT_TYPES}
    if selected_event_type not in valid_event_types:
        selected_event_type = ''

    # Get recent events for selected time range
    since = timezone.now() - time_delta
    recent_events_qs = SecurityEvent.objects.filter(timestamp__gte=since)
    if selected_event_type:
        recent_events_qs = recent_events_qs.filter(event_type=selected_event_type)
    paginator = Paginator(recent_events_qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    recent_events = list(page_obj.object_list)
    for event in recent_events:
        client_ip, raw_remote_addr = _extract_ip_info(event.details, event.ip_address)
        event.client_ip_display = client_ip
        event.raw_remote_addr_display = raw_remote_addr
    
    # Event type counts
    event_counts = list(SecurityEvent.objects.filter(
        timestamp__gte=since
    ).values('event_type').annotate(
        count=Count('id')
    ).order_by('-count'))
    for event in event_counts:
        event['help_text'] = EVENT_TYPE_HELP.get(
            event['event_type'],
            'View matching events in recent activity.',
        )
        event['severity'] = EVENT_TYPE_SEVERITY.get(event['event_type'], 'low')
    
    # Top failing IPs
    top_failing_ips = SecurityEvent.objects.filter(
        event_type__in=['LOGIN_FAILURE', 'RATE_LIMIT_EXCEEDED'],
        timestamp__gte=since,
        ip_address__isnull=False
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Suspicious activity (multiple failures from same IP)
    suspicious_ips = SecurityEvent.objects.filter(
        event_type='LOGIN_FAILURE',
        timestamp__gte=since,
        ip_address__isnull=False
    ).values('ip_address').annotate(
        count=Count('id')
    ).filter(count__gte=5).order_by('-count')
    
    context = {
        'recent_events': recent_events,
        'event_counts': event_counts,
        'top_failing_ips': top_failing_ips,
        'suspicious_ips': suspicious_ips,
        'time_range': time_range_label,
        'selected_time_range': selected_time_range,
        'time_range_options': TIME_RANGE_OPTIONS,
        'selected_event_type': selected_event_type,
        'selected_event_help': EVENT_TYPE_HELP.get(selected_event_type, ''),
        'page_obj': page_obj,
    }
    
    return render(request, 'security/dashboard.html', context)


def health_check(request):
    """Lightweight health endpoint for uptime checks."""

    return JsonResponse({'status': 'ok'})

