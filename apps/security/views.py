"""
Security dashboard views (staff only)
"""

from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone

from .models import SecurityEvent


@login_required
def security_dashboard(request):
    """Admin security dashboard showing recent events and statistics."""
    if not request.user.is_staff:
        return HttpResponseForbidden()

    # Get recent events (last 24 hours)
    last_24h = timezone.now() - timedelta(hours=24)
    recent_events = SecurityEvent.objects.filter(timestamp__gte=last_24h)[:50]
    
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

