"""
Profile views with security event logging
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from .models import UserProfile
from .forms import UserProfileForm
from apps.security.models import SecurityEvent


@login_required
def dashboard_view(request):
    """User dashboard showing profile summary."""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    return render(request, 'profiles/dashboard.html', {'profile': profile})


@login_required
@require_http_methods(["GET", "POST"])
@csrf_protect
def edit_profile_view(request):
    """Edit profile view with security event logging."""
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            # Log profile update
            SecurityEvent.objects.create(
                user=request.user,
                event_type='PROFILE_UPDATE',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details='User updated profile information'
            )
            messages.success(request, 'Profile updated successfully!')
            return redirect('profiles:dashboard')
    else:
        form = UserProfileForm(instance=profile)
    
    return render(request, 'profiles/edit_profile.html', {'form': form, 'profile': profile})
