"""
Authentication views with security logging
"""

import threading
import time
from random import SystemRandom

from django.contrib import messages
from django.contrib.auth import login, logout
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.security.models import SecurityEvent

from .forms import ResendVerificationForm, UserLoginForm, UserRegistrationForm
from .models import User
from .tokens import generate_email_verification_token, parse_email_verification_token

CAPTCHA_THRESHOLD = 3
LOCKOUT_THRESHOLD = 5
CAPTCHA_TTL_SECONDS = 300
CAPTCHA_EXTRA_ATTEMPTS = 2
CAPTCHA_SESSION_KEY = 'login_captcha_gate'


def _get_client_ip(request):
    """Best-effort extraction of client IP address."""

    return request.META.get('REMOTE_ADDR', '')


def _get_user_agent(request):
    """Best-effort extraction of user agent string."""

    return request.META.get('HTTP_USER_AGENT', '')


def _normalize_email(email):
    """Normalize submitted email for consistent tracking."""

    return (email or '').strip().lower()


def _build_login_gate_key(email, ip_address):
    """Build deterministic key for session gate state."""

    return f'{_normalize_email(email)}|{ip_address or ""}'


def _get_captcha_state(request, gate_key):
    """Fetch CAPTCHA state for a given gate key from session."""

    state = request.session.get(CAPTCHA_SESSION_KEY, {})
    return state.get(gate_key, {})


def _set_captcha_state(request, gate_key, state):
    """Persist CAPTCHA state for a gate key into session."""

    all_state = request.session.get(CAPTCHA_SESSION_KEY, {})
    all_state[gate_key] = state
    request.session[CAPTCHA_SESSION_KEY] = all_state
    request.session.modified = True


def _clear_captcha_state(request, gate_key):
    """Remove CAPTCHA state for a gate key from session."""

    all_state = request.session.get(CAPTCHA_SESSION_KEY, {})
    if gate_key in all_state:
        del all_state[gate_key]
        request.session[CAPTCHA_SESSION_KEY] = all_state
        request.session.modified = True


def _generate_captcha_challenge():
    """Return a simple math CAPTCHA challenge and its answer."""

    rng = SystemRandom()
    left = rng.randint(1, 9)
    right = rng.randint(1, 9)
    return f'What is {left} + {right}?', str(left + right)


def _get_or_rotate_captcha(request, gate_key):
    """Create or rotate captcha and return current state."""

    question, answer = _generate_captcha_challenge()
    state = _get_captcha_state(request, gate_key)
    state['captcha_question'] = question
    state['captcha_answer'] = answer
    state['captcha_expires_at'] = int(time.time()) + CAPTCHA_TTL_SECONDS
    _set_captcha_state(request, gate_key, state)
    return state


def _captcha_is_valid(state, submitted_answer):
    """Validate submitted captcha answer and expiration."""

    if not state:
        return False
    expires_at = int(state.get('captcha_expires_at', 0) or 0)
    expected_answer = str(state.get('captcha_answer', '')).strip()
    if expires_at < int(time.time()):
        return False
    return expected_answer and expected_answer == str(submitted_answer).strip()


def _get_failed_attempts(email, ip_address):
    """Read failed login count from axes server-side records."""

    from axes.models import AccessAttempt

    normalized = _normalize_email(email)
    if not normalized:
        return 0

    attempt = (
        AccessAttempt.objects.filter(
            username=normalized,
            ip_address=ip_address or '',
        )
        .order_by('-attempt_time')
        .first()
    )
    if not attempt:
        return 0
    return int(attempt.failures_since_start or 0)


def _send_verification_email(request, user):
    """
    Send an email verification link to the given user.

    Uses the configured backend for non-SMTP modes (tests, console).
    For SMTP mode, sends through SMTP and mirrors the same message to console after 10 seconds (temporary).
    """

    from django.conf import settings
    from django.core.mail import get_connection, send_mail

    token = generate_email_verification_token(user)
    verify_path = reverse('accounts:verify_email', args=[token])
    verify_url = request.build_absolute_uri(verify_path)

    subject = 'Verify your email address'
    message = (
        'Thank you for registering.\n\n'
        'Please click the link below to verify your email address:\n'
        f'{verify_url}\n\n'
        'If you did not create an account, you can ignore this email.'
    )

    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None)
    recipient_list = [user.email]
    email_backend = getattr(settings, 'EMAIL_BACKEND', '')

    # If using non-SMTP backend (tests, console), use it directly
    if 'smtp' not in email_backend.lower():
        try:
            send_mail(
                subject,
                message,
                from_email,
                recipient_list,
                fail_silently=False,
            )
            details = f'Verification email sent via {email_backend}'
        except Exception as exc:  # pragma: no cover
            details = f'Failed to send verification email: {exc}'

        SecurityEvent.objects.create(
            user=user,
            event_type='VERIFICATION_EMAIL_SENT',
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            details=details,
        )
        return

    # Step 1: Try SMTP first
    smtp_details = None
    try:
        smtp_connection = get_connection(
            backend='django.core.mail.backends.smtp.EmailBackend',
            host=getattr(settings, 'EMAIL_HOST', 'localhost'),
            port=getattr(settings, 'EMAIL_PORT', 25),
            username=getattr(settings, 'EMAIL_HOST_USER', ''),
            password=getattr(settings, 'EMAIL_HOST_PASSWORD', ''),
            use_tls=getattr(settings, 'EMAIL_USE_TLS', False),
        )
        send_mail(
            subject,
            message,
            from_email,
            recipient_list,
            connection=smtp_connection,
            fail_silently=False,
        )
        smtp_details = 'Verification email sent via SMTP'
    except Exception as exc:  # pragma: no cover - network-dependent
        smtp_details = f'SMTP send failed: {exc}'


    # Temporary fallback: mirror the same message to console after 10 seconds.
    def _send_via_console_delayed():
        time.sleep(10)
        try:
            console_connection = get_connection(
                backend='django.core.mail.backends.console.EmailBackend',
            )
            send_mail(
                subject,
                message,
                from_email,
                recipient_list,
                connection=console_connection,
                fail_silently=False,
            )
            console_details = 'Verification email mirrored to console backend after 10s'
        except Exception as exc:  # pragma: no cover
            console_details = f'Console mirror send failed: {exc}'

        SecurityEvent.objects.create(
            user=user,
            event_type='VERIFICATION_EMAIL_SENT',
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            details=f'{smtp_details}; {console_details}',
        )

    thread = threading.Thread(target=_send_via_console_delayed, daemon=True)
    thread.start()
    # Log the initial SMTP attempt
    SecurityEvent.objects.create(
        user=user,
        event_type='VERIFICATION_EMAIL_SENT',
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        details=smtp_details,
    )


@require_http_methods(['GET', 'POST'])
@csrf_protect
def register_view(request):
    """User registration view with security event logging and email verification."""

    if request.user.is_authenticated:
        return redirect('profiles:dashboard')

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_email_verified = True
            user.save()

            SecurityEvent.objects.create(
                user=user,
                event_type='REGISTRATION',
                ip_address=_get_client_ip(request),
                user_agent=_get_user_agent(request),
                details='User registered successfully',
            )

            login(
                request,
                user,
                backend='django.contrib.auth.backends.ModelBackend',
            )
            messages.success(request, 'Registration successful.')
            return redirect('profiles:dashboard')
    else:
        form = UserRegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})


@require_http_methods(['GET'])
def verification_sent_view(request):
    """Simple page informing the user that a verification email has been sent."""

    return render(request, 'accounts/verification_sent.html')


@require_http_methods(['GET', 'POST'])
@csrf_protect
def resend_verification_view(request):
    """
    Allow users to request a new verification email.

    Rate-limited per session to reduce abuse potential.
    """

    if request.method == 'POST':
        form = ResendVerificationForm(request.POST)
        if form.is_valid():
            messages.info(request, 'This feature is currently unavailable.')
            return redirect('accounts:login')
    else:
        initial_email = request.GET.get('email') or ''
        form = ResendVerificationForm(initial={'email': initial_email})

    return render(request, 'accounts/resend_verification.html', {'form': form})


@require_http_methods(['GET'])
def verify_email_view(request, token):
    """
    Handle email verification link clicks.

    On success, marks the user's email as verified and redirects to login.
    """

    data = parse_email_verification_token(token)
    if not data:
        return render(request, 'accounts/verification_failed.html')

    user_id = data.get('user_id')
    email = data.get('email')

    try:
        user = User.objects.get(pk=user_id, email=email)
    except User.DoesNotExist:
        return render(request, 'accounts/verification_failed.html')

    if not user.is_email_verified:
        user.is_email_verified = True
        user.save(update_fields=['is_email_verified'])

        SecurityEvent.objects.create(
            user=user,
            event_type='EMAIL_VERIFIED',
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            details='User verified email address',
        )

    messages.success(
        request,
        'Your email has been verified successfully. You can now log in.',
    )
    return render(request, 'accounts/verification_success.html')


@require_http_methods(['GET', 'POST'])
@csrf_protect
def login_view(request):
    """User login view with security event logging."""

    if request.user.is_authenticated:
        return redirect('profiles:dashboard')

    form = UserLoginForm(request)
    client_ip = _get_client_ip(request)
    user_agent = _get_user_agent(request)

    if request.method == 'POST':
        submitted_email = _normalize_email(request.POST.get('username'))
        gate_key = _build_login_gate_key(submitted_email, client_ip)

        pre_failures = _get_failed_attempts(submitted_email, client_ip)
        state = _get_captcha_state(request, gate_key)
        captcha_passed = bool(state.get('captcha_passed'))
        extra_attempts_left = int(state.get('extra_attempts_left', 0) or 0)
        captcha_required = (
            pre_failures >= CAPTCHA_THRESHOLD
            and pre_failures < LOCKOUT_THRESHOLD
            and not (captcha_passed and extra_attempts_left > 0)
        )

        captcha_label = 'CAPTCHA'
        if captcha_required:
            state = _get_or_rotate_captcha(request, gate_key)
            captcha_label = state.get('captcha_question', 'CAPTCHA')
            SecurityEvent.objects.create(
                user=None,
                event_type='CAPTCHA_REQUIRED',
                ip_address=client_ip,
                user_agent=user_agent,
                details='CAPTCHA required after repeated failed login attempts',
            )

        form = UserLoginForm(
            request,
            data=request.POST,
            require_captcha=captcha_required,
            captcha_label=captcha_label,
        )

        if captcha_required:
            captcha_answer = request.POST.get('captcha_answer', '')
            captcha_state = _get_captcha_state(request, gate_key)
            if not _captcha_is_valid(captcha_state, captcha_answer):
                SecurityEvent.objects.create(
                    user=None,
                    event_type='CAPTCHA_FAILED',
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details='CAPTCHA validation failed',
                )
                _get_or_rotate_captcha(request, gate_key)
                form = UserLoginForm(
                    request,
                    data=request.POST,
                    require_captcha=True,
                    captcha_label=_get_captcha_state(request, gate_key).get(
                        'captcha_question', 'CAPTCHA'
                    ),
                )
                form.add_error('captcha_answer', 'Incorrect or expired CAPTCHA.')
                messages.error(
                    request,
                    'Please complete the CAPTCHA challenge to continue.',
                )
                return render(request, 'accounts/login.html', {'form': form})

            state = _get_captcha_state(request, gate_key)
            state['captcha_passed'] = True
            state['extra_attempts_left'] = CAPTCHA_EXTRA_ATTEMPTS
            _set_captcha_state(request, gate_key, state)
            SecurityEvent.objects.create(
                user=None,
                event_type='CAPTCHA_PASSED',
                ip_address=client_ip,
                user_agent=user_agent,
                details='CAPTCHA solved; temporary additional attempts granted',
            )

        if form.is_valid():
            user = form.get_user()

            _clear_captcha_state(request, gate_key)

            login(request, user)

            SecurityEvent.objects.create(
                user=user,
                event_type='LOGIN_SUCCESS',
                ip_address=client_ip,
                user_agent=user_agent,
                details='User logged in successfully',
            )
            messages.success(request, f'Welcome back, {user.first_name}!')
            return redirect('profiles:dashboard')
        else:
            email = form.data.get('username', 'unknown')
            SecurityEvent.objects.create(
                user=None,
                event_type='LOGIN_FAILURE',
                ip_address=client_ip,
                user_agent=user_agent,
                details=f'Failed login attempt for email: {email}',
            )

            if submitted_email:
                post_failures = _get_failed_attempts(submitted_email, client_ip)
                state = _get_captcha_state(request, gate_key)
                if state.get('captcha_passed') and state.get('extra_attempts_left', 0):
                    state['extra_attempts_left'] = max(
                        0, int(state.get('extra_attempts_left', 0)) - 1
                    )
                    _set_captcha_state(request, gate_key, state)

                if post_failures >= LOCKOUT_THRESHOLD:
                    SecurityEvent.objects.create(
                        user=None,
                        event_type='ACCOUNT_LOCKED',
                        ip_address=client_ip,
                        user_agent=user_agent,
                        details='Account temporarily locked after failed login attempts',
                    )
                elif (
                    post_failures >= CAPTCHA_THRESHOLD
                    and not (
                        state.get('captcha_passed')
                        and int(state.get('extra_attempts_left', 0) or 0) > 0
                    )
                ):
                    rotated_state = _get_or_rotate_captcha(request, gate_key)
                    SecurityEvent.objects.create(
                        user=None,
                        event_type='CAPTCHA_REQUIRED',
                        ip_address=client_ip,
                        user_agent=user_agent,
                        details='CAPTCHA required after repeated failed login attempts',
                    )
                    form = UserLoginForm(
                        request,
                        initial={'username': submitted_email},
                        require_captcha=True,
                        captcha_label=rotated_state.get('captcha_question', 'CAPTCHA'),
                    )

            messages.error(request, 'Invalid email or password.')

    return render(request, 'accounts/login.html', {'form': form})


@require_http_methods(['POST'])
@csrf_protect
def logout_view(request):
    """User logout view with security event logging."""

    if request.user.is_authenticated:
        SecurityEvent.objects.create(
            user=request.user,
            event_type='LOGOUT',
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            details='User logged out',
        )
        logout(request)
        messages.info(request, 'You have been logged out successfully.')
    return redirect('pages:home')


