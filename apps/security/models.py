"""
Security audit logging models
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class SecurityEvent(models.Model):
    """Model for logging security-relevant events."""

    EVENT_TYPES = [
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILURE', 'Login Failure'),
        ('LOGOUT', 'Logout'),
        ('REGISTRATION', 'Registration'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PROFILE_UPDATE', 'Profile Update'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
        ('RATE_LIMIT_EXCEEDED', 'Rate Limit Exceeded'),
        ('VERIFICATION_EMAIL_SENT', 'Verification Email Sent'),
        ('EMAIL_VERIFIED', 'Email Verified'),
        ('CAPTCHA_REQUIRED', 'CAPTCHA Required'),
        ('CAPTCHA_FAILED', 'CAPTCHA Failed'),
        ('CAPTCHA_PASSED', 'CAPTCHA Passed'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        (
            'LOGIN_BLOCKED_UNVERIFIED',
            'Login Blocked - Email Not Verified',
        ),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events',
    )
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'event_type']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]

    def __str__(self):
        user_str = self.user.email if self.user else 'Anonymous'
        return f'{self.event_type} - {user_str} - {self.timestamp}'
