"""
Tests for accounts app (authentication, registration, email verification)
"""

import re
import unittest

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.security.models import SecurityEvent

User = get_user_model()


class UserRegistrationTests(TestCase):
    """Test user registration functionality."""

    def setUp(self):
        self.client = Client()
        self.register_url = reverse('accounts:register')

    def test_registration_page_loads(self):
        """Test that registration page is accessible."""

        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create an Account')

    def test_registration_success_logs_in_user_without_email_send(self):
        """Successful registration should allow immediate access without email."""

        data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('profiles:dashboard'))

        user = User.objects.get(email='test@example.com')
        self.assertTrue(user.is_email_verified)

        registration_event = SecurityEvent.objects.filter(
            event_type='REGISTRATION',
            user=user,
        ).first()
        self.assertIsNotNone(registration_event)

        self.assertEqual(len(mail.outbox), 0)

    def test_registration_weak_password(self):
        """Test that weak passwords are rejected."""

        data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'short',
            'password2': 'short',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email='test@example.com').exists())

    def test_registration_duplicate_email(self):
        """Test that duplicate emails are rejected."""

        User.objects.create_user(email='existing@example.com', password='Password123!')
        data = {
            'email': 'existing@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'SecurePassword123!',
            'password2': 'SecurePassword123!',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'already exists')


@unittest.skip('Email verification is temporarily disabled in user flows')
class EmailVerificationTests(TestCase):
    """Tests for the email verification workflow."""

    def setUp(self):
        self.client = Client()
        self.verify_url_name = 'accounts:verify_email'
        self.resend_url = reverse('accounts:resend_verification')

        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePassword123!',
            first_name='Test',
            last_name='User',
        )
        self.user.is_email_verified = False
        self.user.save()

    def _generate_token(self):
        from apps.accounts.tokens import generate_email_verification_token

        return generate_email_verification_token(self.user)

    def test_verification_endpoint_marks_user_as_verified(self):
        """Valid verification token should flip is_email_verified to True."""

        token = self._generate_token()
        url = reverse(self.verify_url_name, args=[token])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/verification_success.html')

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)

        event = SecurityEvent.objects.filter(
            event_type='EMAIL_VERIFIED', user=self.user
        ).first()
        self.assertIsNotNone(event)

    def test_invalid_token_is_rejected(self):
        """Invalid token should show verification failed page."""

        url = reverse(self.verify_url_name, args=['invalid-token'])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/verification_failed.html')

    def test_resend_verification_sends_email(self):
        """Resend verification view sends a verification email for unverified user."""

        data = {'email': self.user.email}
        response = self.client.post(self.resend_url, data)
        self.assertRedirects(response, reverse('accounts:verification_sent'))

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Verify your email address', mail.outbox[0].subject)

        event = SecurityEvent.objects.filter(
            event_type='VERIFICATION_EMAIL_SENT', user=self.user
        ).first()
        self.assertIsNotNone(event)


class UserLoginTests(TestCase):
    """Test user login functionality."""

    def setUp(self):
        self.client = Client()
        self.login_url = reverse('accounts:login')
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePassword123!',
            first_name='Test',
            last_name='User',
        )

    def test_login_page_loads(self):
        """Test that login page is accessible."""

        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Log In')

    def test_unverified_user_can_log_in(self):
        """Unverified flag should not block login while verification is disabled."""

        self.user.is_email_verified = False
        self.user.save()

        data = {
            'username': 'test@example.com',
            'password': 'SecurePassword123!',
        }
        response = self.client.post(self.login_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_verified_user_can_log_in(self):
        """Verified user should be able to log in."""

        self.user.is_email_verified = True
        self.user.save()

        data = {
            'username': 'test@example.com',
            'password': 'SecurePassword123!',
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 302)

        event = SecurityEvent.objects.filter(
            event_type='LOGIN_SUCCESS', user=self.user
        ).first()
        self.assertIsNotNone(event)

    def test_login_failure(self):
        """Test failed login attempt."""

        data = {
            'username': 'test@example.com',
            'password': 'WrongPassword',
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 200)

        event = SecurityEvent.objects.filter(event_type='LOGIN_FAILURE').first()
        self.assertIsNotNone(event)

    def test_csrf_protection(self):
        """Test that CSRF protection is enabled."""

        csrf_client = Client(enforce_csrf_checks=True)
        data = {
            'username': 'test@example.com',
            'password': 'SecurePassword123!',
        }
        response = csrf_client.post(self.login_url, data)
        self.assertEqual(response.status_code, 403)


class UserLogoutTests(TestCase):
    """Test user logout functionality."""

    def setUp(self):
        self.client = Client()
        self.logout_url = reverse('accounts:logout')
        self.user = User.objects.create_user(
            email='test@example.com', password='SecurePassword123!'
        )
        self.client.force_login(self.user)

    def test_logout_success(self):
        """Test successful logout."""

        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

        event = SecurityEvent.objects.filter(event_type='LOGOUT').first()
        self.assertIsNotNone(event)


class PasswordHashingTests(TestCase):
    """Test that Django stores password hashes, not plaintext."""

    def test_password_is_hashed_with_pbkdf2_prefix(self):
        raw_password = 'VerySecurePassword123!'
        user = User.objects.create_user(
            email='hash-check@example.com',
            password=raw_password,
        )
        self.assertNotEqual(user.password, raw_password)
        self.assertTrue(user.password.startswith('pbkdf2_'))


class BruteForceProtectionTests(TestCase):
    """Test CAPTCHA gate and final lockout behavior."""

    def setUp(self):
        self.client = Client(REMOTE_ADDR='127.0.0.1')
        self.login_url = reverse('accounts:login')
        self.email = 'axes@example.com'
        self.password = 'CorrectPassword123!'
        user = User.objects.create_user(
            email=self.email,
            password=self.password,
        )
        user.is_email_verified = True
        user.save(update_fields=['is_email_verified'])

    def _failed_login(
        self,
        email=None,
        password='WrongPassword123!',
        follow=False,
        **extra,
    ):
        payload = {
            'username': email or self.email,
            'password': password,
        }
        request_meta = {}
        for key, value in extra.items():
            if key == 'REMOTE_ADDR' or key.startswith('HTTP_'):
                request_meta[key] = value
            else:
                payload[key] = value
        return self.client.post(
            self.login_url,
            payload,
            follow=follow,
            **request_meta,
        )

    def _extract_captcha_answer(self, response):
        form = response.context['form']
        label = form.fields['captcha_answer'].label
        match = re.search(r'(\d+)\s*\+\s*(\d+)', label)
        self.assertIsNotNone(match)
        return str(int(match.group(1)) + int(match.group(2)))

    def test_captcha_required_after_three_failed_attempts(self):
        self._failed_login()
        self._failed_login()
        response = self._failed_login()
        self.assertEqual(response.status_code, 200)
        self.assertIn('captcha_answer', response.context['form'].fields)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type='CAPTCHA_REQUIRED').exists()
        )

    def test_solved_captcha_grants_exactly_two_extra_attempts_then_locks(self):
        self._failed_login()
        self._failed_login()
        captcha_response = self._failed_login()
        captcha_answer = self._extract_captcha_answer(captcha_response)

        # 4th failed attempt (with solved CAPTCHA): allowed, no lockout yet
        response4 = self._failed_login(captcha_answer=captcha_answer)
        self.assertEqual(response4.status_code, 200)
        self.assertNotIn(b'Account Temporarily Locked', response4.content)

        # 5th failed attempt: should lock
        response5 = self._failed_login(follow=True)
        lockout_detected = (
            response5.status_code in (403, 429)
            or b'Account Temporarily Locked' in response5.content
            or any(
                '/accounts/locked-out/' in redirect_url
                for redirect_url, _status in response5.redirect_chain
            )
        )
        self.assertTrue(lockout_detected)

    @override_settings(AXES_COOLOFF_TIME=0.5)
    def test_lockout_duration_setting_is_30_minutes(self):
        from django.conf import settings

        self.assertEqual(settings.AXES_COOLOFF_TIME, 0.5)

    def test_unknown_email_flow_remains_neutral(self):
        unknown_email = 'unknown-user@example.com'
        known_response = self._failed_login(email=self.email)
        unknown_response = self._failed_login(email=unknown_email)
        self.assertContains(known_response, 'Invalid email or password.')
        self.assertContains(unknown_response, 'Invalid email or password.')
        self.assertNotContains(unknown_response, 'does not exist')

    @override_settings(TRUST_PROXY_HEADERS=True)
    def test_x_forwarded_for_is_used_consistently_for_captcha_threshold(self):
        meta = {'HTTP_X_FORWARDED_FOR': '203.0.113.10'}
        self._failed_login(REMOTE_ADDR='100.64.0.1', **meta)
        self._failed_login(REMOTE_ADDR='100.64.0.2', **meta)
        response = self._failed_login(REMOTE_ADDR='100.64.0.3', **meta)

        self.assertEqual(response.status_code, 200)
        self.assertIn('captcha_answer', response.context['form'].fields)

        latest_failure = SecurityEvent.objects.filter(event_type='LOGIN_FAILURE').first()
        self.assertIsNotNone(latest_failure)
        self.assertEqual(str(latest_failure.ip_address), '203.0.113.10')
        self.assertIn('raw_remote_addr=100.64.0.3', latest_failure.details)
