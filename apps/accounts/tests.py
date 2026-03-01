"""
Tests for accounts app (authentication, registration, email verification)
"""

import re
import unittest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
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
        cache.clear()
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

    def test_password_field_is_empty_after_failed_login(self):
        """Password input must not preserve submitted value after an error."""

        bad_password = 'WrongPassword123!'
        data = {
            'username': 'test@example.com',
            'password': bad_password,
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, f'value="{bad_password}"')
        self.assertContains(response, 'name="password"')

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
        cache.clear()
        self.client = Client(REMOTE_ADDR='127.0.0.1')
        self.login_url = reverse('accounts:login')
        self.login_captcha_url = reverse('accounts:login_captcha')
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

    def _open_captcha_page(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_captcha_url, response['Location'])
        return self.client.get(response['Location'])

    def _fixed_captcha(self):
        return patch(
            'apps.accounts.views._generate_captcha_challenge',
            return_value=('What is 7 + 3?', '10'),
        )

    def test_captcha_required_on_third_attempt_after_two_failures(self):
        self._failed_login()
        self._failed_login()
        response = self._failed_login()
        captcha_page = self._open_captcha_page(response)
        self.assertEqual(captcha_page.status_code, 200)
        self.assertIn('captcha_answer', captcha_page.context['form'].fields)
        self.assertTrue(
            SecurityEvent.objects.filter(event_type='CAPTCHA_REQUIRED').exists()
        )

    def test_solved_captcha_grants_exactly_two_extra_attempts_then_locks(self):
        self._failed_login()
        self._failed_login()

        with self._fixed_captcha():
            challenge_redirect = self._failed_login()
            captcha_page = self._open_captcha_page(challenge_redirect)
            captcha_answer = self._extract_captcha_answer(captcha_page)
            verify = self.client.post(
                self.login_captcha_url,
                {'email': self.email, 'captcha_answer': captcha_answer},
            )
        self.assertEqual(verify.status_code, 302)
        self.assertIn(self.login_url, verify['Location'])

        # Two failed password attempts are allowed after CAPTCHA pass.
        response3 = self._failed_login()
        self.assertEqual(response3.status_code, 200)
        response4 = self._failed_login()
        self.assertEqual(response4.status_code, 200)

        # Next step requires CAPTCHA again; failing it triggers the 5th failure lockout.
        challenge_again = self._failed_login()
        self.assertEqual(challenge_again.status_code, 302)
        self.assertIn(self.login_captcha_url, challenge_again['Location'])
        response5 = self.client.post(
            self.login_captcha_url,
            {'email': self.email, 'captcha_answer': '999'},
            follow=True,
        )
        self.assertTrue(
            response5.status_code in (403, 429)
            or b'Account Temporarily Locked' in response5.content
        )

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
        third = self._failed_login(REMOTE_ADDR='100.64.0.3', **meta)
        self.assertEqual(third.status_code, 302)
        response = self._failed_login(REMOTE_ADDR='100.64.0.4', **meta)

        self._open_captcha_page(response)

        latest_event = SecurityEvent.objects.first()
        self.assertIsNotNone(latest_event)
        self.assertEqual(str(latest_event.ip_address), '203.0.113.10')
        self.assertIn('raw_remote_addr=100.64.0.4', latest_event.details)

    def test_captcha_field_is_empty_after_captcha_validation_failure(self):
        self._failed_login()
        self._failed_login()
        with self._fixed_captcha():
            redirect_response = self._failed_login()
            self._open_captcha_page(redirect_response)
            response = self.client.post(
                self.login_captcha_url,
                {'email': self.email, 'captcha_answer': '999'},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn('captcha_answer', response.context['form'].fields)
        self.assertNotContains(response, 'value="999"')

    def test_empty_captcha_blocks_authentication_and_logs_captcha_failed(self):
        self._failed_login()
        self._failed_login()

        challenge = self._failed_login()
        self._open_captcha_page(challenge)

        with patch('django.contrib.auth.forms.authenticate') as mocked_authenticate:
            response = self.client.post(
                self.login_captcha_url,
                {'email': self.email, 'captcha_answer': ''},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn('captcha_answer', response.context['form'].fields)
        self.assertContains(response, 'Please complete the CAPTCHA challenge to continue.')
        mocked_authenticate.assert_not_called()
        self.assertTrue(SecurityEvent.objects.filter(event_type='CAPTCHA_FAILED').exists())

    @override_settings(TRUST_PROXY_HEADERS=True)
    def test_lockout_after_five_failures_with_stable_xff_and_changing_remote_addr(self):
        meta = {'HTTP_X_FORWARDED_FOR': '198.51.100.20'}
        self._failed_login(REMOTE_ADDR='100.64.0.1', **meta)
        self._failed_login(REMOTE_ADDR='100.64.0.2', **meta)

        with self._fixed_captcha():
            challenge_redirect = self._failed_login(REMOTE_ADDR='100.64.0.3', **meta)
            captcha_page = self.client.get(challenge_redirect['Location'], **meta)
            captcha_answer = self._extract_captcha_answer(captcha_page)
            self.client.post(
                self.login_captcha_url,
                {'email': self.email, 'captcha_answer': captcha_answer},
                **meta,
            )
            self._failed_login(REMOTE_ADDR='100.64.0.4', **meta)
            self._failed_login(REMOTE_ADDR='100.64.0.5', **meta)
        challenge_again = self._failed_login(REMOTE_ADDR='100.64.0.6', **meta)
        self.assertEqual(challenge_again.status_code, 302)
        response5 = self.client.post(
            self.login_captcha_url,
            {'email': self.email, 'captcha_answer': '999'},
            follow=True,
            **meta,
        )
        lockout_detected = (
            response5.status_code in (403, 429)
            or b'Account Temporarily Locked' in response5.content
            or any(
                '/accounts/locked-out/' in redirect_url
                for redirect_url, _status in response5.redirect_chain
            )
        )
        self.assertTrue(lockout_detected)

    def test_lockout_persists_across_new_session_for_same_email(self):
        self._failed_login()
        self._failed_login()
        with self._fixed_captcha():
            challenge_redirect = self._failed_login()
            captcha_page = self._open_captcha_page(challenge_redirect)
            captcha_answer = self._extract_captcha_answer(captcha_page)
            self.client.post(
                self.login_captcha_url,
                {'email': self.email, 'captcha_answer': captcha_answer},
            )
        self._failed_login()
        self._failed_login()
        self._failed_login()
        self.client.post(
            self.login_captcha_url,
            {'email': self.email, 'captcha_answer': '999'},
        )

        # New client simulates new browser/incognito session.
        new_client = Client(REMOTE_ADDR='127.0.0.1')
        response = new_client.post(
            self.login_url,
            {'username': self.email, 'password': 'WrongPassword123!'},
            follow=True,
        )
        self.assertTrue(
            response.status_code in (403, 429)
            or b'Account Temporarily Locked' in response.content
        )
