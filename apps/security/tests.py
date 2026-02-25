"""
Tests for security app (audit logging, dashboard)
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.security.models import SecurityEvent

User = get_user_model()


class SecurityEventTests(TestCase):
    """Test security event logging."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePassword123!'
        )
    
    def test_security_event_creation(self):
        """Test creating security events."""
        event = SecurityEvent.objects.create(
            user=self.user,
            event_type='LOGIN_SUCCESS',
            ip_address='127.0.0.1',
            details='Test login'
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.event_type, 'LOGIN_SUCCESS')
    
    def test_security_event_ordering(self):
        """Test that events are ordered by timestamp (newest first)."""
        event1 = SecurityEvent.objects.create(
            user=self.user,
            event_type='LOGIN_SUCCESS',
            details='First event'
        )
        event2 = SecurityEvent.objects.create(
            user=self.user,
            event_type='LOGIN_SUCCESS',
            details='Second event'
        )
        
        events = list(SecurityEvent.objects.all())
        self.assertEqual(events[0], event2)  # Newest first
        self.assertEqual(events[1], event1)


class SecurityDashboardTests(TestCase):
    """Test security dashboard views."""
    
    def setUp(self):
        self.client = Client()
        # Create staff user
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='SecurePassword123!',
            is_staff=True
        )
        # Create regular user
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='SecurePassword123!'
        )
        # Create some security events
        SecurityEvent.objects.create(
            user=self.regular_user,
            event_type='LOGIN_SUCCESS',
            ip_address='127.0.0.1',
            details='Login'
        )
        SecurityEvent.objects.create(
            user=None,
            event_type='LOGIN_FAILURE',
            ip_address='192.168.1.1',
            details='Failed login'
        )
    
    def test_dashboard_requires_staff(self):
        """Test that dashboard requires staff permission."""
        self.client.force_login(self.regular_user)
        response = self.client.get(reverse('security:dashboard'))
        self.assertEqual(response.status_code, 403)  # Forbidden

    def test_dashboard_requires_authentication(self):
        """Anonymous users should be redirected to login."""
        response = self.client.get(reverse('security:dashboard'))
        self.assertEqual(response.status_code, 302)
    
    def test_dashboard_accessible_by_staff(self):
        """Test that staff can access dashboard."""
        self.client.force_login(self.staff_user)
        response = self.client.get(reverse('security:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Security Dashboard')
        self.assertContains(response, 'LOGIN_SUCCESS')
        self.assertContains(response, 'LOGIN_FAILURE')
