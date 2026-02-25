"""
Tests for profiles app (encrypted fields, profile management)
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.profiles.models import UserProfile
from apps.security.models import SecurityEvent

User = get_user_model()


class ProfileEncryptionTests(TestCase):
    """Test that encrypted fields are actually encrypted in the database."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePassword123!'
        )
        self.profile = UserProfile.objects.get(user=self.user)
    
    def test_address_encryption(self):
        """Test that address is encrypted in database."""
        test_address = "123 Main St, City, State 12345"
        self.profile.address = test_address
        self.profile.save()
        
        # Refresh from database
        self.profile.refresh_from_db()
        
        # Value should be decrypted when reading
        self.assertEqual(self.profile.address, test_address)
        
        # But in the database, it should be encrypted (different from plaintext)
        from django.db import connection

        table_name = UserProfile._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT address FROM {table_name} WHERE id = %s", [self.profile.id]
            )
            row = cursor.fetchone()
            db_value = row[0] if row else None
        
        # Database value should be encrypted (different from plaintext)
        self.assertIsNotNone(db_value)
        self.assertNotEqual(db_value, test_address)
        # Encrypted value should start with Fernet token (base64, starts with 'gAAAAA')
        self.assertTrue(db_value.startswith('gAAAAA'))
    
    def test_notes_encryption(self):
        """Test that notes are encrypted in database."""
        test_notes = "This is sensitive personal information"
        self.profile.notes = test_notes
        self.profile.save()
        
        # Refresh from database
        self.profile.refresh_from_db()
        
        # Value should be decrypted when reading
        self.assertEqual(self.profile.notes, test_notes)
        
        # But in the database, it should be encrypted
        from django.db import connection

        table_name = UserProfile._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT notes FROM {table_name} WHERE id = %s", [self.profile.id]
            )
            row = cursor.fetchone()
            db_value = row[0] if row else None
        
        # Database value should be encrypted
        self.assertIsNotNone(db_value)
        self.assertNotEqual(db_value, test_notes)
        self.assertTrue(db_value.startswith('gAAAAA'))


class ProfileViewsTests(TestCase):
    """Test profile views and forms."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePassword123!',
            first_name='Test',
            last_name='User'
        )
        self.client.force_login(self.user)
        self.profile = UserProfile.objects.get(user=self.user)
    
    def test_dashboard_requires_login(self):
        """Test that dashboard requires authentication."""
        self.client.logout()
        response = self.client.get(reverse('profiles:dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_dashboard_displays_profile(self):
        """Test that dashboard displays user profile."""
        response = self.client.get(reverse('profiles:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user.email)
    
    def test_edit_profile_success(self):
        """Test successful profile update."""
        edit_url = reverse('profiles:edit')
        data = {
            'phone_number': '+1234567890',
            'address': '123 Test St',
            'notes': 'Test notes'
        }
        response = self.client.post(edit_url, data)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        
        # Refresh profile
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.phone_number, '+1234567890')
        self.assertEqual(self.profile.address, '123 Test St')
        self.assertEqual(self.profile.notes, 'Test notes')
        
        # Check security event was logged
        event = SecurityEvent.objects.filter(event_type='PROFILE_UPDATE').first()
        self.assertIsNotNone(event)
        self.assertEqual(event.user, self.user)
    
    def test_profile_form_validation(self):
        """Test profile form validation."""
        edit_url = reverse('profiles:edit')
        # Try to submit script tag (XSS attempt)
        data = {
            'phone_number': '+1234567890',
            'address': '<script>alert("xss")</script>',
            'notes': 'Test notes'
        }
        response = self.client.post(edit_url, data)
        # Should show validation error
        self.assertEqual(response.status_code, 200)  # Form errors, not redirect
        self.assertContains(response, 'Invalid characters')

    def test_edit_profile_requires_csrf_token(self):
        """Missing CSRF token on profile edit should return 403."""
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        edit_url = reverse('profiles:edit')
        response = csrf_client.post(
            edit_url,
            {
                'phone_number': '+1234567890',
                'address': '123 Test St',
                'notes': 'Test notes',
            },
        )
        self.assertEqual(response.status_code, 403)
