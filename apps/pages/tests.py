"""Tests for pages app, including security demo behaviour."""

from django.test import TestCase
from django.urls import reverse


class SecurityDemoPageTests(TestCase):
    """Validate the /security-demo/ educational protections."""

    def setUp(self):
        self.url = reverse('pages:security_demo')

    def test_security_demo_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Security Demo')

    def test_xss_script_payload_is_blocked(self):
        response = self.client.post(
            self.url,
            {'payload': '<script>alert(1)</script>'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Blocked by validation')
        self.assertContains(response, 'potentially unsafe HTML/JavaScript payload')

    def test_xss_onerror_payload_is_blocked(self):
        response = self.client.post(
            self.url,
            {'payload': '<img src=x onerror=alert(1)>'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Blocked by validation')

    def test_safe_payload_is_escaped_not_executed(self):
        response = self.client.post(
            self.url,
            {'payload': '<b>demo</b>'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Escaped output (not executed)')
        self.assertContains(response, '&lt;b&gt;demo&lt;/b&gt;')
        self.assertNotContains(response, '<b>demo</b>', html=True)
