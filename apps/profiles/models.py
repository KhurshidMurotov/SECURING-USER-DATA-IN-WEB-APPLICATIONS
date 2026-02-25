"""
Profile model with encrypted sensitive fields
"""
from django.db import models
from django.contrib.auth import get_user_model
from django.conf import settings
from cryptography.fernet import Fernet

User = get_user_model()


class EncryptedTextField(models.TextField):
    """
    Custom field that encrypts data at rest using Fernet-based authenticated 
    symmetric encryption (via cryptography.fernet.Fernet).
    
    Fernet uses AES-128 in CBC mode with HMAC-SHA256 for authentication.
    This implementation is suitable for a student prototype demonstrating
    field-level encryption at rest.
    
    Data is encrypted before saving and decrypted when reading.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Get encryption key from settings
        encryption_key = getattr(settings, 'ENCRYPTION_KEY', None)
        if not encryption_key:
            raise ValueError("ENCRYPTION_KEY must be set in settings")
        
        # Ensure key is bytes
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        
        # Fernet requires base64-encoded 32-byte key
        try:
            self.cipher = Fernet(encryption_key)
        except Exception as e:
            raise ValueError(f"Invalid ENCRYPTION_KEY: {e}")
    
    def from_db_value(self, value, expression, connection):
        """Decrypt value when reading from database."""
        if value is None:
            return value
        try:
            decrypted = self.cipher.decrypt(value.encode())
            return decrypted.decode('utf-8')
        except Exception:
            # If decryption fails, return as-is (for migration purposes)
            return value
    
    def to_python(self, value):
        """Convert value to Python string."""
        if isinstance(value, str) or value is None:
            return value
        return str(value)
    
    def get_prep_value(self, value):
        """Encrypt value before saving to database."""
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        encrypted = self.cipher.encrypt(value.encode('utf-8'))
        return encrypted.decode('utf-8')


class UserProfile(models.Model):
    """
    User profile with encrypted sensitive fields.
    - phone_number: stored in plaintext (less sensitive)
    - address: encrypted at rest
    - notes: encrypted at rest
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        help_text='Phone number (stored in plaintext)'
    )
    address = EncryptedTextField(
        blank=True,
        help_text='Address (encrypted at rest)'
    )
    notes = EncryptedTextField(
        blank=True,
        help_text='Personal notes (encrypted at rest)'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f'Profile for {self.user.email}'
