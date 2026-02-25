"""
Profile forms with input validation
"""
from django import forms
from .models import UserProfile
import re


class UserProfileForm(forms.ModelForm):
    """Form for editing user profile with validation."""
    
    phone_number = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
            'placeholder': '+1 (555) 123-4567',
            'autocomplete': 'tel'
        }),
        help_text='Optional phone number'
    )
    address = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
            'rows': 3,
            'placeholder': 'Your address (will be encrypted)',
            'autocomplete': 'street-address'
        }),
        help_text='Your address will be encrypted at rest'
    )
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
            'rows': 5,
            'placeholder': 'Personal notes (will be encrypted)'
        }),
        help_text='Personal notes will be encrypted at rest'
    )
    
    class Meta:
        model = UserProfile
        fields = ('phone_number', 'address', 'notes')
    
    def clean_phone_number(self):
        """Validate phone number format (basic validation)."""
        phone = self.cleaned_data.get('phone_number')
        if phone:
            # Remove common formatting characters
            cleaned = re.sub(r'[\s\-\(\)\+]', '', phone)
            # Check if it's mostly digits
            if not cleaned.isdigit() or len(cleaned) < 10:
                raise forms.ValidationError('Please enter a valid phone number.')
        return phone
    
    def clean_address(self):
        """Basic validation for address (prevent XSS attempts)."""
        address = self.cleaned_data.get('address')
        if address:
            # Check for potential script tags (basic XSS prevention)
            if re.search(r'<script', address, re.IGNORECASE):
                raise forms.ValidationError('Invalid characters in address.')
        return address
    
    def clean_notes(self):
        """Basic validation for notes (prevent XSS attempts)."""
        notes = self.cleaned_data.get('notes')
        if notes:
            # Check for potential script tags (basic XSS prevention)
            if re.search(r'<script', notes, re.IGNORECASE):
                raise forms.ValidationError('Invalid characters in notes.')
        return notes
