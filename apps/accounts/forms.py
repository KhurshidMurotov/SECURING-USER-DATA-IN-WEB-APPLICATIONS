"""
Authentication forms with strong validation
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.core.exceptions import ValidationError

from .models import User


class UserRegistrationForm(UserCreationForm):
    """Registration form with email as username and strong password validation."""

    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'your.email@example.com',
                'autocomplete': 'email',
            }
        ),
        help_text="We'll never share your email with anyone else.",
    )
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'First Name',
                'autocomplete': 'given-name',
            }
        ),
    )
    last_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'Last Name',
                'autocomplete': 'family-name',
            }
        ),
    )
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'Create a strong password',
                'autocomplete': 'new-password',
            }
        ),
        help_text='Must be at least 12 characters long and not too common.',
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'Confirm your password',
                'autocomplete': 'new-password',
            }
        ),
    )

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password1', 'password2')

    def clean_email(self):
        """Validate email uniqueness."""

        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError('A user with this email already exists.')
        return email

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove default help text, we'll show our own
        for field_name in self.fields:
            self.fields[field_name].help_text = None


class UserLoginForm(AuthenticationForm):
    """Login form with email and password."""

    username = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'your.email@example.com',
                'autocomplete': 'email',
            }
        ),
    )
    password = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'Enter your password',
                'autocomplete': 'current-password',
            }
        ),
    )

    def __init__(self, *args, **kwargs):
        require_captcha = kwargs.pop('require_captcha', False)
        self.require_captcha = require_captcha
        captcha_label = kwargs.pop('captcha_label', 'CAPTCHA')
        super().__init__(*args, **kwargs)
        # Use email field for authentication
        self.fields['username'].label = 'Email'
        if require_captcha:
            self.fields['captcha_answer'] = forms.CharField(
                label=captcha_label,
                required=True,
                widget=forms.TextInput(
                    attrs={
                        'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                        'placeholder': 'Enter CAPTCHA answer',
                        'autocomplete': 'off',
                    }
                ),
            )

    def clean_captcha_answer(self):
        """Server-side validation for dynamically attached CAPTCHA field."""

        if not self.require_captcha:
            return self.cleaned_data.get('captcha_answer', '')

        answer = (self.cleaned_data.get('captcha_answer') or '').strip()
        if not answer:
            raise ValidationError('This field is required.')
        return answer


class ResendVerificationForm(forms.Form):
    """Form for requesting a new verification email."""

    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'your.email@example.com',
                'autocomplete': 'email',
            }
        ),
    )


class CaptchaChallengeForm(forms.Form):
    """Standalone CAPTCHA form used in the dedicated challenge page."""

    captcha_answer = forms.CharField(
        label='CAPTCHA',
        required=True,
        widget=forms.TextInput(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent',
                'placeholder': 'Enter CAPTCHA answer',
                'autocomplete': 'off',
            }
        ),
    )

    def clean_captcha_answer(self):
        answer = (self.cleaned_data.get('captcha_answer') or '').strip()
        if not answer:
            raise ValidationError('This field is required.')
        return answer
