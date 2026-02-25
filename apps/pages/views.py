"""
Pages app views (landing, security tips)
"""
from django import forms
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods


class SecurityDemoXSSForm(forms.Form):
    """Simple form for demonstrating XSS-safe handling."""

    payload = forms.CharField(
        label='Payload',
        max_length=500,
        widget=forms.Textarea(
            attrs={
                'class': 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm',
                'rows': 3,
                'placeholder': '<script>alert(1)</script>',
            }
        ),
    )

    def clean_payload(self):
        """Block obviously dangerous HTML/JS payloads for demo safety."""
        payload = self.cleaned_data['payload']
        lowered = payload.lower()
        blocked_markers = ('<script', 'onerror=', 'onload=', 'javascript:')
        if any(marker in lowered for marker in blocked_markers):
            raise forms.ValidationError(
                'Blocked by validation: potentially unsafe HTML/JavaScript payload.'
            )
        return payload


def home_view(request):
    """Landing page with project description."""
    return render(request, 'pages/home.html')


def security_tips_view(request):
    """Security tips educational page."""
    return render(request, 'pages/security_tips.html')


@require_http_methods(['GET', 'POST'])
@csrf_protect
def security_demo_view(request):
    """Educational security demo page for key controls."""
    form = SecurityDemoXSSForm()
    result_message = None
    submitted_payload = None

    if request.method == 'POST':
        form = SecurityDemoXSSForm(request.POST)
        if form.is_valid():
            submitted_payload = form.cleaned_data['payload']
            result_message = 'Escaped output (not executed)'
        else:
            result_message = 'Blocked by validation'

    return render(
        request,
        'pages/security_demo.html',
        {
            'form': form,
            'result_message': result_message,
            'submitted_payload': submitted_payload,
        },
    )
