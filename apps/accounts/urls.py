from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('login/captcha/', views.login_captcha_view, name='login_captcha'),
    path('logout/', views.logout_view, name='logout'),
    path(
        'locked-out/',
        TemplateView.as_view(template_name='accounts/locked_out.html'),
        name='locked_out',
    ),
    path(
        'verification-sent/',
        views.verification_sent_view,
        name='verification_sent',
    ),
    path(
        'verify/<str:token>/',
        views.verify_email_view,
        name='verify_email',
    ),
    path(
        'resend-verification/',
        views.resend_verification_view,
        name='resend_verification',
    ),
]


