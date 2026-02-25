from django.urls import path
from . import views

app_name = 'pages'

urlpatterns = [
    path('', views.home_view, name='home'),
    path('security-tips/', views.security_tips_view, name='security_tips'),
    path('security-demo/', views.security_demo_view, name='security_demo'),
]
