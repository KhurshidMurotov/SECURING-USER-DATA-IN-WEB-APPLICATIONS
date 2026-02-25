from django.urls import path
from . import views

app_name = 'profiles'

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('edit/', views.edit_profile_view, name='edit'),
]
