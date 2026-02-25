"""
URL configuration for secure_web project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.pages.urls')),
    path('accounts/', include('apps.accounts.urls')),
    path('profile/', include('apps.profiles.urls')),
    path('security/', include('apps.security.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

