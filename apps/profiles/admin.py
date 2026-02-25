from django.contrib import admin
from .models import UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for user profiles."""
    list_display = ('user', 'phone_number', 'created_at', 'updated_at')
    search_fields = ('user__email', 'phone_number')
    readonly_fields = ('created_at', 'updated_at')
    
    # Note: address and notes will show encrypted values in admin
    # This is intentional to demonstrate encryption at rest
