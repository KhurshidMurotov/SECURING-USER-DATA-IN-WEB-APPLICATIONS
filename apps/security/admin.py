from django.contrib import admin
from .models import SecurityEvent


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    """Admin interface for security events."""
    list_display = ('event_type', 'user', 'ip_address', 'timestamp', 'details')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('user__email', 'ip_address', 'details')
    readonly_fields = ('user', 'event_type', 'ip_address', 'user_agent', 'details', 'timestamp')
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        """Prevent manual creation of security events."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Prevent modification of security events."""
        return False

