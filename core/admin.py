from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Bus, Booking, AuditLog

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ['username', 'email', 'role', 'is_active', 'created_at']
    list_filter = ['role', 'is_active']
    fieldsets = UserAdmin.fieldsets + (
        ('Role & Security', {'fields': ('role', 'phone_number', 'is_locked')}),
    )

@admin.register(Bus)
class BusAdmin(admin.ModelAdmin):
    list_display = ['bus_number', 'route_from', 'route_to', 'departure_time', 'available_seats', 'is_active']

@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ['booking_reference', 'user', 'bus', 'seat_count', 'status', 'created_at']
    readonly_fields = ['booking_reference']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'event_type', 'user', 'ip_address']
    readonly_fields = ['timestamp', 'event_type', 'user', 'description', 'ip_address', 'user_agent']
    list_filter = ['event_type']
    ordering = ['-timestamp']

    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False
