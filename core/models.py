"""
Models — Secure Bus Booking System
OWASP ASVS V2 (Auth), V4 (Access Control), V7 (Logging)
"""

import uuid
import os
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


def profile_upload_path(instance, filename):
    """
    Rename uploaded profile pictures to UUID at save time.
    Prevents path traversal, overwrite attacks, and filename enumeration.
    OWASP File Upload Security — PW.7
    """
    ext = os.path.splitext(filename)[1].lower()
    return f"profiles/{uuid.uuid4().hex}{ext}"


class CustomUser(AbstractUser):
    """Extended user model with role-based access control (RBAC)."""

    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Admin'
        USER = 'USER', 'User'

    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)
    phone_number = models.CharField(max_length=15, blank=True)
    profile_picture = models.ImageField(
        upload_to=profile_upload_path, blank=True, null=True  # UUID rename on every upload
    )
    is_locked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_admin(self):
        return self.role == self.Role.ADMIN

    def __str__(self):
        return f"{self.username} ({self.role})"


class Bus(models.Model):
    """Bus entity managed by admin."""
    bus_number = models.CharField(max_length=20, unique=True)
    route_from = models.CharField(max_length=100)
    route_to = models.CharField(max_length=100)
    departure_time = models.DateTimeField()
    arrival_time = models.DateTimeField()
    total_seats = models.PositiveIntegerField()
    available_seats = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=8, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, related_name='buses_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['departure_time']

    def __str__(self):
        return f"Bus {self.bus_number}: {self.route_from} → {self.route_to}"


class Booking(models.Model):
    """Booking entity — belongs strictly to one user (prevents IDOR)."""

    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        CONFIRMED = 'CONFIRMED', 'Confirmed'
        CANCELLED = 'CANCELLED', 'Cancelled'

    # UUID prevents IDOR — no sequential IDs exposed (OWASP A01)
    booking_reference = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='bookings')
    bus = models.ForeignKey(Bus, on_delete=models.CASCADE, related_name='bookings')
    seat_count = models.PositiveIntegerField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    passenger_name = models.CharField(max_length=150)
    passenger_ic = models.CharField(max_length=20)  # IC / passport
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Booking {self.booking_reference} by {self.user.username}"


class AuditLog(models.Model):
    """Security audit log — records all important security events (OWASP ASVS V7)."""

    class EventType(models.TextChoices):
        LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Login Success'
        LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'
        LOGOUT = 'LOGOUT', 'Logout'
        BOOKING_CREATED = 'BOOKING_CREATED', 'Booking Created'
        BOOKING_CANCELLED = 'BOOKING_CANCELLED', 'Booking Cancelled'
        BOOKING_UPDATED = 'BOOKING_UPDATED', 'Booking Updated'
        ACCESS_DENIED = 'ACCESS_DENIED', 'Access Denied'
        PROFILE_UPDATED = 'PROFILE_UPDATED', 'Profile Updated'
        PASSWORD_CHANGED = 'PASSWORD_CHANGED', 'Password Changed'
        ADMIN_ACTION = 'ADMIN_ACTION', 'Admin Action'
        BUS_CREATED = 'BUS_CREATED', 'Bus Created'
        BUS_UPDATED = 'BUS_UPDATED', 'Bus Updated'
        BUS_DELETED = 'BUS_DELETED', 'Bus Deleted'
        FILE_UPLOAD = 'FILE_UPLOAD', 'File Upload'
        SUSPICIOUS = 'SUSPICIOUS', 'Suspicious Activity'

    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs'
    )
    event_type = models.CharField(max_length=30, choices=EventType.choices)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    # NO sensitive data stored here (OWASP ASVS V7.1)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp}] {self.event_type} — {self.user}"
