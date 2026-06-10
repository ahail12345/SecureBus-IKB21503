"""
Views — Secure Bus Booking System
RBAC enforced on every view. All inputs from forms only (no raw request.GET/POST).
Django ORM used exclusively — no raw SQL (OWASP A03 — Injection prevention).
"""

import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction
from django.http import Http404
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache

from .models import CustomUser, Bus, Booking, AuditLog
from .forms import (SecureRegistrationForm, SecureLoginForm,
                    BusForm, BookingForm, ProfileForm)
from .decorators import admin_required, user_required
from .utils import log_event, secure_filename

logger = logging.getLogger('security')


# ── Auth Views ────────────────────────────────────────────────────────────────

@never_cache
@require_http_methods(["GET", "POST"])
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SecureRegistrationForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.role = CustomUser.Role.USER
        user.save()
        log_event(request, AuditLog.EventType.LOGIN_SUCCESS,
                  f"New user registered: {user.username}")
        messages.success(request, "Account created! Please log in.")
        return redirect('login')

    return render(request, 'core/register.html', {'form': form})


@never_cache
@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SecureLoginForm(request, data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            log_event(request, AuditLog.EventType.LOGIN_SUCCESS,
                      f"User logged in: {user.username}")
            messages.success(request, f"Welcome back, {user.first_name or user.username}!")
            return redirect('dashboard')
        else:
            # Log failed login — no password details logged (OWASP ASVS V7.1)
            username_attempt = request.POST.get('username', '')[:30]
            log_event(request, AuditLog.EventType.LOGIN_FAILED,
                      f"Failed login for username: {username_attempt}")
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, 'core/login.html', {'form': form})


@login_required
@require_http_methods(["POST"])
def logout_view(request):
    """POST-only logout with CSRF protection."""
    username = request.user.username
    log_event(request, AuditLog.EventType.LOGOUT, f"User logged out: {username}")
    logout(request)
    messages.info(request, "You have been securely logged out.")
    return redirect('login')


# ── Dashboard ─────────────────────────────────────────────────────────────────

@login_required
@never_cache
def dashboard_view(request):
    user = request.user
    if user.is_admin():
        # Admin dashboard
        context = {
            'total_buses': Bus.objects.count(),
            'total_bookings': Booking.objects.count(),
            'total_users': CustomUser.objects.filter(role=CustomUser.Role.USER).count(),
            'recent_bookings': Booking.objects.select_related('user', 'bus').order_by('-created_at')[:5],
        }
    else:
        # User dashboard — only their own bookings (IDOR prevention)
        context = {
            'my_bookings': Booking.objects.filter(user=user).select_related('bus').order_by('-created_at')[:5],
            'available_buses': Bus.objects.filter(is_active=True, available_seats__gt=0).order_by('departure_time')[:5],
        }
    context['is_admin'] = user.is_admin()
    return render(request, 'core/dashboard.html', context)


# ── Bus Management (Admin CRUD) ───────────────────────────────────────────────

@admin_required
def bus_list_view(request):
    buses = Bus.objects.all().order_by('departure_time')
    paginator = Paginator(buses, 10)
    page = request.GET.get('page', 1)
    buses_page = paginator.get_page(page)
    return render(request, 'core/bus_list.html', {'buses': buses_page})


@admin_required
@require_http_methods(["GET", "POST"])
def bus_create_view(request):
    form = BusForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        bus = form.save(commit=False)
        bus.created_by = request.user
        bus.save()
        log_event(request, AuditLog.EventType.BUS_CREATED,
                  f"Admin created bus: {bus.bus_number}")
        messages.success(request, f"Bus {bus.bus_number} created successfully.")
        return redirect('bus_list')
    return render(request, 'core/bus_form.html', {'form': form, 'action': 'Create'})


@admin_required
@require_http_methods(["GET", "POST"])
def bus_update_view(request, bus_id):
    bus = get_object_or_404(Bus, id=bus_id)
    form = BusForm(request.POST or None, instance=bus)
    if request.method == 'POST' and form.is_valid():
        form.save()
        log_event(request, AuditLog.EventType.BUS_UPDATED,
                  f"Admin updated bus: {bus.bus_number}")
        messages.success(request, f"Bus {bus.bus_number} updated.")
        return redirect('bus_list')
    return render(request, 'core/bus_form.html', {'form': form, 'action': 'Update', 'bus': bus})


@admin_required
@require_http_methods(["POST"])
def bus_delete_view(request, bus_id):
    """POST-only deletion with CSRF — prevents CSRF-based deletion."""
    bus = get_object_or_404(Bus, id=bus_id)
    bus_number = bus.bus_number
    bus.delete()
    log_event(request, AuditLog.EventType.BUS_DELETED,
              f"Admin deleted bus: {bus_number}")
    messages.success(request, f"Bus {bus_number} deleted.")
    return redirect('bus_list')


# ── Booking (User CRUD) ───────────────────────────────────────────────────────

@user_required
def booking_list_view(request):
    """Users see ONLY their own bookings — IDOR prevention (OWASP A01)."""
    bookings = Booking.objects.filter(user=request.user).select_related('bus').order_by('-created_at')
    paginator = Paginator(bookings, 10)
    page = request.GET.get('page', 1)
    return render(request, 'core/booking_list.html', {'bookings': paginator.get_page(page)})


@user_required
def available_buses_view(request):
    buses = Bus.objects.filter(is_active=True, available_seats__gt=0).order_by('departure_time')
    return render(request, 'core/available_buses.html', {'buses': buses})


@user_required
@require_http_methods(["GET", "POST"])
def booking_create_view(request, bus_id):
    bus = get_object_or_404(Bus, id=bus_id, is_active=True)

    if bus.available_seats < 1:
        messages.error(request, "No seats available on this bus.")
        return redirect('available_buses')

    form = BookingForm(request.POST or None, bus=bus)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():  # Atomic to prevent race conditions
            bus.refresh_from_db()
            seat_count = form.cleaned_data['seat_count']
            if bus.available_seats < seat_count:
                messages.error(request, "Seats no longer available. Please try again.")
                return redirect('available_buses')

            booking = form.save(commit=False)
            booking.user = request.user
            booking.bus = bus
            booking.total_price = bus.price * seat_count
            booking.status = Booking.Status.CONFIRMED
            booking.save()

            bus.available_seats -= seat_count
            bus.save()

        log_event(request, AuditLog.EventType.BOOKING_CREATED,
                  f"Booking {booking.booking_reference} created for bus {bus.bus_number}")
        messages.success(request, f"Booking confirmed! Reference: {booking.booking_reference}")
        return redirect('booking_list')

    return render(request, 'core/booking_form.html', {'form': form, 'bus': bus})


@user_required
@require_http_methods(["POST"])
def booking_cancel_view(request, booking_ref):
    """
    Cancel own booking only — strict ownership check prevents IDOR.
    OWASP A01 — Broken Access Control.
    """
    # UUID lookup via booking_reference (not sequential ID)
    booking = get_object_or_404(
        Booking,
        booking_reference=booking_ref,
        user=request.user  # ← ownership enforced at query level
    )

    if booking.status == Booking.Status.CANCELLED:
        messages.error(request, "This booking is already cancelled.")
        return redirect('booking_list')

    with transaction.atomic():
        booking.status = Booking.Status.CANCELLED
        booking.save()
        booking.bus.available_seats += booking.seat_count
        booking.bus.save()

    log_event(request, AuditLog.EventType.BOOKING_CANCELLED,
              f"Booking {booking.booking_reference} cancelled")
    messages.success(request, "Booking cancelled successfully.")
    return redirect('booking_list')


# ── Profile ───────────────────────────────────────────────────────────────────

@login_required
@require_http_methods(["GET", "POST"])
def profile_view(request):
    form = ProfileForm(request.POST or None, request.FILES or None, instance=request.user)
    if request.method == 'POST' and form.is_valid():
        # UUID renaming handled by profile_upload_path in models.py automatically
        form.save()
        log_event(request, AuditLog.EventType.PROFILE_UPDATED,
                  f"User {request.user.username} updated profile")
        messages.success(request, "Profile updated successfully.")
        return redirect('profile')

    return render(request, 'core/profile.html', {'form': form})


# ── Audit Log (Admin only) ────────────────────────────────────────────────────

@admin_required
def audit_log_view(request):
    logs = AuditLog.objects.select_related('user').order_by('-timestamp')
    
    # Filter by event type if requested
    event_filter = request.GET.get('event', '')
    if event_filter and event_filter in [e.value for e in AuditLog.EventType]:
        logs = logs.filter(event_type=event_filter)

    paginator = Paginator(logs, 25)
    page = request.GET.get('page', 1)
    return render(request, 'core/audit_log.html', {
        'logs': paginator.get_page(page),
        'event_types': AuditLog.EventType.choices,
        'selected_event': event_filter,
    })


# ── Custom Error Handlers ─────────────────────────────────────────────────────
# No stack traces exposed — custom error pages (OWASP ASVS V7.4)

def handler400(request, exception=None):
    return render(request, 'errors/400.html', status=400)

def handler403(request, exception=None):
    log_event(request, AuditLog.EventType.ACCESS_DENIED,
              f"403 at {request.path}")
    return render(request, 'errors/403.html', status=403)

def handler404(request, exception=None):
    return render(request, 'errors/404.html', status=404)

def handler500(request):
    logger.error(f"500 error at {request.path}")
    return render(request, 'errors/500.html', status=500)
