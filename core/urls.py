from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Bus Management (Admin)
    path('manage-bus/', views.bus_list_view, name='bus_list'),
    path('manage-bus/create/', views.bus_create_view, name='bus_create'),
    path('manage-bus/<int:bus_id>/edit/', views.bus_update_view, name='bus_update'),
    path('manage-bus/<int:bus_id>/delete/', views.bus_delete_view, name='bus_delete'),

    # Bookings (User)
    path('buses/', views.available_buses_view, name='available_buses'),
    path('buses/<int:bus_id>/book/', views.booking_create_view, name='booking_create'),
    path('my-bookings/', views.booking_list_view, name='booking_list'),
    path('my-bookings/<uuid:booking_ref>/cancel/', views.booking_cancel_view, name='booking_cancel'),

    # Profile
    path('profile/', views.profile_view, name='profile'),

    # Audit Logs (Admin)
    path('audit-logs/', views.audit_log_view, name='audit_log'),
]
