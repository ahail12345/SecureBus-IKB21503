from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
    path('', lambda req: redirect('login'), name='home'),
]

# Serve media files in development regardless of DEBUG
# In production, use Nginx/Apache to serve media instead
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers — no stack traces (OWASP ASVS V7.4)
handler400 = 'core.views.handler400'
handler403 = 'core.views.handler403'
handler404 = 'core.views.handler404'
handler500 = 'core.views.handler500'
