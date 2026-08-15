from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('auth/', include('accounts.urls')),
    path('chat/', include('chat.urls')),
    path('admin/', include('audit.urls')),
    path('profile/', include('accounts.urls_profile')),
    path('', lambda req: redirect('lobby'), name='home'),
]

# Serve static files in development
if settings.DEBUG:
    from django.views.static import serve
    urlpatterns += [
        path('static/<path:path>', serve, {'document_root': settings.STATICFILES_DIRS[0]}),
    ]