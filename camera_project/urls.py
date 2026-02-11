from django.contrib import admin
from django.urls import path, include
from camera_project import auth_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # SSO authentication
    path('api/auth/login/', auth_views.sso_login, name='sso_login'),
    path('api/auth/callback/', auth_views.sso_callback, name='sso_callback'),
    path('api/auth/logout/', auth_views.sso_logout, name='sso_logout'),
    path('login/', auth_views.login_page, name='login_page'),

    # Camera API
    path('api/', include('camera.urls')),
]
