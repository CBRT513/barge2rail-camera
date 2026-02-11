from django.urls import path
from camera import views

app_name = 'camera'

urlpatterns = [
    # Google SDM OAuth
    path('oauth/initiate/', views.oauth_initiate, name='oauth_initiate'),
    path('oauth/callback/', views.oauth_callback, name='oauth_callback'),

    # Devices
    path('devices/', views.list_devices, name='list_devices'),

    # Camera operations
    path('grab-frame/', views.grab_frame, name='grab_frame'),
    path('classify/', views.classify, name='classify'),
    path('grab-and-classify/', views.grab_and_classify, name='grab_and_classify'),

    # Health + Status
    path('health/', views.health, name='health'),
    path('status/', views.status, name='status'),
]
