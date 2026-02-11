from django.contrib import admin
from .models import GoogleNestToken, CameraSnapshot, ClassificationResult


@admin.register(GoogleNestToken)
class GoogleNestTokenAdmin(admin.ModelAdmin):
    list_display = ['id', 'is_active', 'is_expired_display', 'token_expiry', 'updated_at']
    list_filter = ['is_active']
    readonly_fields = ['created_at', 'updated_at']

    def is_expired_display(self, obj):
        return obj.is_expired
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'


@admin.register(CameraSnapshot)
class CameraSnapshotAdmin(admin.ModelAdmin):
    list_display = ['id', 'camera_device_id', 'captured_at']
    list_filter = ['camera_device_id']
    readonly_fields = ['captured_at']


@admin.register(ClassificationResult)
class ClassificationResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'snapshot', 'classification', 'confidence', 'model_used', 'created_at']
    list_filter = ['classification', 'model_used']
    readonly_fields = ['created_at']
