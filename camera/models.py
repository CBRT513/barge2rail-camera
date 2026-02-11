from django.db import models
from django.utils import timezone


class GoogleNestToken(models.Model):
    """
    Stores Google SDM OAuth tokens for camera API access.
    Singleton pattern: only one active token set at a time.
    """
    access_token = models.TextField()
    refresh_token = models.TextField()
    token_expiry = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        status = "active" if self.is_active else "inactive"
        return f"GoogleNestToken ({status}, updated {self.updated_at})"

    @property
    def is_expired(self):
        if not self.token_expiry:
            return True
        return timezone.now() >= self.token_expiry

    @classmethod
    def get_active(cls):
        """Return the current active token, or None."""
        return cls.objects.filter(is_active=True).first()

    def save(self, *args, **kwargs):
        # Deactivate all other tokens when saving a new active one
        if self.is_active:
            GoogleNestToken.objects.filter(is_active=True).exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)


class CameraSnapshot(models.Model):
    """A single frame captured from a Nest camera."""
    camera_device_id = models.CharField(max_length=255)
    image_url = models.URLField(max_length=2000)
    image_token = models.CharField(max_length=500, blank=True)
    captured_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-captured_at']

    def __str__(self):
        return f"Snapshot {self.pk} ({self.captured_at})"


class ClassificationResult(models.Model):
    """Claude Vision classification of a camera snapshot."""

    CLASSIFICATION_CHOICES = [
        ('crane_active', 'Crane Active'),
        ('crane_idle', 'Crane Idle'),
        ('barge_present', 'Barge Present'),
        ('barge_absent', 'No Barge'),
        ('loading', 'Loading Operations'),
        ('unloading', 'Unloading Operations'),
        ('idle', 'Dock Idle'),
        ('obstructed', 'View Obstructed'),
        ('night', 'Nighttime/Low Visibility'),
        ('unknown', 'Unknown'),
    ]

    snapshot = models.ForeignKey(
        CameraSnapshot,
        on_delete=models.CASCADE,
        related_name='classifications',
    )
    raw_response = models.JSONField()
    classification = models.CharField(max_length=50, choices=CLASSIFICATION_CHOICES)
    confidence = models.FloatField()
    details = models.TextField(blank=True)
    model_used = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.classification} ({self.confidence:.0%}) - Snapshot {self.snapshot_id}"
