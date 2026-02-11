from django.test import TestCase
from django.utils import timezone
from datetime import timedelta

from .models import GoogleNestToken, CameraSnapshot, ClassificationResult


class GoogleNestTokenTests(TestCase):
    def test_is_expired_when_no_expiry(self):
        token = GoogleNestToken(access_token='a', refresh_token='r')
        self.assertTrue(token.is_expired)

    def test_is_expired_when_past(self):
        token = GoogleNestToken(
            access_token='a',
            refresh_token='r',
            token_expiry=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(token.is_expired)

    def test_is_not_expired_when_future(self):
        token = GoogleNestToken(
            access_token='a',
            refresh_token='r',
            token_expiry=timezone.now() + timedelta(hours=1),
        )
        self.assertFalse(token.is_expired)

    def test_singleton_deactivates_others(self):
        t1 = GoogleNestToken.objects.create(
            access_token='a1', refresh_token='r1', is_active=True
        )
        t2 = GoogleNestToken.objects.create(
            access_token='a2', refresh_token='r2', is_active=True
        )
        t1.refresh_from_db()
        self.assertFalse(t1.is_active)
        self.assertTrue(t2.is_active)

    def test_get_active_returns_active_token(self):
        GoogleNestToken.objects.create(
            access_token='a1', refresh_token='r1', is_active=False
        )
        t2 = GoogleNestToken.objects.create(
            access_token='a2', refresh_token='r2', is_active=True
        )
        self.assertEqual(GoogleNestToken.get_active(), t2)

    def test_get_active_returns_none_when_none(self):
        self.assertIsNone(GoogleNestToken.get_active())
