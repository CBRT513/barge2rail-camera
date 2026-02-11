"""
Google Smart Device Management (SDM) API client.

Handles OAuth flow, token management, and camera image capture
for Google Nest cameras via the SDM API.
"""

import time
import logging
from datetime import timedelta
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.utils import timezone

from camera.models import GoogleNestToken

logger = logging.getLogger('camera.sdm_client')

SDM_API_BASE = 'https://smartdevicemanagement.googleapis.com/v1'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_AUTH_URL = 'https://nestservices.google.com/partnerconnections/{project_id}/auth'


class SDMError(Exception):
    """Base exception for SDM API errors."""
    pass


class SDMTokenError(SDMError):
    """Token-related errors (missing, expired, refresh failed)."""
    pass


class SDMClient:
    """Client for Google Smart Device Management API."""

    MAX_RETRIES = 3
    BACKOFF_BASE = 1  # seconds

    def get_authorization_url(self):
        """Generate the Google OAuth consent URL for SDM access."""
        project_id = settings.GOOGLE_SDM_PROJECT_ID
        if not project_id:
            raise SDMError("GOOGLE_SDM_PROJECT_ID not configured")

        params = {
            'redirect_uri': settings.SDM_OAUTH_REDIRECT_URI,
            'access_type': 'offline',
            'prompt': 'consent',
            'client_id': settings.GOOGLE_CLIENT_ID,
            'response_type': 'code',
            'scope': 'https://www.googleapis.com/auth/sdm.service',
        }

        base_url = GOOGLE_AUTH_URL.format(project_id=project_id)
        return f"{base_url}?{urlencode(params)}"

    def exchange_code(self, authorization_code):
        """
        Exchange authorization code for access + refresh tokens.
        Stores tokens in the database.
        """
        data = {
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'code': authorization_code,
            'grant_type': 'authorization_code',
            'redirect_uri': settings.SDM_OAUTH_REDIRECT_URI,
        }

        response = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=10)
        if not response.ok:
            logger.error(f"Token exchange failed: {response.status_code} {response.text}")
            raise SDMTokenError(f"Token exchange failed: {response.status_code}")

        token_data = response.json()
        expires_in = token_data.get('expires_in', 3600)

        token = GoogleNestToken.objects.create(
            access_token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token', ''),
            token_expiry=timezone.now() + timedelta(seconds=expires_in),
            is_active=True,
        )

        logger.info("Google SDM tokens stored successfully")
        return token

    def _get_valid_token(self):
        """Get a valid (non-expired) access token, refreshing if needed."""
        token = GoogleNestToken.get_active()
        if not token:
            raise SDMTokenError("No active Google token. Complete OAuth flow first.")

        if not token.refresh_token:
            raise SDMTokenError("No refresh token available. Re-authorize via OAuth.")

        if token.is_expired:
            self._refresh_token(token)

        return token

    def _refresh_token(self, token):
        """Refresh an expired access token."""
        data = {
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'refresh_token': token.refresh_token,
            'grant_type': 'refresh_token',
        }

        response = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=10)
        if not response.ok:
            logger.error(f"Token refresh failed: {response.status_code} {response.text}")
            raise SDMTokenError(f"Token refresh failed: {response.status_code}")

        token_data = response.json()
        expires_in = token_data.get('expires_in', 3600)

        token.access_token = token_data['access_token']
        token.token_expiry = timezone.now() + timedelta(seconds=expires_in)
        # Refresh tokens may be rotated
        if 'refresh_token' in token_data:
            token.refresh_token = token_data['refresh_token']
        token.save()

        logger.info("Google SDM token refreshed successfully")

    def _api_request(self, method, url, **kwargs):
        """
        Make an authenticated SDM API request with exponential backoff.
        Automatically refreshes tokens on 401.
        """
        token = self._get_valid_token()

        for attempt in range(self.MAX_RETRIES):
            headers = {
                'Authorization': f'Bearer {token.access_token}',
                'Content-Type': 'application/json',
            }

            try:
                logger.info(f"SDM API {method} {url}")
                logger.info(f"SDM API headers: Authorization: Bearer {token.access_token[:10]}..., Content-Type: application/json")
                if 'json' in kwargs:
                    logger.info(f"SDM API body: {kwargs['json']}")

                response = requests.request(
                    method, url, headers=headers, timeout=30, **kwargs
                )

                if not response.ok:
                    logger.error(f"SDM API response {response.status_code}: {response.text[:500]}")

                if response.status_code == 401 and attempt < self.MAX_RETRIES - 1:
                    logger.warning("SDM API returned 401, refreshing token")
                    self._refresh_token(token)
                    continue

                if response.status_code == 429 and attempt < self.MAX_RETRIES - 1:
                    wait = self.BACKOFF_BASE * (2 ** attempt)
                    logger.warning(f"SDM API rate limited, waiting {wait}s")
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                return response

            except requests.exceptions.Timeout:
                if attempt < self.MAX_RETRIES - 1:
                    wait = self.BACKOFF_BASE * (2 ** attempt)
                    logger.warning(f"SDM API timeout, retrying in {wait}s")
                    time.sleep(wait)
                    continue
                raise SDMError("SDM API request timed out after retries")

            except requests.exceptions.RequestException as e:
                if attempt < self.MAX_RETRIES - 1:
                    wait = self.BACKOFF_BASE * (2 ** attempt)
                    logger.warning(f"SDM API error: {e}, retrying in {wait}s")
                    time.sleep(wait)
                    continue
                raise SDMError(f"SDM API request failed: {e}")

    def list_devices(self):
        """List all devices in the SDM project."""
        project_id = settings.GOOGLE_SDM_PROJECT_ID
        url = f"{SDM_API_BASE}/enterprises/{project_id}/devices"
        response = self._api_request('GET', url)
        return response.json().get('devices', [])

    def generate_rtsp_stream(self, device_id=None):
        """
        Generate an RTSP stream URL using the CameraLiveStream trait.

        Returns dict with 'streamUrl' and 'streamToken'.
        """
        device_id = device_id or settings.DEFAULT_CAMERA_DEVICE_ID
        if not device_id:
            raise SDMError("No camera device ID configured")

        project_id = settings.GOOGLE_SDM_PROJECT_ID
        url = f"{SDM_API_BASE}/enterprises/{project_id}/devices/{device_id}:executeCommand"

        payload = {
            'command': 'sdm.devices.commands.CameraLiveStream.GenerateRtspStream',
        }

        response = self._api_request('POST', url, json=payload)
        result = response.json().get('results', {})

        stream_url = result.get('streamUrls', {}).get('rtspUrl')
        stream_token = result.get('streamToken')

        if not stream_url:
            raise SDMError("No RTSP URL in GenerateRtspStream response")

        return {
            'stream_url': stream_url,
            'stream_token': stream_token,
        }

    def grab_frame(self, device_id=None):
        """
        Grab a single frame from the camera's RTSP stream using ffmpeg.

        Returns JPEG image bytes.
        """
        import subprocess
        import tempfile
        import os

        stream_data = self.generate_rtsp_stream(device_id)
        rtsp_url = stream_data['stream_url']

        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [
                    'ffmpeg',
                    '-y',                   # overwrite output
                    '-rtsp_transport', 'tcp',
                    '-i', rtsp_url,
                    '-frames:v', '1',       # grab one frame
                    '-q:v', '2',            # JPEG quality
                    tmp_path,
                ],
                capture_output=True,
                timeout=30,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode('utf-8', errors='replace')[-500:]
                logger.error(f"ffmpeg failed: {stderr}")
                raise SDMError(f"ffmpeg failed to grab frame (exit {result.returncode})")

            with open(tmp_path, 'rb') as f:
                image_bytes = f.read()

            if not image_bytes:
                raise SDMError("ffmpeg produced empty output")

            logger.info(f"Frame grabbed successfully ({len(image_bytes)} bytes)")
            return image_bytes

        except subprocess.TimeoutExpired:
            raise SDMError("ffmpeg timed out grabbing frame from RTSP stream")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
