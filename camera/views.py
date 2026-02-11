"""
Camera API views.

All endpoints require SSO authentication.
Google SDM OAuth endpoints are admin-only.
"""

import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django_ratelimit.decorators import ratelimit

from camera_project.decorators import require_role
from camera.models import GoogleNestToken, CameraSnapshot, ClassificationResult
from camera.services.sdm_client import SDMClient, SDMError, SDMTokenError
from camera.services.vision import classify_image

logger = logging.getLogger('camera.views')


# --- Google SDM OAuth ---

@login_required
@require_role('Admin')
def oauth_initiate(request):
    """Start Google SDM OAuth flow. Admin only. GET redirects to Google consent."""
    try:
        client = SDMClient()
        auth_url = client.get_authorization_url()
        if request.method == 'GET':
            return redirect(auth_url)
        return JsonResponse({'authorization_url': auth_url})
    except SDMError as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_role('Admin')
@require_GET
def list_devices(request):
    """List all devices in the SDM project."""
    try:
        client = SDMClient()
        devices = client.list_devices()
        device_list = []
        for d in devices:
            traits = d.get('traits', {})
            name = traits.get('sdm.devices.traits.Info', {}).get('customName', '')
            device_list.append({
                'device_id': d.get('name', '').split('/')[-1],
                'full_name': d.get('name', ''),
                'type': d.get('type', ''),
                'custom_name': name,
                'traits': list(traits.keys()),
            })
        return JsonResponse({'devices': device_list})
    except SDMTokenError as e:
        return JsonResponse({'error': str(e), 'hint': 'Complete OAuth flow first'}, status=401)
    except SDMError as e:
        return JsonResponse({'error': str(e)}, status=502)


@csrf_exempt
def oauth_callback(request):
    """Handle Google OAuth callback. No auth required (Google redirects here)."""
    code = request.GET.get('code')
    error = request.GET.get('error')

    if error:
        logger.error(f"Google OAuth error: {error}")
        return JsonResponse({'error': f'Google OAuth error: {error}'}, status=400)

    if not code:
        return JsonResponse({'error': 'No authorization code received'}, status=400)

    try:
        client = SDMClient()
        token = client.exchange_code(code)
        return JsonResponse({
            'success': True,
            'message': 'Google SDM tokens stored successfully',
            'token_expiry': token.token_expiry.isoformat() if token.token_expiry else None,
        })
    except SDMTokenError as e:
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"OAuth callback error: {e}", exc_info=True)
        return JsonResponse({'error': 'Token exchange failed'}, status=500)


# --- Camera Operations ---

@login_required
@ratelimit(key='user', rate='10/m', method='GET')
@require_GET
def grab_frame(request):
    """Grab a frame from the configured Nest camera via RTSP stream."""
    try:
        client = SDMClient()
        device_id = request.GET.get('device_id') or settings.DEFAULT_CAMERA_DEVICE_ID

        image_bytes = client.grab_frame(device_id)

        snapshot = CameraSnapshot.objects.create(
            camera_device_id=device_id,
            image_url='rtsp://stream',
            image_token='',
        )

        return JsonResponse({
            'success': True,
            'snapshot_id': snapshot.id,
            'image_size': len(image_bytes),
            'captured_at': snapshot.captured_at.isoformat(),
        })

    except SDMTokenError as e:
        return JsonResponse({'error': str(e), 'hint': 'Complete OAuth flow first'}, status=401)
    except SDMError as e:
        return JsonResponse({'error': str(e)}, status=502)
    except Exception as e:
        logger.error(f"grab_frame error: {e}", exc_info=True)
        return JsonResponse({'error': 'Failed to grab frame'}, status=500)


@login_required
@ratelimit(key='user', rate='3/m', method='GET')
@require_GET
def grab_and_classify(request):
    """Grab a frame via RTSP and classify it in one call."""
    try:
        client = SDMClient()
        device_id = request.GET.get('device_id') or settings.DEFAULT_CAMERA_DEVICE_ID

        # Grab frame from RTSP stream
        image_bytes = client.grab_frame(device_id)

        snapshot = CameraSnapshot.objects.create(
            camera_device_id=device_id,
            image_url='rtsp://stream',
            image_token='',
        )

        # Classify
        result = classify_image(image_bytes)

        if not result.get('success'):
            return JsonResponse({
                'success': False,
                'snapshot_id': snapshot.id,
                'error': result.get('error', 'Classification failed'),
            }, status=502)

        classification = ClassificationResult.objects.create(
            snapshot=snapshot,
            raw_response=result['raw_response'],
            classification=result['classification'],
            confidence=result['confidence'],
            details=result.get('details', ''),
            model_used=result.get('model_used', ''),
        )

        return JsonResponse({
            'success': True,
            'snapshot_id': snapshot.id,
            'captured_at': snapshot.captured_at.isoformat(),
            'classification_id': classification.id,
            'classification': classification.classification,
            'confidence': classification.confidence,
            'details': classification.details,
            'model_used': classification.model_used,
            'raw_response': result['raw_response'],
        })

    except SDMTokenError as e:
        return JsonResponse({'error': str(e), 'hint': 'Complete OAuth flow first'}, status=401)
    except SDMError as e:
        return JsonResponse({'error': str(e)}, status=502)
    except Exception as e:
        logger.error(f"grab_and_classify error: {e}", exc_info=True)
        return JsonResponse({'error': 'Failed to grab and classify'}, status=500)


# --- Health / Status ---

def health(request):
    """Unauthenticated health check for load balancers."""
    return JsonResponse({'status': 'healthy'})


@login_required
@require_GET
def status(request):
    """Authenticated status endpoint with system health details."""
    # Token status
    active_token = GoogleNestToken.get_active()
    token_info = None
    if active_token:
        token_info = {
            'has_token': True,
            'is_expired': active_token.is_expired,
            'token_expiry': active_token.token_expiry.isoformat() if active_token.token_expiry else None,
            'updated_at': active_token.updated_at.isoformat(),
        }
    else:
        token_info = {
            'has_token': False,
            'is_expired': None,
            'token_expiry': None,
            'updated_at': None,
        }

    # Anthropic config
    anthropic_info = {
        'configured': bool(settings.ANTHROPIC_API_KEY),
        'model': settings.ANTHROPIC_MODEL,
    }

    # Camera config
    camera_info = {
        'default_device_id': settings.DEFAULT_CAMERA_DEVICE_ID or None,
        'sdm_project_id': bool(settings.GOOGLE_SDM_PROJECT_ID),
    }

    # Counts
    snapshot_count = CameraSnapshot.objects.count()
    classification_count = ClassificationResult.objects.count()

    # Last activity
    last_snapshot = CameraSnapshot.objects.first()
    last_classification = ClassificationResult.objects.first()

    return JsonResponse({
        'status': 'healthy',
        'google_token': token_info,
        'anthropic': anthropic_info,
        'camera': camera_info,
        'counts': {
            'snapshots': snapshot_count,
            'classifications': classification_count,
        },
        'last_activity': {
            'last_snapshot': last_snapshot.captured_at.isoformat() if last_snapshot else None,
            'last_classification': last_classification.created_at.isoformat() if last_classification else None,
        },
    })
