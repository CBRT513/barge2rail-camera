"""
Anthropic Claude Vision classification service.

Sends camera snapshots to Claude for dock activity classification.
"""

import base64
import json
import time
import logging

import anthropic
from django.conf import settings

logger = logging.getLogger('camera.vision')

MAX_RETRIES = 3
BACKOFF_BASE = 2  # seconds

CLASSIFICATION_PROMPT = """Analyze this dock camera image and classify the current dock activity.

Return a JSON object with these fields:
{
    "classification": "<one of: crane_active, crane_idle, barge_present, barge_absent, loading, unloading, idle, obstructed, night, unknown>",
    "confidence": <float 0.0-1.0>,
    "details": "<brief description of what you see>",
    "objects_detected": ["<list of notable objects>"],
    "weather_conditions": "<clear, overcast, rain, fog, night, etc.>"
}

Classification definitions:
- crane_active: Crane is moving or operating
- crane_idle: Crane is visible but not moving
- barge_present: Barge is docked but no loading/unloading
- barge_absent: No barge at the dock
- loading: Active loading operations (crane moving cargo onto barge)
- unloading: Active unloading operations (crane removing cargo from barge)
- idle: Dock is empty/inactive, no notable activity
- obstructed: Camera view is blocked or unclear
- night: Nighttime or too dark to classify
- unknown: Cannot determine activity

Respond with ONLY the JSON object, no other text."""


def classify_image(image_bytes, media_type='image/jpeg'):
    """
    Classify a dock camera image using Claude Vision.

    Args:
        image_bytes: Raw image bytes
        media_type: MIME type of the image (default: image/jpeg)

    Returns:
        dict with keys: success, classification, confidence, details, raw_response, error
    """
    api_key = settings.ANTHROPIC_API_KEY
    if not api_key:
        return {
            'success': False,
            'error': 'ANTHROPIC_API_KEY not configured',
        }

    model = settings.ANTHROPIC_MODEL
    image_b64 = base64.standard_b64encode(image_bytes).decode('utf-8')

    client = anthropic.Anthropic(api_key=api_key)

    for attempt in range(MAX_RETRIES):
        try:
            message = client.messages.create(
                model=model,
                max_tokens=1024,
                messages=[
                    {
                        'role': 'user',
                        'content': [
                            {
                                'type': 'image',
                                'source': {
                                    'type': 'base64',
                                    'media_type': media_type,
                                    'data': image_b64,
                                },
                            },
                            {
                                'type': 'text',
                                'text': CLASSIFICATION_PROMPT,
                            },
                        ],
                    }
                ],
            )

            raw_text = message.content[0].text
            logger.info(f"Claude Vision response received ({len(raw_text)} chars)")

            # Parse JSON response
            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                start = raw_text.find('{')
                end = raw_text.rfind('}') + 1
                if start >= 0 and end > start:
                    parsed = json.loads(raw_text[start:end])
                else:
                    return {
                        'success': False,
                        'error': f'Failed to parse Claude response as JSON',
                        'raw_response': raw_text,
                    }

            return {
                'success': True,
                'classification': parsed.get('classification', 'unknown'),
                'confidence': float(parsed.get('confidence', 0.0)),
                'details': parsed.get('details', ''),
                'raw_response': parsed,
                'model_used': model,
            }

        except anthropic.RateLimitError:
            if attempt < MAX_RETRIES - 1:
                wait = BACKOFF_BASE * (2 ** attempt)
                logger.warning(f"Anthropic rate limited, waiting {wait}s")
                time.sleep(wait)
                continue
            return {
                'success': False,
                'error': 'Anthropic API rate limited after retries',
            }

        except anthropic.APITimeoutError:
            if attempt < MAX_RETRIES - 1:
                wait = BACKOFF_BASE * (2 ** attempt)
                logger.warning(f"Anthropic API timeout, retrying in {wait}s")
                time.sleep(wait)
                continue
            return {
                'success': False,
                'error': 'Anthropic API timed out after retries',
            }

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            return {
                'success': False,
                'error': f'Anthropic API error: {str(e)}',
            }

        except Exception as e:
            logger.error(f"Unexpected error in classify_image: {e}", exc_info=True)
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
            }
