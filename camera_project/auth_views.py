"""
OAuth/SSO authentication views for barge2rail-camera.

Handles OAuth flow with barge2rail-auth SSO system.
Adapted from cbrtconnect/sacks_project/auth_views.py.

SECURITY NOTES:
- Never log OAuth tokens (access_token, refresh_token, id_token) at any level
- Never log partial token values (even first N characters can be risky)
- Token presence ('SET' vs 'MISSING') is safe to log for debugging
- State tokens are single-use CSRF protection - don't log values
- User email and role info are safe to log (no credentials)
"""

import secrets
import requests
import time
import logging
from urllib.parse import urlencode
from django.shortcuts import redirect
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.conf import settings
from django.http import HttpResponseForbidden
from django.core.cache import cache
import jwt
from jwt import PyJWKClient

logger = logging.getLogger('camera_project.auth_views')
security_logger = logging.getLogger('oauth.security')


def generate_oauth_state():
    """Generate secure OAuth state token with timestamp."""
    token = secrets.token_urlsafe(32)
    timestamp = str(int(time.time()))
    state = f"{token}:{timestamp}"
    logger.info(f"Generated OAuth state token (timestamp: {timestamp})")
    return state


def store_oauth_state(state, ttl=600):
    """Store OAuth state in cache with TTL."""
    cache_key = f"oauth_state:{state}"
    try:
        cache.set(cache_key, {'created_at': int(time.time())}, timeout=ttl)
        logger.info(f"Stored OAuth state in cache (TTL: {ttl}s)")
        return True
    except Exception as e:
        security_logger.error(f"Failed to store OAuth state in cache: {e}")
        return False


def validate_and_consume_oauth_state(state, max_age=600):
    """Validate OAuth state token and consume it (single-use)."""
    if not state:
        security_logger.warning("OAuth state validation failed: No state provided")
        return False, "Missing state parameter"

    try:
        token, timestamp_str = state.split(':', 1)
        timestamp = int(timestamp_str)
    except (ValueError, AttributeError) as e:
        security_logger.warning(f"OAuth state validation failed: Invalid format - {e}")
        return False, "Invalid state format"

    cache_key = f"oauth_state:{state}"
    cached_data = cache.get(cache_key)

    if cached_data is None:
        security_logger.warning("OAuth state validation failed: State not found in cache or already used")
        return False, "Invalid or expired state token"

    age = int(time.time()) - timestamp
    if age > max_age:
        security_logger.warning(f"OAuth state validation failed: Token expired (age: {age}s)")
        cache.delete(cache_key)
        return False, f"State token expired (age: {age}s, max: {max_age}s)"

    cache.delete(cache_key)
    logger.info(f"OAuth state validated and consumed (age: {age}s)")

    return True, None


def login_page(request):
    """Redirect directly to SSO - no choice screen."""
    if request.user.is_authenticated:
        return redirect('/api/status/')
    return redirect('sso_login')


def sso_login(request):
    """Initiate SSO login - redirect to SSO OAuth with cache-based state storage."""
    state = generate_oauth_state()

    if not store_oauth_state(state, ttl=600):
        security_logger.error("Failed to store OAuth state - cache unavailable")
        return HttpResponseForbidden("Authentication service temporarily unavailable. Please try again.")

    request.session['oauth_state'] = state

    next_url = request.GET.get('next')
    if next_url:
        request.session['login_next_url'] = next_url
        request.session.modified = True

    logger.info(f"Initiating SSO login (next: {next_url})")

    scopes = set((settings.SSO_SCOPES or '').split())
    scopes.add('roles')
    scope_str = ' '.join(sorted(scopes))

    params = {
        'client_id': settings.SSO_CLIENT_ID,
        'redirect_uri': settings.SSO_REDIRECT_URI,
        'response_type': 'code',
        'scope': scope_str,
        'state': state,
    }

    auth_url = f"{settings.SSO_BASE_URL}/o/authorize/?{urlencode(params)}"
    return redirect(auth_url)


def sso_callback(request):
    """Handle SSO callback after user authenticates."""
    state = request.GET.get('state')
    code = request.GET.get('code')

    logger.info(f"SSO callback received - code: {'present' if code else 'missing'}")

    is_valid, error_msg = validate_and_consume_oauth_state(state, max_age=600)

    if settings.DEBUG_AUTH_FLOW:
        logger.debug(f"[FLOW DEBUG] State validation result: is_valid={is_valid}, error_msg={error_msg}")

    if not is_valid:
        stored_state = request.session.get('oauth_state')

        if state and stored_state and state == stored_state:
            logger.warning("State validated using session fallback")
            if 'oauth_state' in request.session:
                del request.session['oauth_state']
                request.session.modified = True
        else:
            security_logger.warning(
                f"OAuth state validation failed - IP: {request.META.get('REMOTE_ADDR')}, "
                f"Error: {error_msg}"
            )
            return HttpResponseForbidden(
                f"Invalid state parameter - {error_msg}. "
                f"This may indicate a CSRF attack or an expired session. "
                f"Please try logging in again."
            )
    else:
        if 'oauth_state' in request.session:
            del request.session['oauth_state']
            request.session.modified = True

    if not code:
        security_logger.warning("No authorization code received in SSO callback")
        return HttpResponseForbidden("No authorization code received")

    # Exchange code for tokens
    token_url = f"{settings.SSO_BASE_URL}/o/token/"
    token_data = {
        'code': code,
        'client_id': settings.SSO_CLIENT_ID,
        'client_secret': settings.SSO_CLIENT_SECRET,
        'redirect_uri': settings.SSO_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }

    try:
        response = requests.post(token_url, data=token_data, timeout=10)
        response.raise_for_status()
        tokens = response.json()
    except requests.RequestException as e:
        security_logger.error(f"Token exchange failed: {str(e)}")
        return HttpResponseForbidden(f"Token exchange failed: {str(e)}")

    access_token = tokens.get('access_token')
    id_token = tokens.get('id_token')

    # Verify JWT
    try:
        jwks_url = f"{settings.SSO_BASE_URL}/api/auth/.well-known/jwks.json"
        jwks_client = PyJWKClient(jwks_url, cache_keys=True)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        decoded = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.SSO_CLIENT_ID,
            issuer=f"{settings.SSO_BASE_URL}/o",
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
            }
        )

        logger.info(f"JWT verified and decoded successfully. Claims: {list(decoded.keys())}")

    except jwt.InvalidSignatureError as e:
        security_logger.error(f"JWT signature verification failed: {str(e)}")
        return HttpResponseForbidden("Invalid token signature - authentication failed.")

    except jwt.ExpiredSignatureError as e:
        security_logger.warning(f"JWT token expired: {str(e)}")
        return HttpResponseForbidden("Authentication token has expired. Please log in again.")

    except jwt.InvalidAudienceError as e:
        security_logger.error(f"JWT audience mismatch: {str(e)}")
        return HttpResponseForbidden("Invalid token audience - token not intended for this application.")

    except jwt.InvalidIssuerError as e:
        security_logger.error(f"JWT issuer mismatch: {str(e)}")
        return HttpResponseForbidden("Invalid token issuer - token from untrusted source.")

    except jwt.DecodeError as e:
        security_logger.error(f"JWT decode failed: {str(e)}")
        return HttpResponseForbidden(f"Invalid JWT token format: {str(e)}")

    except Exception as e:
        security_logger.error(f"JWT verification error: {str(e)}", exc_info=True)
        return HttpResponseForbidden("Authentication failed. Please try again or contact support.")

    # Fallback: fetch userinfo if application_roles missing
    if not decoded.get('application_roles') and access_token:
        try:
            ui_resp = requests.get(
                f"{settings.SSO_BASE_URL}/o/userinfo/",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5,
            )
            if ui_resp.ok:
                userinfo = ui_resp.json()
                decoded.update(userinfo)
        except Exception:
            pass

    email = decoded.get('email')
    logger.info(f"Extracted email: {email}")

    if not email:
        security_logger.warning(f"No email claim in JWT. Available claims: {list(decoded.keys())}")
        return HttpResponseForbidden("No email claim in authentication token. Contact admin.")

    # Check for camera role in application_roles claim
    application_roles = decoded.get("application_roles", {})
    app_identifier = getattr(settings, 'APP_IDENTIFIER', 'camera')
    camera_role = application_roles.get(app_identifier)

    if not camera_role:
        logger.warning(f"User {email} does not have {app_identifier} role. Available apps: {list(application_roles.keys())}")
        return HttpResponseForbidden(f"You don't have access to {app_identifier}. Contact admin.")

    role_name = camera_role.get("role")
    permissions = camera_role.get("permissions", [])

    logger.info(f"User {email} authenticated with {app_identifier} role: {role_name}")

    user, created = User.objects.get_or_create(
        username=email,
        defaults={
            'email': email,
            'first_name': decoded.get('given_name', decoded.get('display_name', '').split()[0] if decoded.get('display_name') else ''),
        }
    )

    if created:
        logger.info(f"Created new user: {email}")

    # Grant admin access based on role
    if role_name == "camshare_admin":
        user.is_staff = True
        user.is_superuser = True
        user.save()
    else:
        user.is_staff = True
        user.is_superuser = False
        user.save()

    # Store SSO role in session
    request.session['camera_role'] = {
        'role': role_name,
        'permissions': permissions,
    }
    request.session['sso_access_token'] = access_token

    # Log user into Django
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')

    # All camera users go to status page
    next_url = request.session.pop('login_next_url', None) or '/api/status/'
    logger.info(f"Login complete, redirecting {role_name} to: {next_url}")
    return redirect(next_url)


def sso_logout(request):
    """Logout user and redirect to SSO logout with return path."""
    logout(request)

    redirect_base = settings.SSO_REDIRECT_URI.rsplit('/auth/callback/', 1)[0]
    post_logout_uri = f"{redirect_base}/auth/login/"

    logout_params = {
        'client_id': settings.SSO_CLIENT_ID,
        'post_logout_redirect_uri': post_logout_uri,
    }
    logout_query = urlencode(logout_params)
    sso_logout_url = f"{settings.SSO_BASE_URL}/o/logout/?{logout_query}"

    logger.info("Logging out and redirecting to SSO")
    return redirect(sso_logout_url)
