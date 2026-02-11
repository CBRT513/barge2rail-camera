"""
Reusable RBAC decorators for barge2rail-camera.

Adapted from django-primetrade/primetrade_project/decorators.py.
Reads role from session['camera_role']['role'] set during OAuth callback.
"""

from functools import wraps
from django.http import HttpResponseForbidden
import logging

logger = logging.getLogger('camera.security')


def require_role(*allowed_roles):
    """
    Require specific role(s) for view access.

    Reads role from request.session['camera_role']['role'] which is set
    during OAuth callback in camera_project/auth_views.py.

    Usage:
        @require_role('Admin')
        def admin_only_view(request):
            pass

        @require_role('Admin', 'User')
        def multi_role_view(request):
            pass
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            app_role = request.session.get('camera_role', {})
            user_role = app_role.get('role')
            user_email = request.user.email if request.user.is_authenticated else 'unknown'

            if not app_role:
                logger.error(
                    f"Missing camera_role in session for {user_email} "
                    f"attempting {view_func.__name__}"
                )
                return HttpResponseForbidden(
                    "Session expired or missing role data. Please log out and log in again."
                )

            if user_role and user_role.lower() in [r.lower() for r in allowed_roles]:
                return view_func(request, *args, **kwargs)

            logger.warning(
                f"Access denied: {user_email} (role={user_role or 'none'}) "
                f"attempted {view_func.__name__}. "
                f"Required roles: {', '.join(allowed_roles)}"
            )

            return HttpResponseForbidden(
                f"Access denied. This action requires one of the following roles: "
                f"{', '.join(allowed_roles)}. Your current role: {user_role or 'none'}. "
                f"Contact your administrator if you believe this is incorrect."
            )

        return wrapped_view
    return decorator


def require_role_for_writes(*allowed_roles):
    """
    Require specific role(s) for write operations (POST, PUT, PATCH, DELETE).
    GET requests pass through without role check.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if request.method == 'GET':
                return view_func(request, *args, **kwargs)

            app_role = request.session.get('camera_role', {})
            user_role = app_role.get('role')
            user_email = request.user.email if request.user.is_authenticated else 'unknown'

            if not app_role:
                logger.error(
                    f"Missing camera_role in session for {user_email} "
                    f"attempting {view_func.__name__} {request.method}"
                )
                return HttpResponseForbidden(
                    "Session expired or missing role data. Please log out and log in again."
                )

            if user_role and user_role.lower() in [r.lower() for r in allowed_roles]:
                return view_func(request, *args, **kwargs)

            logger.warning(
                f"Access denied: {user_email} (role={user_role or 'none'}) "
                f"attempted {view_func.__name__} {request.method}. "
                f"Required roles: {', '.join(allowed_roles)}"
            )

            return HttpResponseForbidden(
                f"Access denied. This action requires one of the following roles: "
                f"{', '.join(allowed_roles)}. Your current role: {user_role or 'none'}. "
                f"Contact your administrator if you believe this is incorrect."
            )

        return wrapped_view
    return decorator
