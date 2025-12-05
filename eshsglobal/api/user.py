import frappe
from frappe import _
import time
from functools import wraps
from .auth import verify_jwt_token  # Import JWT verification from auth.py (adjust path if needed)

# -------------------------
# Security Config
# -------------------------
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 3600
MAX_REQUEST_SIZE = 10 * 1024 * 1024

# -------------------------
# Decorators
# -------------------------
def rate_limit(key_fn):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                key = key_fn(*args, **kwargs)
                cache_key = f"rate_limit_{key}"
                data = frappe.cache().get_value(cache_key) or {
                    "count": 0,
                    "reset_at": time.time() + RATE_LIMIT_WINDOW
                }
                if time.time() > data["reset_at"]:
                    data = {"count": 0, "reset_at": time.time() + RATE_LIMIT_WINDOW}
                if data["count"] >= RATE_LIMIT_REQUESTS:
                    return {"success": False, "message": "rate_limit_exceeded"}
                data["count"] += 1
                frappe.cache().set_value(cache_key, data, expires_in_sec=RATE_LIMIT_WINDOW)
            except:
                pass
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def check_request_size(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if (frappe.request.content_length or 0) > MAX_REQUEST_SIZE:
            return {"success": False, "message": "request_too_large"}
        return fn(*args, **kwargs)
    return wrapper

def sanitize_input(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        for key, value in kwargs.items():
            if isinstance(value, str):
                if any(p in value.lower() for p in
                       ['--', ';--', '/*', '*/', 'xp_', 'sp_', '<script', 'javascript:', 'onerror=']):
                    return {"success": False, "message": "invalid_input"}
        return fn(*args, **kwargs)
    return wrapper

# -------------------------
# JWT Auth Decorator (Now secondary enforcement post-patch)
# -------------------------
def require_jwt_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # If patch already set a valid user, skip detailed check (optimization)
        if frappe.session.user != "Guest":
            frappe.logger().info(f"User already auth'd via patch: {frappe.session.user}")
            return fn(*args, **kwargs)
        
        # Fallback: Full check (for cases where patch didn't trigger)
        auth_header = frappe.get_request_header('Authorization') or ''
        if not auth_header.startswith('Bearer '):
            frappe.throw(frappe.AuthenticationError('Authorization header with Bearer token required'))
        
        token = auth_header[7:].strip()
        if not token:
            frappe.throw(frappe.AuthenticationError('No token provided in Authorization header'))
        
        try:
            payload = verify_jwt_token(token)
            user_email = payload.get('user_email')
            if not user_email:
                frappe.throw(frappe.AuthenticationError('Invalid token: missing user_email'))
            
            # Set if not already (redundant post-patch, but safe)
            frappe.set_user(user_email)
            frappe.session.user = user_email
            frappe.session['user'] = user_email
            
        except frappe.AuthenticationError:
            raise
        except Exception as e:
            frappe.throw(frappe.AuthenticationError(f'Token verification failed: {str(e)}'))
        
        return fn(*args, **kwargs)
    return wrapper

def _response(success, message, data, code=200):
    return {"success": success, "message": message, "data": data}

# -------------------------
#   UPDATED API (Now with allow_guest=True to skip early auth check)
# -------------------------

@frappe.whitelist(allow_guest=True)
@require_jwt_auth  # Use your decorator if needed
def get_user_profile():
    try:
        user_email = frappe.session.user  # Now guaranteed non-Guest via patch
        if not user_email or user_email == "Guest":
            raise frappe.AuthenticationError("User not authenticated")

        app_user = frappe.get_doc("App Users", {"user_link": user_email})
        user_doc = frappe.get_doc("User", user_email)
        
        # Generate new keys only if requested (avoid always regenerating)
        new_api_key, new_api_secret = None, None
        # if some_condition:  # e.g., via query param
        #     new_api_key, new_api_secret = _ensure_api_credentials_for_user(user_email)

        data = {
            "uuid": app_user.uuid,
            "first_name": app_user.first_name,
            "last_name": app_user.last_name,
            "email": app_user.email,
            "api_key": user_doc.api_key,
            "api_secret_encrypted": user_doc.api_secret,  # Assuming it's stored encrypted
        }
        if new_api_key:
            data.update({"new_api_key": new_api_key, "new_api_secret": new_api_secret})

        return _response(True, "profile_fetched", data)
    except frappe.AuthenticationError as auth_err:
        return _response(False, str(auth_err), {}, 401)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "get_user_profile_error")
        return _response(False, "internal_error", {}, 500)