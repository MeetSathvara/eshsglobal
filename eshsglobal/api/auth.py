import frappe
from frappe import _
import random
import string
import json
import time
import hmac
import hashlib
import base64
from datetime import datetime, timedelta, timezone


# -------------------------
# Helpers: JWT (no external libs) - Moved before patch for definition order
# -------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")
def _b64url_decode(input_str: str) -> bytes:
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)
def create_jwt_token(payload: dict, exp_seconds: int = None) -> str:  # Note: exp_seconds param added for flexibility
    # Config moved here as it's needed
    JWT_EXP_SECONDS = 60 * 60 * 24
    JWT_ALGO = "HS256"
    JWT_ISS = "eshsglobal"
    JWT_SECRET = getattr(frappe.conf, "secret_key", None) or frappe.get_site_config().get("secret_key") or frappe.generate_hash(length=32)
    
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = payload.copy()
    payload.setdefault("iat", now)
    payload.setdefault("exp", now + (exp_seconds or JWT_EXP_SECONDS))
    payload.setdefault("iss", JWT_ISS)
   
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
   
    return f"{header_b64}.{payload_b64}.{sig_b64}"
def verify_jwt_token(token: str) -> dict:
    try:
        # Config for verify
        JWT_SECRET = getattr(frappe.conf, "secret_key", None) or frappe.get_site_config().get("secret_key") or frappe.generate_hash(length=32)
        
        parts = token.split(".")
        if len(parts) != 3:
            raise frappe.AuthenticationError("Invalid token format")
       
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        expected_sig_b64 = _b64url_encode(expected_sig)
       
        if not hmac.compare_digest(expected_sig_b64, sig_b64):
            raise frappe.AuthenticationError("Invalid token signature")
       
        payload_json = _b64url_decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)
       
        now = int(time.time())
        if "exp" in payload and now > int(payload["exp"]):
            raise frappe.AuthenticationError("Token expired")
       
        return payload
    except Exception as e:
        frappe.logger().debug(f"JWT verify error: {str(e)}")
        raise frappe.AuthenticationError("Token verification failed")

# -------------------------
# MONKEY PATCH: Custom JWT Auth for validate_auth() (loads early, no hooks needed)
# -------------------------
# Store original for fallback

def custom_validate_auth():
    """
    Patched validate_auth: Checks Bearer JWT first, sets user/session if valid.
    Falls back to original if no/invalid token (allows guest methods).
    """
    # Only for API requests with potential auth header
    auth_header = frappe.get_request_header('Authorization') or ''
    if auth_header.startswith('Bearer '):
        token = auth_header[7:].strip()
        if token:
            try:
                # Now verify_jwt_token is defined
                payload = verify_jwt_token(token)
                user_email = payload.get('user_email')
                if user_email and frappe.db.exists('User', user_email):
                    # Set user and login (bypasses error)
                    frappe.set_user(user_email)
                    frappe.session.user = user_email
                    frappe.session['user'] = user_email
                    # Optional: Add payload extras to session
                    frappe.session['uuid'] = payload.get('uuid')
                    frappe.session['phone'] = payload.get('phone')
                    
                    frappe.logger().info(f"JWT auth via patch successful for: {user_email}")
                    return  # Auth passed—no error raised
            except frappe.AuthenticationError:
                frappe.logger().warning("JWT auth failed in patch")
                pass  # Continue to original (will error if needed)
            except Exception as e:
                frappe.logger().error(f"JWT patch error: {str(e)}")
                pass
    
    # Fallback: Original behavior (guest if allow_guest=True, else error)
    original_validate_auth()

# Apply the patch immediately (runs on import)

# -------------------------
# Config (now partially in helpers, but OTP config here)
# -------------------------
OTP_EXPIRE_SECONDS = 300

# -------------------------
# UUID generator: ESHS001, ESHS002...
# -------------------------
def generate_unique_uuid():
    try:
        row = frappe.db.sql(
            """SELECT uuid FROM `tabApp Users`
            WHERE uuid LIKE 'ESHS%'
            ORDER BY CAST(SUBSTRING(uuid, 5) AS INTEGER) DESC
            LIMIT 1""",
            as_dict=True,
        )
        if not row:
            return "ESHS001"
       
        last_uuid = row[0].uuid or "ESHS000"
        prefix = "ESHS"
        num = int(last_uuid.replace(prefix, "")) + 1
        return f"{prefix}{num:03d}"
    except Exception:
        last_uuid = frappe.db.get_value("App Users", {}, "uuid", order_by="creation desc")
        if not last_uuid:
            return "ESHS001"
        try:
            prefix = "ESHS"
            num = int(last_uuid.replace(prefix, "")) + 1
            return f"{prefix}{num:03d}"
        except Exception:
            return f"ESHS{random.randint(100,999)}"

# -------------------------
# OTP helpers
# -------------------------
def _generate_otp():
    return "".join(random.choices(string.digits, k=6))
def _store_otp(phone: str, otp: str):
    cache_key = f"otp_{phone}"
    frappe.cache().set_value(cache_key, otp, expires_in_sec=OTP_EXPIRE_SECONDS)
   
    # Store in App User Registration if exists
    try:
        reg_exists = frappe.db.exists("App User Registration", {"phone": phone})
        if reg_exists:
            expiry = datetime.now(timezone.utc) + timedelta(seconds=OTP_EXPIRE_SECONDS)
            frappe.db.set_value("App User Registration", reg_exists, {
                "otp": otp,
                "otp_expires_at": expiry,
                "updated_at": datetime.now(timezone.utc)

            })
            frappe.db.commit()
    except Exception:
        pass
def _get_stored_otp(phone: str):
    cache_key = f"otp_{phone}"
    return frappe.cache().get_value(cache_key)

# -------------------------
# Standard response wrapper
# -------------------------
def _response(success: bool, message: str = "", data: dict = None, status_code: int = 200):
    return {
        "success": bool(success),
        "message": message or "",
        "data": data or {}
    }

# -------------------------
# ENDPOINT: send_otp
# -------------------------
@frappe.whitelist(allow_guest=True, methods=["POST"])
def send_otp(phone: str = None):
    try:
        if not phone or len(phone.strip()) < 7:
            return _response(False, "invalid_phone", {})
       
        phone = phone.strip()
        otp = _generate_otp()
        _store_otp(phone, otp)
       
        frappe.log_error(title=f"OTP for {phone}", message=f"OTP: {otp}")
       
        is_new = not bool(frappe.db.exists("App Users", {"phone": phone}))
       
        data = {
            "phone": phone,
            "is_new": bool(is_new),
            "otp": otp
        }
        return _response(True, "otp_sent", data)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "send_otp_error")
        return _response(False, "internal_error", {})

# -------------------------
# ENDPOINT: resend_otp
# -------------------------
@frappe.whitelist(allow_guest=True, methods=["POST"])
def resend_otp(phone: str = None):
    try:
        if not phone or len(phone.strip()) < 7:
            return _response(False, "invalid_phone", {})
       
        phone = phone.strip()
        otp = _generate_otp()
        _store_otp(phone, otp)
       
        frappe.log_error(title=f"Resent OTP for {phone}", message=f"OTP: {otp}")
       
        is_new = not bool(frappe.db.exists("App Users", {"phone": phone}))
       
        data = {"phone": phone, "is_new": bool(is_new), "otp": otp}
        return _response(True, "otp_resent", data)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "resend_otp_error")
        return _response(False, "internal_error", {})

# -------------------------
# ENDPOINT: verify_otp
# -------------------------
@frappe.whitelist(allow_guest=True, methods=["POST"])
def verify_otp(phone: str = None, otp: str = None):
    try:
        if not phone or not otp:
            return _response(False, "phone_and_otp_required", {})
       
        phone = phone.strip()
        otp = otp.strip()
       
        # Extract country code if present
        phone_country_code = "+971"
        phone_number = phone
        if phone.startswith("+"):
            parts = phone.split(" ", 1) if " " in phone else [phone[:4], phone[4:]]
            phone_country_code = parts[0]
            phone_number = parts[1] if len(parts) > 1 else phone[len(phone_country_code):]
            print('otp', otp)
       
        stored = _get_stored_otp(phone)
        if not stored:
            return _response(False, "otp_expired_or_not_found", {})
       
        if stored != otp:
            return _response(False, "invalid_otp", {})
       
        frappe.cache().delete_value(f"otp_{phone}")
       
        existing = frappe.db.exists("App Users", {"phone": phone})
        current_utc_time = datetime.now(timezone.utc)
        if not existing:
            reg_exists = frappe.db.exists("App User Registration", {"phone": phone, "otp":otp})
           
            if reg_exists:
                reg_doc = frappe.get_doc("App User Registration", reg_exists)
               
            else:
                reg_doc = frappe.get_doc({
                    "doctype": "App User Registration",
                    "phone": phone,
                    "phone_country_code": phone_country_code,
                    "otp": otp,
                    "otp_expires_at": None,
                    "is_verified": True,
                    "created_at": current_utc_time,
                    "updated_at": current_utc_time,
                })
                reg_doc.insert(ignore_permissions=True)
           
            reg_doc.is_verified = True
            reg_doc.otp = None
            reg_doc.otp_expires_at = None
            reg_doc.updated_at = datetime.now(timezone.utc)
            reg_doc.save(ignore_permissions=True)
            frappe.db.commit()
           
            data = {
                "phone": phone,
                "is_new": True
            }
        else:
            app_user = frappe.get_doc("App Users", existing)
            api_key, api_secret = _ensure_api_credentials_for_user(app_user.user_link)
           
            payload = {
                "user_email": app_user.user_link,
                "uuid": app_user.uuid,
                "phone": phone,
                "api_key": api_key,
            }
            token = create_jwt_token(payload)
           
            data = {
                "uuid": app_user.uuid,
                "phone": phone,
                "is_new": False,
                "token": token
            }
       
        return _response(True, "otp_verified", data)
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "verify_otp_error")
        return _response(False, "internal_error", {})

# -------------------------
# Helper: ensure api credentials
# -------------------------
def _ensure_api_credentials_for_user(user_email: str):
    user = frappe.get_doc("User", user_email)
    api_key = getattr(user, "api_key", None)
    api_secret = getattr(user, "api_secret", None)
   
    if not api_key or not api_secret:
        api_key = frappe.generate_hash(length=24)
        api_secret = frappe.generate_hash(length=48)
        user.api_key = api_key
        user.api_secret = api_secret
        user.save(ignore_permissions=True)
   
    return api_key, api_secret

# -------------------------
# ENDPOINT: register_user
# -------------------------
def parse_date(date_str):
    if not date_str or date_str in ("0", "0000-00-00", ""):
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except Exception:
        return None

@frappe.whitelist(allow_guest=True, methods=["POST"])
def register_user(**kwargs):
    try:
        phone = kwargs.get("phone")
        if not phone:
            return _response(False, "phone_required", {})
       
        phone = phone.strip()
       
        # Check App User Registration for verification
        reg_exists = frappe.db.exists("App User Registration", {"phone": phone, "is_verified": True})
        if not reg_exists:
            return _response(False, "phone_not_verified", {})
       
        # Check if already registered in App Users
        if frappe.db.exists("App Users", {"phone": phone}):
            return _response(False, "user_already_registered", {})
       
        # Create system user
        user_email = f"{phone}@eshsglobal.com"
        current_utc_time = datetime.now(timezone.utc)
       
        if not frappe.db.exists("User", user_email):
            system_user = frappe.get_doc({
                "doctype": "User",
                "email": user_email,
                "first_name": kwargs.get("first_name", phone),
                "send_welcome_email": 0,
                "user_type": "Website User",
            })
            system_user.insert(ignore_permissions=True)
        else:
            system_user = frappe.get_doc("User", user_email)
       
        # Handle consent flags (logic remains the same)
        data_consent = kwargs.get("data_consent_given")
        if isinstance(data_consent, str):
            data_consent = data_consent.lower() in ("true", "1", "yes")
        else:
            data_consent = bool(data_consent) if data_consent else False
       
        sharing_consent = kwargs.get("sharing_consent_given")
        if isinstance(sharing_consent, str):
            sharing_consent = sharing_consent.lower() in ("true", "1", "yes")
        else:
            sharing_consent = bool(sharing_consent) if sharing_consent else False
       
        medical_consent = kwargs.get("medical_consent_given")
        if isinstance(medical_consent, str):
            medical_consent = medical_consent.lower() in ("true", "1", "yes")
        else:
            medical_consent = bool(medical_consent) if medical_consent else False
       
        teleconsult_consent = kwargs.get("teleconsult_recording_consent")
        if isinstance(teleconsult_consent, str):
            teleconsult_consent = teleconsult_consent.lower() in ("true", "1", "yes")
        else:
            teleconsult_consent = bool(teleconsult_consent) if teleconsult_consent else False
       
        # Parse Dates (logic remains the same)
        date_of_birth = parse_date(kwargs.get("date_of_birth"))
        emirates_id_expiry_date = parse_date(kwargs.get("emirates_id_expiry_date"))
        passport_expiry_date = parse_date(kwargs.get("passport_expiry_date"))
        print('Reah here =========>')
        # Create base App Users doc data
        app_user_data = {
            "doctype": "App Users",
            "uuid": generate_unique_uuid(),
            "phone": phone,
            "phone_country_code": kwargs.get("phone_country_code", "+971"),
            "email": kwargs.get("email", user_email),
            "first_name": kwargs.get("first_name", ""),
            "last_name": kwargs.get("last_name", ""),
            "gender": kwargs.get("gender", ""),
            "nationality": kwargs.get("nationality", ""),
            "profile_photo": kwargs.get("profile_photo", ""),
            "language_preference": kwargs.get("language_preference", "en"),
            "is_verified": True,
            "data_consent_given": int(data_consent),
            "sharing_consent_given": int(sharing_consent),
            "medical_consent_given": int(medical_consent),
            "teleconsult_recording_consent": int(teleconsult_consent),
            "account_status": "active",
            "created_at": current_utc_time,
            "updated_at": current_utc_time,
            "user_link": system_user.name,
            "emirates_id": kwargs.get("emirates_id", ""),
            "emirates_id_front_photo": kwargs.get("emirates_id_front_photo", ""),
            "emirates_id_back_photo": kwargs.get("emirates_id_back_photo", ""),
            "passport_number": kwargs.get("passport_number", ""),
            "passport_photo": kwargs.get("passport_photo", "")
        }
        print('Reah belowwwwwwwwwwwwwww =========>')
        # Conditionally add date fields (avoids '0' date error)
        if date_of_birth:
            app_user_data["date_of_birth"] = date_of_birth
        if emirates_id_expiry_date:
            app_user_data["emirates_id_expiry_date"] = emirates_id_expiry_date
        if passport_expiry_date:
            app_user_data["passport_expiry_date"] = passport_expiry_date
        app_user = frappe.get_doc(app_user_data)
        # Force None for consent timestamps (overrides DB defaults)
        datetime_fields = [df.fieldname for df in frappe.get_meta("App Users").fields
                   if df.fieldtype in ["Datetime", "Date"]]
        # Set all unset datetime fields to None
        for field in datetime_fields:
            if not app_user.get(field):
                app_user.set(field, None)
        # Then set your consent timestamps
        if data_consent:
            app_user.data_consent_at = current_utc_time
            app_user.data_consent_ip = frappe.local.request_ip
        if not data_consent:
            app_user.data_consent_at = None
            app_user.data_consent_ip = None
        else:
            app_user.data_consent_at = current_utc_time
            app_user.data_consent_ip = frappe.local.request_ip
        if not sharing_consent:
            app_user.sharing_consent_at = None
        else:
            app_user.sharing_consent_at = current_utc_time
        if not medical_consent:
            app_user.medical_consent_at = None
        else:
            app_user.medical_consent_at = current_utc_time
        if not teleconsult_consent:
            app_user.teleconsult_recording_consent_at = None
        else:
            app_user.teleconsult_recording_consent_at = current_utc_time
        app_user.insert(ignore_permissions=True)
        frappe.db.commit()
       
        # Create API credentials and JWT token
        api_key, api_secret = _ensure_api_credentials_for_user(system_user.name)
       
        payload = {
            "user_email": system_user.name,
            "uuid": app_user.uuid,
            "phone": app_user.phone,
            "api_key": api_key,
        }
        token = create_jwt_token(payload)
       
        data = {
            "uuid": app_user.uuid,
            "is_user_verified": True,
            "token": token
        }
       
        return _response(True, "registration_successful", data)
    except Exception as e:
        frappe.db.rollback()
        frappe.log_error(frappe.get_traceback(), "register_user_error")
        return _response(False, "internal_error", {})
