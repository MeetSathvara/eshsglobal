app_name = "eshsglobal"
app_title = "ESHS Global"
app_publisher = "ESHS Global"
app_description = "ESHS Healthcare Platform APIs"
app_email = "dev@eshsglobal.com"
app_license = "mit"
# hooks.py
import frappe
from frappe.auth import validate_auth as _original_validate_auth
from eshsglobal.api.auth import verify_jwt_token  # Ensure this import path is correct


def jwt_validate_auth():
    auth_header = frappe.get_request_header('Authorization', '') or ''
    if auth_header.startswith('Bearer '):
        token = auth_header[7:].strip()
        try:
            payload = verify_jwt_token(token)
            user_email = payload.get('user_email')
            if user_email:
                if frappe.db.exists('User', user_email):
                    frappe.set_user(user_email)
                    frappe.local.login_manager.user = user_email
                    frappe.logger().info(f"JWT auth successful for {user_email}")
                    return
                else:
                    frappe.logger().warning(f"JWT valid but user {user_email} not found in DB")
                    # Optional: Auto-create stub user (risky—only for dev)
                    # See fix #1 above
            else:
                frappe.logger().warning("JWT valid but missing user_email")
        except Exception as e:  # Broader catch for debugging
            frappe.logger().error(f"JWT auth error: {str(e)}")
    # Fallback
    _original_validate_auth()

frappe.auth.validate_auth = jwt_validate_auth