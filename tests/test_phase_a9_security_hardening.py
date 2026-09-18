"""Phase A9 Verification Test Suite: Security Hardening.

Tests all 32 required A9 scenarios:
 1. Invalid Google token rejected (401)
 2. Expired Google token rejected (401)
 3. Wrong audience rejected when configured (401)
 4. Unverified Google email rejected (401)
 5. Google identity mismatch rejected (403)
 6. Unknown Google account cannot create a user (403)
 7. Session token is unpredictable (256-bit CSPRNG entropy)
 8. Expired session rejected (401)
 9. Revoked session rejected (401)
10. Disabled user session rejected (403)
11. Logout invalidates session
12. Authentication creates a fresh session (no session fixation)
13. USER cannot elevate through request body (403)
14. USER cannot elevate through headers (403)
15. USER cannot elevate through query parameters (403)
16. USER cannot elevate through frontend state (403)
17. Disabled ADMIN cannot access Admin endpoints (403)
18. USER cannot access Admin endpoints (403)
19. Last-admin protection remains intact (400)
20. Self-admin protection remains intact (400)
21. Deleted user cannot reuse old session (401)
22. Admin role changes take immediate effect
23. Disabled status overrides ADMIN role (403)
24. Sensitive credentials are absent from responses
25. Sensitive credentials are absent from logs where testable
26. Auth tokens/roles absent from localStorage
27. Auth tokens/roles absent from sessionStorage
28. CORS does not permit unauthorized credentialed origins
29. Security headers are present as intended
30. Webhook remains HMAC protected
31. Public health endpoints remain public
32. CLI remains operational offline
"""

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage import (
    AnalysisStore,
    UserRecord,
    UserRole,
    UserStatus,
)
from backend.app.core.config import settings
from backend.app.core.security import sanitize_sensitive_text, SecurityHeadersMiddleware
from backend.app.main import app


@pytest.fixture
def a9_env(monkeypatch):
    """Provide isolated SQLite database and TestClient with enforced session auth."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    store.initialize()

    # Monkeypatch store instances across backend modules
    monkeypatch.setattr("backend.app.core.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.admin.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.history._get_store", lambda: AnalysisStore(db_path=temp_db_path))

    # Seed Root Admin
    root_admin = store.seed_initial_admin("admin@codesentinel.dev", "Root Administrator")
    store.bind_google_identity(root_admin.user_id, "goog_sub_root_admin")

    # Seed Second Admin
    second_admin = store.create_authorized_user(
        email="admin2@codesentinel.dev",
        role=UserRole.ADMIN.value,
        full_name="Second Administrator",
        created_by=root_admin.email,
    )
    store.bind_google_identity(second_admin.user_id, "goog_sub_admin2")

    # Seed Standard Active User
    std_user = store.create_authorized_user(
        email="developer@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Standard Developer",
        created_by=root_admin.email,
    )
    store.bind_google_identity(std_user.user_id, "goog_sub_developer")

    # Pre-authorized user without bound Google ID
    preauth_user = store.create_authorized_user(
        email="preauthorized@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Preauth Developer",
        created_by=root_admin.email,
    )

    # Create active sessions
    admin_session_id = store.create_session(root_admin.user_id)
    second_admin_session_id = store.create_session(second_admin.user_id)
    user_session_id = store.create_session(std_user.user_id)

    client = TestClient(app)

    yield {
        "store": store,
        "client": client,
        "root_admin": root_admin,
        "second_admin": second_admin,
        "std_user": std_user,
        "preauth_user": preauth_user,
        "admin_session_id": admin_session_id,
        "second_admin_session_id": second_admin_session_id,
        "user_session_id": user_session_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scenario 1: Invalid Google token rejected (401)
# ---------------------------------------------------------------------------
def test_1_invalid_google_token_rejected(a9_env):
    client = a9_env["client"]
    resp = client.post("/auth/google", json={"id_token": "mock_invalid_token_xyz"})
    assert resp.status_code == 401
    assert "Invalid or expired Google" in resp.json().get("detail", "")


# ---------------------------------------------------------------------------
# Scenario 2: Expired Google token rejected (401)
# ---------------------------------------------------------------------------
def test_2_expired_google_token_rejected(a9_env):
    client = a9_env["client"]
    expired_token = f"mock:{json.dumps({'sub': 'sub_exp', 'email': 'developer@codesentinel.dev', 'exp': time.time() - 3600})}"
    resp = client.post("/auth/google", json={"id_token": expired_token})
    assert resp.status_code == 401
    assert "expired" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 3: Wrong audience rejected when configured (401)
# ---------------------------------------------------------------------------
def test_3_wrong_audience_rejected(a9_env, monkeypatch):
    client = a9_env["client"]
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "expected-client-id-12345.apps.googleusercontent.com")
    wrong_aud_token = f"mock:{json.dumps({'sub': 'sub_aud', 'email': 'developer@codesentinel.dev', 'aud': 'wrong-client-id.apps.googleusercontent.com'})}"
    resp = client.post("/auth/google", json={"id_token": wrong_aud_token})
    assert resp.status_code == 401
    assert "audience does not match" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 4: Unverified Google email rejected (401)
# ---------------------------------------------------------------------------
def test_4_unverified_google_email_rejected(a9_env):
    client = a9_env["client"]
    unverified_token = f"mock:{json.dumps({'sub': 'sub_unv', 'email': 'developer@codesentinel.dev', 'email_verified': False})}"
    resp = client.post("/auth/google", json={"id_token": unverified_token})
    assert resp.status_code == 401
    assert "not been verified" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 5: Google identity mismatch rejected (403)
# ---------------------------------------------------------------------------
def test_5_google_identity_mismatch_rejected(a9_env):
    client = a9_env["client"]
    # Provide goog_sub_developer with a different email
    mismatch_token = f"mock:{json.dumps({'sub': 'goog_sub_developer', 'email': 'imposter@codesentinel.dev'})}"
    resp = client.post("/auth/google", json={"id_token": mismatch_token})
    assert resp.status_code == 403
    assert "mismatch" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 6: Unknown Google account cannot create a user (403)
# ---------------------------------------------------------------------------
def test_6_unknown_google_account_cannot_create_user(a9_env):
    client = a9_env["client"]
    unknown_token = "mock_google_:unknown@codesentinel.dev:sub_unknown:Unknown Hacker"
    resp = client.post("/auth/google", json={"id_token": unknown_token})
    assert resp.status_code == 403
    assert "not authorized" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 7: Session token is unpredictable (256-bit CSPRNG entropy)
# ---------------------------------------------------------------------------
def test_7_session_token_is_unpredictable(a9_env):
    store = a9_env["store"]
    user = a9_env["std_user"]
    sids = [store.create_session(user.user_id) for _ in range(10)]
    for sid in sids:
        assert sid.startswith("sess_")
        # 64 hex chars = 256 bits of entropy
        hex_part = sid.replace("sess_", "")
        assert len(hex_part) == 64
        int(hex_part, 16)  # must be valid hex
    # All tokens must be strictly unique
    assert len(set(sids)) == 10


# ---------------------------------------------------------------------------
# Scenario 8: Expired session rejected (401)
# ---------------------------------------------------------------------------
def test_8_expired_session_rejected(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    user = a9_env["std_user"]
    sid = store.create_session(user.user_id)
    with store._get_connection() as conn:
        conn.execute("UPDATE user_sessions SET expires_at = '2020-01-01T00:00:00+00:00' WHERE session_id = ?", (sid,))

    resp = client.get("/analyses", headers={"Authorization": f"Bearer {sid}"})
    assert resp.status_code == 401
    assert "expired" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 9: Revoked session rejected (401)
# ---------------------------------------------------------------------------
def test_9_revoked_session_rejected(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    user = a9_env["std_user"]
    sid = store.create_session(user.user_id)
    store.revoke_session(sid)

    resp = client.get("/analyses", headers={"Authorization": f"Bearer {sid}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Scenario 10: Disabled user session rejected (403)
# ---------------------------------------------------------------------------
def test_10_disabled_user_session_rejected(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    user = a9_env["std_user"]
    store.update_user_status(user.user_id, UserStatus.DISABLED.value)

    resp = client.get("/analyses", headers={"Authorization": f"Bearer {a9_env['user_session_id']}"})
    assert resp.status_code == 403
    assert "disabled" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 11: Logout invalidates session
# ---------------------------------------------------------------------------
def test_11_logout_invalidates_session(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['user_session_id']}"}

    # Verify initial access
    assert client.get("/auth/me", headers=headers).status_code == 200

    # Logout
    logout_resp = client.post("/auth/logout", headers=headers)
    assert logout_resp.status_code == 200

    # Subsequent access must be rejected
    assert client.get("/auth/me", headers=headers).status_code == 401


# ---------------------------------------------------------------------------
# Scenario 12: Authentication creates a fresh session (no session fixation)
# ---------------------------------------------------------------------------
def test_12_authentication_creates_fresh_session(a9_env):
    client = a9_env["client"]
    # Attempting to reuse an attacker-controlled cookie prior to login
    pre_auth_cookie = "sess_attacker_pre_auth_token_value_here"

    login_resp = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:developer@codesentinel.dev:goog_sub_developer:Standard Developer"},
        headers={"Cookie": f"{settings.SESSION_COOKIE_NAME}={pre_auth_cookie}"},
    )
    assert login_resp.status_code == 200
    new_token = login_resp.json().get("session_token")
    assert new_token != pre_auth_cookie
    set_cookie_header = login_resp.headers.get("set-cookie", "")
    assert settings.SESSION_COOKIE_NAME in set_cookie_header
    assert new_token in set_cookie_header


# ---------------------------------------------------------------------------
# Scenario 13: USER cannot elevate through request body (403)
# ---------------------------------------------------------------------------
def test_13_user_cannot_elevate_through_request_body(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['user_session_id']}"}
    resp = client.post(
        "/admin/users",
        json={"email": "hacker@codesentinel.dev", "role": "ADMIN", "is_admin": True},
        headers=headers,
    )
    assert resp.status_code == 403
    assert "administrative privileges required" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 14: USER cannot elevate through headers (403)
# ---------------------------------------------------------------------------
def test_14_user_cannot_elevate_through_headers(a9_env):
    client = a9_env["client"]
    headers = {
        "Authorization": f"Bearer {a9_env['user_session_id']}",
        "X-User-Role": "ADMIN",
        "X-Role": "ADMIN",
        "Role": "ADMIN",
    }
    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403
    assert "administrative privileges required" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 15: USER cannot elevate through query parameters (403)
# ---------------------------------------------------------------------------
def test_15_user_cannot_elevate_through_query_params(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['user_session_id']}"}
    resp = client.get("/admin/users?role=ADMIN&is_admin=true", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 16: USER cannot elevate through frontend state (403)
# ---------------------------------------------------------------------------
def test_16_user_cannot_elevate_through_frontend_state(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['user_session_id']}"}
    # Direct access to admin-only delete endpoint
    resp = client.delete(f"/admin/users/{a9_env['second_admin'].user_id}", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 17: Disabled ADMIN cannot access Admin endpoints (403)
# ---------------------------------------------------------------------------
def test_17_disabled_admin_cannot_access_admin_endpoints(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    admin2 = a9_env["second_admin"]
    store.update_user_status(admin2.user_id, UserStatus.DISABLED.value)

    headers = {"Authorization": f"Bearer {a9_env['second_admin_session_id']}"}
    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403
    assert "disabled" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 18: USER cannot access Admin endpoints (403)
# ---------------------------------------------------------------------------
def test_18_user_cannot_access_admin_endpoints(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['user_session_id']}"}
    endpoints = [
        ("GET", "/admin/users"),
        ("POST", "/admin/users"),
        ("GET", f"/admin/users/{a9_env['second_admin'].user_id}"),
        ("PATCH", f"/admin/users/{a9_env['second_admin'].user_id}/status"),
        ("PATCH", f"/admin/users/{a9_env['second_admin'].user_id}/role"),
        ("DELETE", f"/admin/users/{a9_env['second_admin'].user_id}"),
    ]
    for method, ep in endpoints:
        resp = client.request(method, ep, headers=headers)
        assert resp.status_code == 403, f"Expected 403 for {method} {ep}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Scenario 19: Last-admin protection remains intact (400)
# ---------------------------------------------------------------------------
def test_19_last_admin_protection_remains_intact(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    headers = {"Authorization": f"Bearer {a9_env['admin_session_id']}"}
    root_admin = a9_env["root_admin"]
    second_admin = a9_env["second_admin"]

    # Demote second admin so root admin is the last active admin
    store.update_user_role(second_admin.user_id, UserRole.USER.value)

    resp = client.patch(
        f"/admin/users/{root_admin.user_id}/role",
        json={"role": "USER"},
        headers=headers,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Scenario 20: Self-admin protection remains intact (400)
# ---------------------------------------------------------------------------
def test_20_self_admin_protection_remains_intact(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['admin_session_id']}"}
    root_admin = a9_env["root_admin"]

    # Self-disable attempt
    resp_dis = client.patch(
        f"/admin/users/{root_admin.user_id}/status",
        json={"status": "DISABLED"},
        headers=headers,
    )
    assert resp_dis.status_code == 400
    assert "cannot disable their own account" in resp_dis.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 21: Deleted user cannot reuse old session (401)
# ---------------------------------------------------------------------------
def test_21_deleted_user_cannot_reuse_old_session(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    user = a9_env["std_user"]
    sid = a9_env["user_session_id"]

    # Revoke sessions and delete user
    store.revoke_user_sessions(user.user_id)
    store.delete_user(user.user_id)

    resp = client.get("/analyses", headers={"Authorization": f"Bearer {sid}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Scenario 22: Admin role changes take immediate effect
# ---------------------------------------------------------------------------
def test_22_admin_role_changes_take_immediate_effect(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    user = a9_env["std_user"]
    headers = {"Authorization": f"Bearer {a9_env['user_session_id']}"}

    assert client.get("/admin/users", headers=headers).status_code == 403

    # Promote to ADMIN in DB
    store.update_user_role(user.user_id, UserRole.ADMIN.value)

    # Next call with existing session MUST succeed immediately
    assert client.get("/admin/users", headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# Scenario 23: Disabled status overrides ADMIN role (403)
# ---------------------------------------------------------------------------
def test_23_disabled_status_overrides_admin_role(a9_env):
    client = a9_env["client"]
    store = a9_env["store"]
    admin = a9_env["second_admin"]
    store.update_user_status(admin.user_id, UserStatus.DISABLED.value)

    headers = {"Authorization": f"Bearer {a9_env['second_admin_session_id']}"}
    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403
    assert "disabled" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 24: Sensitive credentials are absent from responses
# ---------------------------------------------------------------------------
def test_24_sensitive_credentials_absent_from_responses(a9_env):
    client = a9_env["client"]
    headers = {"Authorization": f"Bearer {a9_env['admin_session_id']}"}

    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 200
    for u in resp.json().get("users", []):
        for sensitive_key in ["password", "token", "secret", "google_client_secret"]:
            assert sensitive_key not in u


# ---------------------------------------------------------------------------
# Scenario 25: Sensitive credentials are absent from logs where testable
# ---------------------------------------------------------------------------
def test_25_sensitive_credentials_absent_from_logs():
    test_token = "sess_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    sanitized = sanitize_sensitive_text(f"Session token: {test_token}")
    assert test_token not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

    gh_token = "ghp_1234567890abcdef1234567890abcdef"
    sanitized_gh = sanitize_sensitive_text(f"GitHub: {gh_token}")
    assert gh_token not in sanitized_gh
    assert "[REDACTED_SECRET]" in sanitized_gh


# ---------------------------------------------------------------------------
# Scenario 26: Auth tokens/roles absent from localStorage
# ---------------------------------------------------------------------------
def test_26_auth_tokens_roles_absent_from_localstorage():
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "src"))
    bad_patterns = [
        re.compile(r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
        re.compile(r"localStorage\[['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
    ]
    for root, _, files in os.walk(frontend_dir):
        for f in files:
            if f.endswith((".js", ".jsx", ".ts", ".tsx")):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fp:
                    content = fp.read()
                    for pat in bad_patterns:
                        assert not pat.search(content)


# ---------------------------------------------------------------------------
# Scenario 27: Auth tokens/roles absent from sessionStorage
# ---------------------------------------------------------------------------
def test_27_auth_tokens_roles_absent_from_sessionstorage():
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "src"))
    bad_patterns = [
        re.compile(r"sessionStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
        re.compile(r"sessionStorage\[['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
    ]
    for root, _, files in os.walk(frontend_dir):
        for f in files:
            if f.endswith((".js", ".jsx", ".ts", ".tsx")):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fp:
                    content = fp.read()
                    for pat in bad_patterns:
                        assert not pat.search(content)


# ---------------------------------------------------------------------------
# Scenario 28: CORS does not permit unauthorized credentialed origins
# ---------------------------------------------------------------------------
def test_28_cors_does_not_permit_unauthorized_origins(a9_env):
    client = a9_env["client"]
    resp = client.options(
        "/analyses",
        headers={
            "Origin": "https://malicious-attacker-site.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # The Access-Control-Allow-Origin must NOT reflect the untrusted malicious origin
    allow_origin = resp.headers.get("Access-Control-Allow-Origin")
    assert allow_origin != "https://malicious-attacker-site.com"
    assert allow_origin != "*"


# ---------------------------------------------------------------------------
# Scenario 29: Security headers are present as intended
# ---------------------------------------------------------------------------
def test_29_security_headers_present_as_intended(a9_env):
    client = a9_env["client"]
    resp = client.get("/platform/health")
    assert resp.status_code == 200
    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "Strict-Transport-Security" in headers
    assert "Permissions-Policy" in headers
    assert "Content-Security-Policy" in headers


# ---------------------------------------------------------------------------
# Scenario 30: Webhook remains HMAC protected
# ---------------------------------------------------------------------------
def test_30_webhook_remains_hmac_protected(a9_env, monkeypatch):
    client = a9_env["client"]
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "super_secret_webhook_key_abc")

    # Missing signature -> 401
    resp_missing = client.post("/github/webhook", json={"action": "opened"})
    assert resp_missing.status_code == 401
    assert "Missing X-Hub-Signature-256" in resp_missing.json().get("detail", "")

    # Forged signature -> 401
    resp_forged = client.post(
        "/github/webhook",
        json={"action": "opened"},
        headers={"X-Hub-Signature-256": "sha256=baddeadbeef00112233445566778899aabbccddeeff"},
    )
    assert resp_forged.status_code == 401
    assert "Invalid webhook signature" in resp_forged.json().get("detail", "")


# ---------------------------------------------------------------------------
# Scenario 31: Public health endpoints remain public
# ---------------------------------------------------------------------------
def test_31_public_health_endpoints_remain_public(a9_env):
    client = a9_env["client"]
    endpoints = ["/platform/health", "/platform/readiness", "/platform/readiness/release", "/platform/info"]
    for ep in endpoints:
        assert client.get(ep).status_code == 200


# ---------------------------------------------------------------------------
# Scenario 32: CLI remains operational offline
# ---------------------------------------------------------------------------
def test_32_cli_remains_operational_offline():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    result = subprocess.run(
        [sys.executable, "-m", "cli", "version"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "CodeSentinel" in result.stdout or "codesentinel" in result.stdout.lower()
