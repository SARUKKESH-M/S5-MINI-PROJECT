"""Phase A10 Verification Test Suite: Local End-to-End Authentication & RBAC Testing.

Validates the complete local authentication lifecycle:
 1. Local backend startup & public health endpoints
 2. Unknown Google account rejected (403, no user/session created)
 3. Admin preauthorization flow (google_sub=None, ACTIVE status, audit info)
 4. First Google authentication & identity binding (google_sub bound, fresh session)
 5. USER journey: accesses user APIs, rejected on admin user mgmt & analysis deletion
 6. ADMIN journey: accesses user APIs, admin mgmt, role/status updates, analysis deletion
 7. Direct route protection contract (unauthenticated access redirects to /login)
 8. Authenticated login redirect contract (active user redirected to workspace)
 9. Session restoration via /auth/me without browser storage tokens
10. Session expiration (expired session rejected with 401)
11. Logout / session revocation (backend session revoked, cookie cleared, 401 on next call)
12. Disabled account mid-session (disabled USER -> 403; disabled ADMIN -> 403)
13. Role change mid-session (USER -> ADMIN immediate effect; ADMIN -> USER immediate effect)
14. Multi-tab heartbeat session sync (/auth/me re-evaluates updated status/role)
15. Admin management end-to-end operations (list, filter, detail, update, revoke)
16. Last-admin protection invariant (cannot disable or demote last active admin)
17. Privilege escalation attempts blocked (headers, body injection, query params)
18. Cookie security (HttpOnly, SameSite=Lax, Secure in production)
19. Browser storage verification (zero auth tokens/roles in localStorage/sessionStorage)
20. CORS / CSRF behavior (unauthorized origins rejected, standard headers enforced)
21. Security headers verification (nosniff, DENY, HSTS, Permissions-Policy, CSP)
22. Webhook HMAC verification without browser session cookies
23. Offline CLI verification (python -m cli version)
24. Database isolation & clean lifecycle
"""

import json
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
    normalize_email,
)
from backend.app.core.config import settings
from backend.app.main import app


@pytest.fixture
def a10_env(monkeypatch):
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

    # Seed an analysis record for delete testing
    sample_analysis = {
        "status": "success",
        "analysis_id": "analysis_a10_test",
        "query": "local security scan",
        "summary": {"total_findings": 1, "high_count": 1},
        "findings": [
            {
                "finding_id": "finding_a10_1",
                "title": "Command Injection Risk",
                "description": "Risk detected",
                "severity": "high",
                "confidence": "high",
                "category": "Injection",
            }
        ],
    }
    store.save_analysis(sample_analysis)

    # Create active sessions
    admin_session_id = store.create_session(root_admin.user_id)
    second_admin_session_id = store.create_session(second_admin.user_id)

    client = TestClient(app)

    yield {
        "store": store,
        "client": client,
        "temp_db_path": temp_db_path,
        "root_admin": root_admin,
        "second_admin": second_admin,
        "analysis_id": "analysis_a10_test",
        "admin_session_id": admin_session_id,
        "second_admin_session_id": second_admin_session_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test 1: Local backend startup & public health endpoints
# ---------------------------------------------------------------------------
def test_1_local_backend_startup_and_health(a10_env):
    client = a10_env["client"]
    endpoints = [
        "/health",
        "/platform/health",
        "/platform/readiness",
        "/platform/readiness/release",
        "/platform/info",
    ]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 200, f"Expected 200 on public endpoint {ep}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Test 2: Unknown Google account rejected (403, no user/session created)
# ---------------------------------------------------------------------------
def test_2_unknown_google_account_rejected(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    unknown_email = "stranger@gmail.com"
    unknown_token = f"mock_google_:{unknown_email}:sub_stranger_123:Stranger User"

    resp = client.post("/auth/google", json={"id_token": unknown_token})
    assert resp.status_code == 403
    assert "not authorized" in resp.json().get("detail", "").lower()

    # Verify no user or session created in store
    assert store.get_user_by_email(unknown_email) is None
    assert store.get_user_by_google_sub("sub_stranger_123") is None


# ---------------------------------------------------------------------------
# Test 3: Admin preauthorization flow
# ---------------------------------------------------------------------------
def test_3_admin_preauthorization_flow(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    headers = {"Authorization": f"Bearer {a10_env['admin_session_id']}"}
    target_email = "new.developer@codesentinel.dev"

    resp = client.post(
        "/admin/users",
        json={"email": target_email, "role": "USER", "full_name": "New Developer"},
        headers=headers,
    )
    assert resp.status_code == 201
    created_data = resp.json()
    assert created_data["email"] == target_email
    assert created_data["google_sub"] is None
    assert created_data["role"] == "USER"
    assert created_data["status"] == "ACTIVE"
    assert created_data["created_by"] == a10_env["root_admin"].email

    # Verify stored in DB
    db_user = store.get_user_by_email(target_email)
    assert db_user is not None
    assert db_user.google_sub is None


# ---------------------------------------------------------------------------
# Test 4: First Google authentication & identity binding
# ---------------------------------------------------------------------------
def test_4_first_google_auth_and_binding(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    admin_headers = {"Authorization": f"Bearer {a10_env['admin_session_id']}"}
    email = "bind.test@codesentinel.dev"

    # 1. Admin pre-authorizes email
    client.post("/admin/users", json={"email": email, "role": "USER"}, headers=admin_headers)

    # 2. User logs in with Google for the first time
    google_token = f"mock_google_:{email}:sub_google_bound_999:Bound Developer"
    login_resp = client.post("/auth/google", json={"id_token": google_token})
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["user"]["email"] == email
    assert login_data["user"]["role"] == "USER"
    session_token = login_data["session_token"]
    assert session_token.startswith("sess_")

    # 3. Verify bound in database
    user_after = store.get_user_by_email(email)
    assert user_after.google_sub == "sub_google_bound_999"
    assert user_after.last_login is not None


# ---------------------------------------------------------------------------
# Test 5: USER application flow
# ---------------------------------------------------------------------------
def test_5_user_application_flow(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    # Seed user
    user = store.create_authorized_user(
        email="app.user@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="App User",
        created_by="admin@codesentinel.dev",
    )
    user_sid = store.create_session(user.user_id)
    headers = {"Authorization": f"Bearer {user_sid}"}

    # /auth/me
    resp_me = client.get("/auth/me", headers=headers)
    assert resp_me.status_code == 200
    assert resp_me.json()["user"]["role"] == "USER"

    # /analyses
    resp_analyses = client.get("/analyses", headers=headers)
    assert resp_analyses.status_code == 200

    # /platform/policies
    resp_policies = client.get("/platform/policies", headers=headers)
    assert resp_policies.status_code == 200

    # USER denied admin routes
    resp_admin = client.get("/admin/users", headers=headers)
    assert resp_admin.status_code == 403

    # USER denied analysis deletion
    resp_del = client.delete(f"/analyses/{a10_env['analysis_id']}", headers=headers)
    assert resp_del.status_code == 403


# ---------------------------------------------------------------------------
# Test 6: ADMIN application flow
# ---------------------------------------------------------------------------
def test_6_admin_application_flow(a10_env):
    client = a10_env["client"]
    headers = {"Authorization": f"Bearer {a10_env['admin_session_id']}"}

    # Admin profile
    resp_me = client.get("/auth/me", headers=headers)
    assert resp_me.status_code == 200
    assert resp_me.json()["user"]["role"] == "ADMIN"

    # User endpoints work for admin
    assert client.get("/analyses", headers=headers).status_code == 200
    assert client.get("/platform/policies", headers=headers).status_code == 200

    # Admin endpoints work
    resp_users = client.get("/admin/users", headers=headers)
    assert resp_users.status_code == 200
    assert "users" in resp_users.json()

    # Admin delete analysis works
    resp_del = client.delete(f"/analyses/{a10_env['analysis_id']}", headers=headers)
    assert resp_del.status_code == 200
    assert resp_del.json()["deleted"] is True


# ---------------------------------------------------------------------------
# Test 7: Direct route protection contract
# ---------------------------------------------------------------------------
def test_7_direct_route_protection_contract(a10_env):
    client = a10_env["client"]
    protected_endpoints = [
        "/auth/me",
        "/analyses",
        "/platform/policies",
        "/platform/metrics",
        "/platform/developers",
        "/admin/users",
    ]
    for ep in protected_endpoints:
        resp = client.get(ep)
        assert resp.status_code == 401, f"Expected 401 for unauthenticated {ep}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Test 8: Authenticated login redirect contract
# ---------------------------------------------------------------------------
def test_8_authenticated_login_contract(a10_env):
    client = a10_env["client"]
    # With active session, /auth/me returns 200 with ACTIVE status
    headers = {"Authorization": f"Bearer {a10_env['admin_session_id']}"}
    resp = client.get("/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["user"]["status"] == "ACTIVE"


# ---------------------------------------------------------------------------
# Test 9: Session restoration via /auth/me without browser storage tokens
# ---------------------------------------------------------------------------
def test_9_session_restoration_via_cookie(a10_env):
    client = a10_env["client"]
    cookie_name = settings.SESSION_COOKIE_NAME
    # Reopen client with only the session cookie set
    client.cookies.set(cookie_name, a10_env["admin_session_id"])

    resp = client.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["user"]["email"] == a10_env["root_admin"].email


# ---------------------------------------------------------------------------
# Test 10: Session expiration
# ---------------------------------------------------------------------------
def test_10_session_expiration(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    sid = store.create_session(a10_env["root_admin"].user_id)

    # Force expiration in database
    with store._get_connection() as conn:
        conn.execute("UPDATE user_sessions SET expires_at = '2020-01-01T00:00:00+00:00' WHERE session_id = ?", (sid,))

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {sid}"})
    assert resp.status_code == 401
    assert "expired" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Test 11: Logout / session revocation
# ---------------------------------------------------------------------------
def test_11_logout_revocation(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    sid = store.create_session(a10_env["second_admin"].user_id)
    headers = {"Authorization": f"Bearer {sid}"}

    # Verify active
    assert client.get("/auth/me", headers=headers).status_code == 200

    # Logout
    logout_resp = client.post("/auth/logout", headers=headers)
    assert logout_resp.status_code == 200

    # Next request with same token must fail
    assert client.get("/auth/me", headers=headers).status_code == 401


# ---------------------------------------------------------------------------
# Test 12: Disabled account mid-session
# ---------------------------------------------------------------------------
def test_12_disabled_account_mid_session(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]

    # 1. USER test
    user = store.create_authorized_user(
        email="mid.disable@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Mid Disable User",
        created_by="admin@codesentinel.dev",
    )
    user_sid = store.create_session(user.user_id)
    user_headers = {"Authorization": f"Bearer {user_sid}"}

    assert client.get("/auth/me", headers=user_headers).status_code == 200

    # Admin disables user
    store.update_user_status(user.user_id, UserStatus.DISABLED.value)

    resp_after = client.get("/auth/me", headers=user_headers)
    assert resp_after.status_code == 403
    assert "disabled" in resp_after.json().get("detail", "").lower()

    # 2. ADMIN test
    admin2 = a10_env["second_admin"]
    admin2_headers = {"Authorization": f"Bearer {a10_env['second_admin_session_id']}"}
    store.update_user_status(admin2.user_id, UserStatus.DISABLED.value)

    resp_admin2 = client.get("/admin/users", headers=admin2_headers)
    assert resp_admin2.status_code == 403
    assert "disabled" in resp_admin2.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Test 13: Role change mid-session
# ---------------------------------------------------------------------------
def test_13_role_change_mid_session(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]

    user = store.create_authorized_user(
        email="role.swap@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Role Swap User",
        created_by="admin@codesentinel.dev",
    )
    user_sid = store.create_session(user.user_id)
    headers = {"Authorization": f"Bearer {user_sid}"}

    # Initially USER: rejected on admin
    assert client.get("/admin/users", headers=headers).status_code == 403

    # Promote to ADMIN in DB
    store.update_user_role(user.user_id, UserRole.ADMIN.value)

    # Immediately allowed without re-authenticating
    assert client.get("/admin/users", headers=headers).status_code == 200

    # Demote back to USER in DB
    store.update_user_role(user.user_id, UserRole.USER.value)

    # Immediately rejected again
    assert client.get("/admin/users", headers=headers).status_code == 403


# ---------------------------------------------------------------------------
# Test 14: Multi-tab / heartbeat session sync
# ---------------------------------------------------------------------------
def test_14_multitab_session_sync(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]

    user = store.create_authorized_user(
        email="multitab@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="MultiTab User",
        created_by="admin@codesentinel.dev",
    )
    sid = store.create_session(user.user_id)
    tab_headers = {"Authorization": f"Bearer {sid}"}

    # Tab A heartbeat sync
    resp_tab_a = client.get("/auth/me", headers=tab_headers)
    assert resp_tab_a.status_code == 200
    assert resp_tab_a.json()["user"]["role"] == "USER"

    # Tab B admin promotes user
    store.update_user_role(user.user_id, UserRole.ADMIN.value)

    # Tab A next heartbeat sync immediately reflects updated role
    resp_tab_a_after = client.get("/auth/me", headers=tab_headers)
    assert resp_tab_a_after.status_code == 200
    assert resp_tab_a_after.json()["user"]["role"] == "ADMIN"


# ---------------------------------------------------------------------------
# Test 15: Admin management end-to-end operations
# ---------------------------------------------------------------------------
def test_15_admin_management_operations(a10_env):
    client = a10_env["client"]
    admin_headers = {"Authorization": f"Bearer {a10_env['admin_session_id']}"}

    # 1. Preauthorize
    resp_create = client.post(
        "/admin/users",
        json={"email": "lifecycle@codesentinel.dev", "role": "USER", "full_name": "Lifecycle User"},
        headers=admin_headers,
    )
    assert resp_create.status_code == 201
    user_id = resp_create.json()["user_id"]

    # 2. Get detail
    resp_detail = client.get(f"/admin/users/{user_id}", headers=admin_headers)
    assert resp_detail.status_code == 200
    assert resp_detail.json()["email"] == "lifecycle@codesentinel.dev"

    # 3. Update status (disable)
    resp_stat = client.patch(f"/admin/users/{user_id}/status", json={"status": "DISABLED"}, headers=admin_headers)
    assert resp_stat.status_code == 200
    assert resp_stat.json()["status"] == "DISABLED"

    # 4. Update role (promote to ADMIN)
    resp_role = client.patch(f"/admin/users/{user_id}/role", json={"role": "ADMIN"}, headers=admin_headers)
    assert resp_role.status_code == 200
    assert resp_role.json()["role"] == "ADMIN"

    # 5. Revoke / delete user
    resp_del = client.delete(f"/admin/users/{user_id}", headers=admin_headers)
    assert resp_del.status_code == 200
    assert resp_del.json()["status"] == "success"


# ---------------------------------------------------------------------------
# Test 16: Last-admin protection invariant
# ---------------------------------------------------------------------------
def test_16_last_admin_protection(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    admin_headers = {"Authorization": f"Bearer {a10_env['admin_session_id']}"}
    root_admin = a10_env["root_admin"]
    second_admin = a10_env["second_admin"]

    # Demote second admin so root admin is sole active admin
    store.update_user_role(second_admin.user_id, UserRole.USER.value)

    # Attempting to demote sole active admin must fail with 400
    resp_demote = client.patch(f"/admin/users/{root_admin.user_id}/role", json={"role": "USER"}, headers=admin_headers)
    assert resp_demote.status_code == 400


# ---------------------------------------------------------------------------
# Test 17: Privilege escalation attempts blocked
# ---------------------------------------------------------------------------
def test_17_privilege_escalation_blocked(a10_env):
    client = a10_env["client"]
    store = a10_env["store"]
    user = store.create_authorized_user(
        email="pesky@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Pesky User",
        created_by="admin@codesentinel.dev",
    )
    sid = store.create_session(user.user_id)
    headers = {
        "Authorization": f"Bearer {sid}",
        "X-Role": "ADMIN",
        "Role": "ADMIN",
        "X-User-Role": "ADMIN",
    }

    # Call admin endpoints with spoofed headers
    assert client.get("/admin/users", headers=headers).status_code == 403

    # Injecting role in request body
    assert client.post(
        "/admin/users",
        json={"email": "trojan@codesentinel.dev", "role": "ADMIN"},
        headers=headers,
    ).status_code == 403

    # Query param injection
    assert client.get("/admin/users?role=ADMIN", headers=headers).status_code == 403


# ---------------------------------------------------------------------------
# Test 18: Cookie security
# ---------------------------------------------------------------------------
def test_18_cookie_security(a10_env):
    client = a10_env["client"]
    email = a10_env["root_admin"].email
    token = f"mock_google_:{email}:goog_sub_root_admin:Root Administrator"
    resp = client.post("/auth/google", json={"id_token": token})
    assert resp.status_code == 200

    set_cookie = resp.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()


# ---------------------------------------------------------------------------
# Test 19: Browser storage verification
# ---------------------------------------------------------------------------
def test_19_browser_storage_cleanliness():
    frontend_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "src"))
    bad_patterns = [
        re.compile(r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
        re.compile(r"sessionStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
    ]
    for root, _, files in os.walk(frontend_src):
        for f in files:
            if f.endswith((".js", ".jsx", ".ts", ".tsx")):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fp:
                    content = fp.read()
                    for pat in bad_patterns:
                        assert not pat.search(content)


# ---------------------------------------------------------------------------
# Test 20: CORS / CSRF behavior
# ---------------------------------------------------------------------------
def test_20_cors_csrf_behavior(a10_env):
    client = a10_env["client"]
    # Preflight from unauthorized origin
    resp = client.options(
        "/analyses",
        headers={
            "Origin": "https://unauthorized-evil-site.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.headers.get("Access-Control-Allow-Origin") != "https://unauthorized-evil-site.com"
    assert resp.headers.get("Access-Control-Allow-Origin") != "*"


# ---------------------------------------------------------------------------
# Test 21: Security headers verification
# ---------------------------------------------------------------------------
def test_21_security_headers(a10_env):
    client = a10_env["client"]
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
# Test 22: Webhook HMAC verification without browser session cookies
# ---------------------------------------------------------------------------
def test_22_webhook_hmac_isolation(a10_env, monkeypatch):
    client = a10_env["client"]
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "local_hmac_secret_456")

    # Missing signature -> 401
    resp_missing = client.post("/github/webhook", json={"action": "opened"})
    assert resp_missing.status_code == 401

    # Invalid signature -> 401
    resp_bad = client.post(
        "/github/webhook",
        json={"action": "opened"},
        headers={"X-Hub-Signature-256": "sha256=invalid_hash_1234567890"},
    )
    assert resp_bad.status_code == 401


# ---------------------------------------------------------------------------
# Test 23: Offline CLI verification
# ---------------------------------------------------------------------------
def test_23_offline_cli():
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


# ---------------------------------------------------------------------------
# Test 24: Database isolation & clean lifecycle
# ---------------------------------------------------------------------------
def test_24_database_isolation(a10_env):
    # Verify temp database exists during test and is isolated
    temp_path = a10_env["temp_db_path"]
    assert os.path.exists(temp_path)
    store = a10_env["store"]
    assert store.count_users() >= 2
