"""Phase A8 Verification Test Suite: Role-Based Access Control (RBAC).

Tests all 27 required A8 scenarios:
1. Unauthenticated USER endpoint → 401
2. Unauthenticated ADMIN endpoint → 401
3. ACTIVE USER can access USER endpoint
4. ACTIVE USER cannot access Admin endpoint (403)
5. ACTIVE ADMIN can access USER endpoint
6. ACTIVE ADMIN can access Admin endpoint
7. DISABLED USER → 403
8. DISABLED ADMIN → 403
9. USER cannot list Admin users (403)
10. USER cannot create/pre-authorize users (403)
11. USER cannot modify status (403)
12. USER cannot modify roles (403)
13. USER cannot revoke users (403)
14. USER cannot delete analyses (403)
15. ADMIN can delete analyses (200)
16. USER → ADMIN role change takes effect immediately on same session
17. ADMIN → USER role change takes effect immediately on same session
18. Disabled status overrides ADMIN role (403)
19. Frontend role headers cannot elevate backend privileges
20. Request-body role cannot elevate caller privileges
21. Public health & readiness endpoints remain public
22. GitHub webhook remains HMAC protected
23. CLI remains operational offline
24. No auth roles/tokens stored in localStorage
25. No auth roles/tokens stored in sessionStorage
26. Existing A7 self-protection remains intact
27. Last-active-admin protection remains intact
"""

import os
import re
import subprocess
import sys
import tempfile
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
from backend.app.main import app


@pytest.fixture
def a8_env(monkeypatch):
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

    # Seed Second Admin (to allow role change tests without violating last-admin invariant)
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

    # Seed an analysis record for delete testing
    sample_analysis = {
        "status": "success",
        "analysis_id": "analysis_demo_100",
        "query": "security scan",
        "summary": {"total_findings": 1, "high_count": 1},
        "findings": [
            {
                "finding_id": "finding_100",
                "title": "SQL Injection Risk",
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
    user_session_id = store.create_session(std_user.user_id)

    client = TestClient(app)

    yield {
        "store": store,
        "client": client,
        "root_admin": root_admin,
        "second_admin": second_admin,
        "std_user": std_user,
        "analysis_id": "analysis_demo_100",
        "admin_session_id": admin_session_id,
        "second_admin_session_id": second_admin_session_id,
        "user_session_id": user_session_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scenario 1: Unauthenticated USER endpoint → 401
# ---------------------------------------------------------------------------
def test_1_unauthenticated_user_endpoint_401(a8_env):
    client = a8_env["client"]
    resp = client.get("/analyses")
    assert resp.status_code == 401
    assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Scenario 2: Unauthenticated ADMIN endpoint → 401
# ---------------------------------------------------------------------------
def test_2_unauthenticated_admin_endpoint_401(a8_env):
    client = a8_env["client"]
    resp = client.get("/admin/users")
    assert resp.status_code == 401

    resp_del = client.delete(f"/analyses/{a8_env['analysis_id']}")
    assert resp_del.status_code == 401


# ---------------------------------------------------------------------------
# Scenario 3: ACTIVE USER can access USER endpoint
# ---------------------------------------------------------------------------
def test_3_active_user_can_access_user_endpoint(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.get("/analyses", headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("status") == "success"

    resp_pol = client.get("/platform/policies", headers=headers)
    assert resp_pol.status_code == 200

    resp_me = client.get("/auth/me", headers=headers)
    assert resp_me.status_code == 200
    assert resp_me.json().get("user", {}).get("role") == "USER"


# ---------------------------------------------------------------------------
# Scenario 4: ACTIVE USER cannot access Admin endpoint (403)
# ---------------------------------------------------------------------------
def test_4_active_user_cannot_access_admin_endpoint_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403
    assert "administrative privileges required" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 5: ACTIVE ADMIN can access USER endpoint
# ---------------------------------------------------------------------------
def test_5_active_admin_can_access_user_endpoint(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['admin_session_id']}"}

    resp = client.get("/analyses", headers=headers)
    assert resp.status_code == 200

    resp_pol = client.get("/platform/policies", headers=headers)
    assert resp_pol.status_code == 200


# ---------------------------------------------------------------------------
# Scenario 6: ACTIVE ADMIN can access Admin endpoint
# ---------------------------------------------------------------------------
def test_6_active_admin_can_access_admin_endpoint(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['admin_session_id']}"}

    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 200
    assert "users" in resp.json()
    assert isinstance(resp.json().get("users"), list)


# ---------------------------------------------------------------------------
# Scenario 7: DISABLED USER → 403
# ---------------------------------------------------------------------------
def test_7_disabled_user_cannot_access_endpoints_403(a8_env):
    client = a8_env["client"]
    store = a8_env["store"]
    user = a8_env["std_user"]

    # Disable user
    store.update_user_status(user.user_id, UserStatus.DISABLED.value)

    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}
    resp = client.get("/analyses", headers=headers)
    assert resp.status_code == 403
    assert "disabled" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 8: DISABLED ADMIN → 403
# ---------------------------------------------------------------------------
def test_8_disabled_admin_cannot_access_endpoints_403(a8_env):
    client = a8_env["client"]
    store = a8_env["store"]
    admin2 = a8_env["second_admin"]

    # Disable admin2
    store.update_user_status(admin2.user_id, UserStatus.DISABLED.value)

    headers = {"Authorization": f"Bearer {a8_env['second_admin_session_id']}"}

    # Should be rejected on both admin and user endpoints
    resp_admin = client.get("/admin/users", headers=headers)
    assert resp_admin.status_code == 403
    assert "disabled" in resp_admin.json().get("detail", "").lower()

    resp_user = client.get("/analyses", headers=headers)
    assert resp_user.status_code == 403
    assert "disabled" in resp_user.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 9: USER cannot list Admin users (403)
# ---------------------------------------------------------------------------
def test_9_user_cannot_list_admin_users_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 10: USER cannot create/pre-authorize users (403)
# ---------------------------------------------------------------------------
def test_10_user_cannot_create_or_preauthorize_users_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.post(
        "/admin/users",
        json={"email": "newbie@codesentinel.dev", "role": "USER"},
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 11: USER cannot modify status (403)
# ---------------------------------------------------------------------------
def test_11_user_cannot_modify_status_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.patch(
        f"/admin/users/{a8_env['second_admin'].user_id}/status",
        json={"status": "DISABLED"},
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 12: USER cannot modify roles (403)
# ---------------------------------------------------------------------------
def test_12_user_cannot_modify_roles_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.patch(
        f"/admin/users/{a8_env['std_user'].user_id}/role",
        json={"role": "ADMIN"},
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 13: USER cannot revoke users (403)
# ---------------------------------------------------------------------------
def test_13_user_cannot_revoke_users_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.delete(
        f"/admin/users/{a8_env['second_admin'].user_id}",
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 14: USER cannot delete analyses (403)
# ---------------------------------------------------------------------------
def test_14_user_cannot_delete_analyses_403(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.delete(f"/analyses/{a8_env['analysis_id']}", headers=headers)
    assert resp.status_code == 403
    assert "administrative privileges required" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 15: ADMIN can delete analyses (200)
# ---------------------------------------------------------------------------
def test_15_admin_can_delete_analyses_200(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['admin_session_id']}"}

    resp = client.delete(f"/analyses/{a8_env['analysis_id']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("deleted") is True


# ---------------------------------------------------------------------------
# Scenario 16: USER → ADMIN role change takes effect immediately on same session
# ---------------------------------------------------------------------------
def test_16_user_to_admin_role_change_immediate_effect(a8_env):
    client = a8_env["client"]
    store = a8_env["store"]
    user = a8_env["std_user"]
    user_headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    # Verify initial failure on admin endpoint
    resp_init = client.get("/admin/users", headers=user_headers)
    assert resp_init.status_code == 403

    # Promote to ADMIN in DB
    store.update_user_role(user.user_id, UserRole.ADMIN.value)

    # Next call with existing session MUST succeed immediately
    resp_after = client.get("/admin/users", headers=user_headers)
    assert resp_after.status_code == 200
    assert "users" in resp_after.json()


# ---------------------------------------------------------------------------
# Scenario 17: ADMIN → USER role change takes effect immediately on same session
# ---------------------------------------------------------------------------
def test_17_admin_to_user_role_change_immediate_effect(a8_env):
    client = a8_env["client"]
    store = a8_env["store"]
    admin2 = a8_env["second_admin"]
    admin2_headers = {"Authorization": f"Bearer {a8_env['second_admin_session_id']}"}

    # Verify initial success on admin endpoint
    resp_init = client.get("/admin/users", headers=admin2_headers)
    assert resp_init.status_code == 200

    # Demote to USER in DB
    store.update_user_role(admin2.user_id, UserRole.USER.value)

    # Next call with existing session MUST fail immediately
    resp_after = client.get("/admin/users", headers=admin2_headers)
    assert resp_after.status_code == 403
    assert "administrative privileges required" in resp_after.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 18: Disabled status overrides ADMIN role (403)
# ---------------------------------------------------------------------------
def test_18_disabled_status_overrides_admin_role_403(a8_env):
    client = a8_env["client"]
    store = a8_env["store"]
    admin = a8_env["second_admin"]
    admin_headers = {"Authorization": f"Bearer {a8_env['second_admin_session_id']}"}

    # User has ADMIN role, but status is set to DISABLED
    store.update_user_status(admin.user_id, UserStatus.DISABLED.value)

    resp = client.get("/admin/users", headers=admin_headers)
    assert resp.status_code == 403
    # Must report disabled, NOT allow access because role is ADMIN
    assert "disabled" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 19: Frontend role headers cannot elevate backend privileges
# ---------------------------------------------------------------------------
def test_19_frontend_role_cannot_elevate_backend_privileges(a8_env):
    client = a8_env["client"]
    headers = {
        "Authorization": f"Bearer {a8_env['user_session_id']}",
        "X-User-Role": "ADMIN",
        "X-Role": "ADMIN",
        "Role": "ADMIN",
    }

    resp = client.get("/admin/users", headers=headers)
    assert resp.status_code == 403
    assert "administrative privileges required" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 20: Request-body role cannot elevate caller privileges
# ---------------------------------------------------------------------------
def test_20_request_body_role_cannot_elevate_caller_privileges(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['user_session_id']}"}

    resp = client.post(
        "/admin/users",
        json={"email": "attacker@codesentinel.dev", "role": "ADMIN"},
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 21: Public health & readiness endpoints remain public
# ---------------------------------------------------------------------------
def test_21_public_health_and_readiness_endpoints_remain_public(a8_env):
    client = a8_env["client"]

    endpoints = [
        "/platform/health",
        "/platform/readiness",
        "/platform/readiness/release",
        "/platform/info",
    ]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 200, f"Expected 200 for public endpoint {ep}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Scenario 22: GitHub webhook remains HMAC protected
# ---------------------------------------------------------------------------
def test_22_github_webhook_remains_hmac_protected(a8_env, monkeypatch):
    client = a8_env["client"]
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "test_webhook_secret_key_123")

    # Without HMAC signature, it must reject with 401 Unauthorized
    resp = client.post(
        "/github/webhook",
        json={"action": "opened"},
        headers={"X-GitHub-Event": "pull_request"},
    )
    assert resp.status_code == 401
    assert "Missing X-Hub-Signature-256 header" in resp.json().get("detail", "")


# ---------------------------------------------------------------------------
# Scenario 23: CLI remains operational offline
# ---------------------------------------------------------------------------
def test_23_cli_remains_operational_offline():
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
# Scenario 24: No auth roles or tokens stored in localStorage
# ---------------------------------------------------------------------------
def test_24_no_auth_roles_or_tokens_in_localstorage():
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "src"))
    bad_patterns = [
        re.compile(r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
        re.compile(r"localStorage\[['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
    ]

    for root, _, files in os.walk(frontend_dir):
        for f in files:
            if f.endswith((".js", ".jsx", ".ts", ".tsx")):
                filepath = os.path.join(root, f)
                with open(filepath, "r", encoding="utf-8") as fp:
                    content = fp.read()
                    for pat in bad_patterns:
                        assert not pat.search(content), f"Forbidden storage pattern in {filepath}"


# ---------------------------------------------------------------------------
# Scenario 25: No auth roles or tokens stored in sessionStorage
# ---------------------------------------------------------------------------
def test_25_no_auth_roles_or_tokens_in_sessionstorage():
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "src"))
    bad_patterns = [
        re.compile(r"sessionStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
        re.compile(r"sessionStorage\[['\"][^'\"]*(?:token|auth|role|session)", re.IGNORECASE),
    ]

    for root, _, files in os.walk(frontend_dir):
        for f in files:
            if f.endswith((".js", ".jsx", ".ts", ".tsx")):
                filepath = os.path.join(root, f)
                with open(filepath, "r", encoding="utf-8") as fp:
                    content = fp.read()
                    for pat in bad_patterns:
                        assert not pat.search(content), f"Forbidden storage pattern in {filepath}"


# ---------------------------------------------------------------------------
# Scenario 26: Existing A7 self-protection remains intact
# ---------------------------------------------------------------------------
def test_26_existing_a7_self_protection_intact(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['admin_session_id']}"}
    root_admin = a8_env["root_admin"]

    # Root admin attempting self-demotion
    resp = client.patch(
        f"/admin/users/{root_admin.user_id}/role",
        json={"role": "USER"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "cannot demote their own role" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Scenario 27: Last-active-admin protection remains intact
# ---------------------------------------------------------------------------
def test_27_last_active_admin_protection_intact(a8_env):
    client = a8_env["client"]
    headers = {"Authorization": f"Bearer {a8_env['admin_session_id']}"}
    root_admin = a8_env["root_admin"]
    second_admin = a8_env["second_admin"]

    # Demote second admin so root admin is the only active admin remaining
    demote_res = client.patch(
        f"/admin/users/{second_admin.user_id}/role",
        json={"role": "USER"},
        headers=headers,
    )
    assert demote_res.status_code == 200

    # Self-disable or self-demote of the sole remaining admin is rejected
    resp_disable = client.patch(
        f"/admin/users/{root_admin.user_id}/status",
        json={"status": "DISABLED"},
        headers=headers,
    )
    assert resp_disable.status_code == 400
    assert any(
        msg in resp_disable.json().get("detail", "").lower()
        for msg in ["cannot disable", "last active administrator"]
    )

    resp_demote = client.patch(
        f"/admin/users/{root_admin.user_id}/role",
        json={"role": "USER"},
        headers=headers,
    )
    assert resp_demote.status_code == 400
    assert any(
        msg in resp_demote.json().get("detail", "").lower()
        for msg in ["cannot demote", "last active administrator"]
    )
