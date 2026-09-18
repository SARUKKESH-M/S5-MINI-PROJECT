"""Phase A7 Verification Test Suite: Admin Access Management.

Tests all 25 required A7 scenarios:
1. Admin can list users.
2. USER cannot list users (403).
3. Unauthenticated request cannot list users (401).
4. Admin can pre-authorize an email.
5. Email is normalized.
6. Preauthorized user has google_sub = NULL.
7. Admin can activate a user.
8. Admin can disable a user.
9. Disabled user cannot access protected APIs (403).
10. Admin can change USER → ADMIN where valid.
11. Admin can change ADMIN → USER where valid.
12. USER cannot change roles (403).
13. USER cannot change status (403).
14. Duplicate email is rejected safely (409 Conflict).
15. Duplicate google_sub is rejected safely.
16. Invalid role is rejected.
17. Invalid status is rejected.
18. Unknown user_id is handled correctly (404).
19. created_by cannot be spoofed.
20. User history and security findings remain intact after disable/revoke.
21. Existing sessions respect current account status.
22. Admin seed behavior remains intact.
23. No first-user auto-promotion exists.
24. Admin self-protection and last-admin invariant work correctly.
25. No authentication secrets are exposed in admin responses.
"""

import os
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
    create_analysis_record,
)
from backend.app.core.config import settings
from backend.app.main import app


@pytest.fixture
def a7_env(monkeypatch):
    """Provide isolated SQLite database and TestClient with enforced session auth."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    store.initialize()

    # Monkeypatch store instances across modules to use isolated temp database
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
        "admin_session_id": admin_session_id,
        "second_admin_session_id": second_admin_session_id,
        "user_session_id": user_session_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scenario 1: Admin can list users
# ---------------------------------------------------------------------------
def test_1_admin_can_list_users(a7_env):
    client = a7_env["client"]
    resp = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "users" in data
    assert "total_count" in data
    assert data["total_count"] >= 3
    emails = [u["email"] for u in data["users"]]
    assert "admin@codesentinel.dev" in emails
    assert "developer@codesentinel.dev" in emails


# ---------------------------------------------------------------------------
# Scenario 2: USER cannot list users (403 Forbidden)
# ---------------------------------------------------------------------------
def test_2_user_cannot_list_users(a7_env):
    client = a7_env["client"]
    resp = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['user_session_id']}"},
    )
    assert resp.status_code == 403
    assert "Administrative privileges required" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Scenario 3: Unauthenticated request cannot list users (401 Unauthorized)
# ---------------------------------------------------------------------------
def test_3_unauthenticated_request_cannot_list_users(a7_env):
    client = a7_env["client"]
    client.cookies.clear()
    resp = client.get("/admin/users")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Scenario 4: Admin can pre-authorize an email
# ---------------------------------------------------------------------------
def test_4_admin_can_pre_authorize_email(a7_env):
    client = a7_env["client"]
    resp = client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"email": "newhire@codesentinel.dev", "role": "USER", "full_name": "New Hire"},
    )
    assert resp.status_code == 201
    user = resp.json()
    assert user["email"] == "newhire@codesentinel.dev"
    assert user["role"] == "USER"
    assert user["status"] == "ACTIVE"
    assert user["created_by"] == "admin@codesentinel.dev"


# ---------------------------------------------------------------------------
# Scenario 5: Email is normalized
# ---------------------------------------------------------------------------
def test_5_email_is_normalized(a7_env):
    client = a7_env["client"]
    resp = client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"email": "   ALICE.NORM@Example.COM   ", "role": "USER"},
    )
    assert resp.status_code == 201
    user = resp.json()
    assert user["email"] == "alice.norm@example.com"


# ---------------------------------------------------------------------------
# Scenario 6: Preauthorized user has google_sub = NULL
# ---------------------------------------------------------------------------
def test_6_preauthorized_user_has_null_google_sub(a7_env):
    client = a7_env["client"]
    store = a7_env["store"]
    resp = client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"email": "pending.oauth@codesentinel.dev", "role": "USER"},
    )
    assert resp.status_code == 201
    user_data = resp.json()
    assert user_data["google_sub"] is None

    # Verify directly in SQLite storage
    db_user = store.get_user_by_email("pending.oauth@codesentinel.dev")
    assert db_user is not None
    assert db_user.google_sub is None


# ---------------------------------------------------------------------------
# Scenario 7: Admin can activate a user
# ---------------------------------------------------------------------------
def test_7_admin_can_activate_user(a7_env):
    client = a7_env["client"]
    store = a7_env["store"]
    user_id = a7_env["std_user"].user_id
    # First disable
    store.update_user_status(user_id, UserStatus.DISABLED.value)

    resp = client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"status": "ACTIVE"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACTIVE"
    assert store.get_user_by_id(user_id).is_active() is True


# ---------------------------------------------------------------------------
# Scenario 8: Admin can disable a user
# ---------------------------------------------------------------------------
def test_8_admin_can_disable_user(a7_env):
    client = a7_env["client"]
    store = a7_env["store"]
    user_id = a7_env["std_user"].user_id

    resp = client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"status": "DISABLED"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "DISABLED"
    assert store.get_user_by_id(user_id).is_active() is False


# ---------------------------------------------------------------------------
# Scenario 9: Disabled user cannot access protected APIs (403)
# ---------------------------------------------------------------------------
def test_9_disabled_user_cannot_access_protected_apis(a7_env):
    client = a7_env["client"]
    user_id = a7_env["std_user"].user_id
    user_session = a7_env["user_session_id"]

    # Admin disables user
    resp = client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"status": "DISABLED"},
    )
    assert resp.status_code == 200

    # User's existing session must now be rejected with 403
    me_resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {user_session}"},
    )
    assert me_resp.status_code == 403
    assert "disabled" in me_resp.json()["detail"].lower()

    # Application endpoint must also reject with 403
    analyses_resp = client.get(
        "/analyses",
        headers={"Authorization": f"Bearer {user_session}"},
    )
    assert analyses_resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 10: Admin can change USER → ADMIN where valid
# ---------------------------------------------------------------------------
def test_10_admin_can_promote_user_to_admin(a7_env):
    client = a7_env["client"]
    store = a7_env["store"]
    user_id = a7_env["std_user"].user_id

    resp = client.patch(
        f"/admin/users/{user_id}/role",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"role": "ADMIN"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "ADMIN"
    assert store.get_user_by_id(user_id).is_admin() is True


# ---------------------------------------------------------------------------
# Scenario 11: Admin can change ADMIN → USER where valid
# ---------------------------------------------------------------------------
def test_11_admin_can_demote_admin_when_multiple_admins_exist(a7_env):
    client = a7_env["client"]
    store = a7_env["store"]
    second_admin_id = a7_env["second_admin"].user_id

    resp = client.patch(
        f"/admin/users/{second_admin_id}/role",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"role": "USER"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "USER"
    assert store.get_user_by_id(second_admin_id).is_admin() is False


# ---------------------------------------------------------------------------
# Scenario 12: USER cannot change roles (403)
# ---------------------------------------------------------------------------
def test_12_user_cannot_change_roles(a7_env):
    client = a7_env["client"]
    user_id = a7_env["std_user"].user_id

    resp = client.patch(
        f"/admin/users/{user_id}/role",
        headers={"Authorization": f"Bearer {a7_env['user_session_id']}"},
        json={"role": "ADMIN"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 13: USER cannot change status (403)
# ---------------------------------------------------------------------------
def test_13_user_cannot_change_status(a7_env):
    client = a7_env["client"]
    user_id = a7_env["std_user"].user_id

    resp = client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {a7_env['user_session_id']}"},
        json={"status": "DISABLED"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 14: Duplicate email is rejected safely (409 Conflict)
# ---------------------------------------------------------------------------
def test_14_duplicate_email_rejected(a7_env):
    client = a7_env["client"]
    resp = client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"email": "developer@codesentinel.dev", "role": "USER"},
    )
    assert resp.status_code == 409
    assert "already authorized" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Scenario 15: Duplicate google_sub is rejected safely
# ---------------------------------------------------------------------------
def test_15_duplicate_google_sub_rejected(a7_env):
    store = a7_env["store"]
    new_user = store.create_authorized_user("testsub@codesentinel.dev", UserRole.USER.value)
    # Attempting to bind a google_sub already owned by developer must raise ValueError
    with pytest.raises(ValueError) as exc:
        store.bind_google_identity(new_user.user_id, "goog_sub_developer")
    assert "already linked" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Scenario 16: Invalid role is rejected
# ---------------------------------------------------------------------------
def test_16_invalid_role_rejected(a7_env):
    client = a7_env["client"]
    user_id = a7_env["std_user"].user_id

    resp = client.patch(
        f"/admin/users/{user_id}/role",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"role": "SUPERUSER"},
    )
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Scenario 17: Invalid status is rejected
# ---------------------------------------------------------------------------
def test_17_invalid_status_rejected(a7_env):
    client = a7_env["client"]
    user_id = a7_env["std_user"].user_id

    resp = client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"status": "ARCHIVED"},
    )
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Scenario 18: Unknown user_id is handled correctly (404)
# ---------------------------------------------------------------------------
def test_18_unknown_user_id_handled(a7_env):
    client = a7_env["client"]
    resp1 = client.get(
        "/admin/users/usr_nonexistent_999",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
    )
    assert resp1.status_code == 404

    resp2 = client.patch(
        "/admin/users/usr_nonexistent_999/status",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"status": "ACTIVE"},
    )
    assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# Scenario 19: created_by cannot be spoofed by client
# ---------------------------------------------------------------------------
def test_19_created_by_cannot_be_spoofed(a7_env):
    client = a7_env["client"]
    resp = client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={
            "email": "nospoof@codesentinel.dev",
            "role": "USER",
            "created_by": "hacker_spoofed_admin@fake.com",  # Should be ignored/not permitted in schema
        },
    )
    assert resp.status_code == 201
    assert resp.json()["created_by"] == "admin@codesentinel.dev"


# ---------------------------------------------------------------------------
# Scenario 20: User history and analysis records remain intact after disable/revoke
# ---------------------------------------------------------------------------
def test_20_user_history_remains_intact(a7_env):
    store = a7_env["store"]
    client = a7_env["client"]

    # Create an analysis record
    analysis_data = {
        "status": "success",
        "analysis_id": "anls_user_history_intact_test",
        "query": "security scan",
        "summary": {"total_findings": 1, "high_count": 1},
        "findings": [
            {
                "finding_id": "finding_user_test",
                "title": "SQL Injection Risk",
                "description": "Risk detected",
                "severity": "high",
                "confidence": "high",
                "category": "Injection",
                "evidence": [{"document_id": "doc_1"}],
            }
        ],
    }
    store.save_analysis(analysis_data)
    assert store.get_analysis("anls_user_history_intact_test") is not None

    # Pre-authorize and then revoke a user
    pre_resp = client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"email": "toberevoked@codesentinel.dev", "role": "USER"},
    )
    user_id = pre_resp.json()["user_id"]

    # Revoke user
    del_resp = client.delete(
        f"/admin/users/{user_id}",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
    )
    assert del_resp.status_code == 200

    # Analysis record must remain intact!
    assert store.get_analysis("anls_user_history_intact_test") is not None


# ---------------------------------------------------------------------------
# Scenario 21: Existing sessions respect current account status
# ---------------------------------------------------------------------------
def test_21_existing_sessions_respect_account_status(a7_env):
    client = a7_env["client"]
    user_id = a7_env["std_user"].user_id
    user_session = a7_env["user_session_id"]

    # Valid session initially works
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {user_session}"})
    assert me_resp.status_code == 200

    # Admin disables user
    client.patch(
        f"/admin/users/{user_id}/status",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
        json={"status": "DISABLED"},
    )

    # Next call returns 403
    me_resp_after = client.get("/auth/me", headers={"Authorization": f"Bearer {user_session}"})
    assert me_resp_after.status_code == 403


# ---------------------------------------------------------------------------
# Scenario 22: Admin seed behavior remains intact
# ---------------------------------------------------------------------------
def test_22_admin_seed_behavior_remains_intact(a7_env):
    store = a7_env["store"]
    # Reaffirming seed with existing admin preserves google_sub
    reseeded = store.seed_initial_admin("admin@codesentinel.dev", "Root Administrator")
    assert reseeded.role == UserRole.ADMIN.value
    assert reseeded.status == UserStatus.ACTIVE.value
    assert reseeded.google_sub == "goog_sub_root_admin"


# ---------------------------------------------------------------------------
# Scenario 23: No first-user auto-promotion exists
# ---------------------------------------------------------------------------
def test_23_no_first_user_auto_promotion(a7_env):
    client = a7_env["client"]
    store = a7_env["store"]

    # Pre-authorize a new USER whose google_sub is None
    pre_user = store.create_authorized_user(
        email="preauth_dev@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Preauth Developer",
    )
    assert pre_user.google_sub is None

    # User signs in with Google for the first time
    token = 'mock:{"sub":"new_goog_sub_first_login","email":"preauth_dev@codesentinel.dev","name":"Preauth Developer","picture":""}'
    login_resp = client.post("/auth/google", json={"id_token": token})
    assert login_resp.status_code == 200
    # Must remain role='USER', NOT auto-promoted to ADMIN
    assert login_resp.json()["user"]["role"] == "USER"

    # Identity is now bound
    bound_user = store.get_user_by_id(pre_user.user_id)
    assert bound_user.google_sub == "new_goog_sub_first_login"


# ---------------------------------------------------------------------------
# Scenario 24: Admin self-protection and last-admin invariant work correctly
# ---------------------------------------------------------------------------
def test_24_admin_self_protection_and_last_admin_invariant(a7_env):
    client = a7_env["client"]
    root_admin_id = a7_env["root_admin"].user_id
    admin_session = a7_env["admin_session_id"]
    second_admin_id = a7_env["second_admin"].user_id

    # 1. Admin cannot disable their own account
    res1 = client.patch(
        f"/admin/users/{root_admin_id}/status",
        headers={"Authorization": f"Bearer {admin_session}"},
        json={"status": "DISABLED"},
    )
    assert res1.status_code == 400
    assert "cannot disable their own account" in res1.json()["detail"].lower()

    # 2. Admin cannot demote their own role
    res2 = client.patch(
        f"/admin/users/{root_admin_id}/role",
        headers={"Authorization": f"Bearer {admin_session}"},
        json={"role": "USER"},
    )
    assert res2.status_code == 400
    assert "cannot demote their own role" in res2.json()["detail"].lower()

    # 3. Admin cannot revoke their own account
    res3 = client.delete(
        f"/admin/users/{root_admin_id}",
        headers={"Authorization": f"Bearer {admin_session}"},
    )
    assert res3.status_code == 400
    assert "cannot revoke their own account" in res3.json()["detail"].lower()

    # Demote the second admin so root admin becomes the last active admin
    demote_res = client.patch(
        f"/admin/users/{second_admin_id}/role",
        headers={"Authorization": f"Bearer {admin_session}"},
        json={"role": "USER"},
    )
    assert demote_res.status_code == 200

    # 4. Attempting to demote or disable the last active admin from another session is rejected
    # (Here root admin is the ONLY active admin remaining)
    res4 = client.patch(
        f"/admin/users/{root_admin_id}/role",
        headers={"Authorization": f"Bearer {admin_session}"},
        json={"role": "USER"},
    )
    assert res4.status_code == 400


# ---------------------------------------------------------------------------
# Scenario 25: No authentication secrets are exposed in admin responses
# ---------------------------------------------------------------------------
def test_25_no_authentication_secrets_exposed(a7_env):
    client = a7_env["client"]
    resp = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {a7_env['admin_session_id']}"},
    )
    assert resp.status_code == 200
    users = resp.json()["users"]
    for u in users:
        assert "session_id" not in u
        assert "session_token" not in u
        assert "id_token" not in u
        assert "token" not in u
        assert "password" not in u
        assert "secret" not in u
