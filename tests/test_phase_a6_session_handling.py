"""Phase A6 Test Suite: Protected Application & Session Handling.

Validates:
1. All application endpoints (/analyze, /analyses, /repository/*, /analytics/*) strictly require active session (401).
2. Disabled accounts are rejected mid-session with HTTP 403 Forbidden across all protected endpoints.
3. Authenticated active users can access all protected endpoints via cookie or Bearer token.
4. Infrastructure endpoints (/health, /platform/*, /auth/google, /github/webhook, /) remain public and unaffected.
5. Session revocation (logout) immediately blocks subsequent application calls.
6. settings.AUTH_ENFORCED toggle supports backwards-compatible testing mode.
"""

import os
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage import AnalysisStore, UserRole, UserStatus
from backend.app.core.config import settings
from backend.app.main import app


@pytest.fixture
def a6_env(monkeypatch):
    """Provide isolated database and TestClient with enforced session auth."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    store.initialize()

    monkeypatch.setattr("backend.app.core.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.history._get_store", lambda: AnalysisStore(db_path=temp_db_path))

    # Pre-seed users
    admin = store.seed_initial_admin("admin@codesentinel.dev", "Root Admin")
    active_user = store.create_authorized_user(
        email="dev@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Active Developer",
    )
    store.bind_google_identity(active_user.user_id, "goog_sub_dev_123")

    disabled_user = store.create_authorized_user(
        email="badactor@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Bad Actor",
    )
    store.bind_google_identity(disabled_user.user_id, "goog_sub_disabled_123")

    # Create active sessions
    active_session_id = store.create_session(active_user.user_id)
    disabled_session_id = store.create_session(disabled_user.user_id)
    # Disable user after session was created (mid-session deactivation)
    store.update_user_status(disabled_user.user_id, UserStatus.DISABLED.value)

    client = TestClient(app)

    yield {
        "store": store,
        "client": client,
        "active_user": active_user,
        "active_session_id": active_session_id,
        "disabled_user": disabled_user,
        "disabled_session_id": disabled_session_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


def test_1_unauthenticated_requests_rejected_on_all_protected_endpoints(a6_env):
    """Application endpoints must return 401 Unauthorized when no session is provided."""
    client = a6_env["client"]
    client.cookies.clear()

    # 1. /analyze
    resp = client.post("/analyze", json={"source_code": "x = 1", "query": "security"})
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]

    # 2. /analyses
    resp = client.get("/analyses")
    assert resp.status_code == 401

    # 3. /repository/intake
    resp = client.post("/repository/intake", json={"repository_url": "https://github.com/org/repo"})
    assert resp.status_code == 401

    # 4. /analytics/summary
    resp = client.get("/analytics/summary")
    assert resp.status_code == 401


def test_2_disabled_user_session_rejected_with_403(a6_env):
    """When a user is disabled mid-session, all application endpoints return 403 Forbidden."""
    client = a6_env["client"]
    disabled_session_id = a6_env["disabled_session_id"]

    # Set disabled user cookie
    client.cookies.set(settings.SESSION_COOKIE_NAME, disabled_session_id)

    # 1. /analyses
    resp = client.get("/analyses")
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()

    # 2. /analyze
    resp = client.post("/analyze", json={"source_code": "x = 1", "query": "security"})
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()

    # 3. /analytics/summary
    resp = client.get("/analytics/summary")
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"].lower()


def test_3_authenticated_user_accesses_protected_endpoints(a6_env):
    """Active user with valid session cookie or Bearer token successfully accesses application endpoints."""
    client = a6_env["client"]
    session_id = a6_env["active_session_id"]

    # 1. Via cookie
    client.cookies.set(settings.SESSION_COOKIE_NAME, session_id)
    resp = client.get("/analyses")
    assert resp.status_code == 200
    assert "analyses" in resp.json()

    # 2. Via Bearer header
    client.cookies.clear()
    resp = client.get("/analyses", headers={"Authorization": f"Bearer {session_id}"})
    assert resp.status_code == 200
    assert "analyses" in resp.json()

    # 3. POST /analyze works with active session
    resp = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {session_id}"},
        json={"source_code": "def hello(): pass", "query": "security"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


def test_4_public_endpoints_remain_accessible_without_session(a6_env):
    """Infrastructure endpoints and public health probes must NEVER require user sessions."""
    client = a6_env["client"]
    client.cookies.clear()

    # /health
    r = client.get("/health")
    assert r.status_code == 200

    # /platform/health
    r = client.get("/platform/health")
    assert r.status_code == 200

    # /platform/readiness
    r = client.get("/platform/readiness")
    assert r.status_code == 200

    # /platform/info
    r = client.get("/platform/info")
    assert r.status_code == 200

    # /
    r = client.get("/")
    assert r.status_code == 200

    # /github/webhook does not check user sessions (it checks HMAC)
    r = client.post("/github/webhook", json={"test": "ping"})
    assert r.status_code != 401 or "X-Hub-Signature-256" in r.json().get("detail", "")


def test_5_session_revocation_blocks_subsequent_calls(a6_env):
    """Logging out revokes session and immediately causes 401 on protected endpoints."""
    client = a6_env["client"]
    session_id = a6_env["active_session_id"]

    client.cookies.set(settings.SESSION_COOKIE_NAME, session_id)
    assert client.get("/analyses").status_code == 200

    # Execute logout
    logout_resp = client.post("/auth/logout")
    assert logout_resp.status_code == 200

    # Next call with same session ID must fail with 401
    post_logout = client.get("/analyses", headers={"Authorization": f"Bearer {session_id}"})
    assert post_logout.status_code == 401


def test_6_auth_enforced_bypass_mode_for_legacy_tests(a6_env, monkeypatch):
    """When settings.AUTH_ENFORCED is False, unauthenticated requests are allowed for testing."""
    client = a6_env["client"]
    client.cookies.clear()

    monkeypatch.setattr(settings, "AUTH_ENFORCED", False)
    resp = client.get("/analyses")
    assert resp.status_code == 200
