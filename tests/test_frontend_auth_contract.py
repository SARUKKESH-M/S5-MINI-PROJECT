"""
CodeSentinel — Phase A5 Frontend Authentication Contract & Security Invariant Tests

Validates:
1. Frontend API client auth contract compatibility:
   - POST /auth/google -> session cookie issuance
   - GET /auth/me -> 200 (authenticated), 401 (unauthenticated), 403 (disabled)
   - POST /auth/logout -> session revocation & cookie deletion
2. Frontend error message contract alignment (403 Unauthorized vs 403 Disabled).
3. Security Invariant Check: Frontend codebase strictly contains ZERO localStorage tokens or role persistence.
"""

import os
import re
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

# Ensure paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.main import app
from backend.analysis.storage import AnalysisStore, UserRole, UserStatus


@pytest.fixture
def auth_client(monkeypatch):
    """Fixture providing an isolated FastAPI TestClient with fresh test database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    store.initialize()

    monkeypatch.setattr("backend.app.core.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))

    # Seed root admin
    store.seed_initial_admin("admin@codesentinel.dev", "Admin Security Lead")

    # Seed active user
    store.create_authorized_user(
        email="developer@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Standard Developer",
    )

    # Seed disabled user
    disabled_user = store.create_authorized_user(
        email="disabled@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Disabled User",
    )
    store.update_user_status(disabled_user.user_id, UserStatus.DISABLED.value)

    client = TestClient(app)
    yield client

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


def test_unauthenticated_session_check_returns_401(auth_client):
    """Frontend initial boot check GET /auth/me must return 401 when no session exists."""
    response = auth_client.get("/auth/me")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_unauthorized_google_identity_returns_403(auth_client):
    """Google authentication with an unauthorized email returns 403 Pre-Authorization required."""
    token = 'mock:{"sub":"unknown-sub","email":"unknown@example.com","name":"Unknown User","picture":""}'
    response = auth_client.post("/auth/google", json={"id_token": token})
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "Account not authorized" in detail
    assert "codesentinel_session" not in response.cookies


def test_disabled_account_google_login_returns_403(auth_client):
    """Google authentication for a deactivated/disabled user returns 403 Account is disabled."""
    token = 'mock:{"sub":"disabled-sub","email":"disabled@codesentinel.dev","name":"Disabled User","picture":""}'
    response = auth_client.post("/auth/google", json={"id_token": token})
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "disabled" in detail.lower()
    assert "codesentinel_session" not in response.cookies


def test_successful_login_and_me_lifecycle(auth_client):
    """Valid pre-authorized user logs in, receives session cookie, and hydrates GET /auth/me."""
    token = 'mock:{"sub":"dev-google-sub","email":"developer@codesentinel.dev","name":"Standard Developer","picture":"https://example.com/photo.jpg"}'
    login_resp = auth_client.post("/auth/google", json={"id_token": token})
    assert login_resp.status_code == 200
    assert "codesentinel_session" in login_resp.cookies

    # Verify GET /auth/me with session
    me_resp = auth_client.get("/auth/me")
    assert me_resp.status_code == 200
    user = me_resp.json().get("user", me_resp.json())
    assert user["email"] == "developer@codesentinel.dev"
    assert user["role"] == "USER"
    assert user["status"] == "ACTIVE"
    assert user["profile_picture"] == "https://example.com/photo.jpg"

    # Verify POST /auth/logout
    logout_resp = auth_client.post("/auth/logout")
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "success"

    # Subsequent GET /auth/me must return 401
    post_logout_me = auth_client.get("/auth/me")
    assert post_logout_me.status_code == 401


def test_admin_identity_reflects_admin_role(auth_client):
    """Admin login correctly populates role='ADMIN' in /auth/me."""
    token = 'mock:{"sub":"admin-sub","email":"admin@codesentinel.dev","name":"Admin Security Lead","picture":""}'
    login_resp = auth_client.post("/auth/google", json={"id_token": token})
    assert login_resp.status_code == 200

    me_resp = auth_client.get("/auth/me")
    assert me_resp.status_code == 200
    user = me_resp.json().get("user", me_resp.json())
    assert user["email"] == "admin@codesentinel.dev"
    assert user["role"] == "ADMIN"
    assert user["status"] == "ACTIVE"


def test_frontend_security_invariant_no_localstorage_tokens():
    """Security Invariant: Frontend src/ MUST NOT store authentication tokens or roles in localStorage."""
    frontend_src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "src")
    assert os.path.exists(frontend_src), "frontend/src directory must exist"

    forbidden_patterns = [
        re.compile(r'localStorage\.setItem\s*\(\s*[\'"][^\'"]*token', re.IGNORECASE),
        re.compile(r'localStorage\.setItem\s*\(\s*[\'"][^\'"]*role', re.IGNORECASE),
        re.compile(r'localStorage\.setItem\s*\(\s*[\'"][^\'"]*user', re.IGNORECASE),
        re.compile(r'sessionStorage\.setItem\s*\(\s*[\'"][^\'"]*token', re.IGNORECASE),
        re.compile(r'sessionStorage\.setItem\s*\(\s*[\'"][^\'"]*role', re.IGNORECASE),
    ]

    for root, _, files in os.walk(frontend_src):
        for file in files:
            if file.endswith((".js", ".jsx", ".ts", ".tsx")):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    for pattern in forbidden_patterns:
                        match = pattern.search(content)
                        assert match is None, (
                            f"Security violation: Found forbidden localStorage/sessionStorage auth pattern '{match.group(0)}' in {filepath}"
                        )
