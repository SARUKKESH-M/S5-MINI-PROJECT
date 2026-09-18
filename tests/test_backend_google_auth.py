"""Phase A4 Verification Test Suite: Backend Google Authentication & Access Control.

Tests:
1. Valid Google identity exchange
2. Invalid Google identity rejection
3. Unknown Google account rejection (403, no auto-registration)
4. Pre-authorized user login
5. First Google identity binding
6. Existing google_sub direct lookup
7. Conflicting / duplicate google_sub binding rejection
8. Seeded ADMIN authentication
9. Pre-authorized USER authentication
10. DISABLED user rejection on login (403)
11. /auth/me without session (401)
12. /auth/me with valid session (200 + UserPublicResponse)
13. /auth/me with disabled account mid-session (403)
14. Logout endpoint (200 + session revocation + cookie cleared)
15. Session invalidation on subsequent request after logout (401)
16. Invalid / expired session string (401)
17. Email normalization during Google auth exchange
18. Security middleware compatibility (Security headers on /auth/* endpoints)
19. GitHub webhook remains strictly HMAC protected (not affected by auth)
20. Public health / readiness endpoints remain public
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
)
from backend.app.core.config import settings
from backend.app.main import app


@pytest.fixture
def auth_test_env(monkeypatch):
    """Provide an isolated database and clean settings for authentication testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    store.initialize()

    # Monkeypatch store creation in auth modules to use temp_db_path
    monkeypatch.setattr("backend.app.core.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))

    # Pre-seed root admin in temp store
    store.seed_initial_admin("admin@codesentinel.dev", "Root Administrator")

    client = TestClient(app)

    yield store, client

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 1. Google Token Verification & Identity Exchange
# ---------------------------------------------------------------------------
def test_1_invalid_google_identity(auth_test_env):
    store, client = auth_test_env

    # Empty payload
    res1 = client.post("/auth/google", json={})
    assert res1.status_code == 400

    # Invalid / untrusted token
    res2 = client.post("/auth/google", json={"id_token": "invalid_bogus_token_123"})
    assert res2.status_code == 401
    assert "Invalid or expired" in res2.json()["detail"] or "Failed to verify" in res2.json()["detail"]


def test_2_unknown_google_account_rejected(auth_test_env):
    store, client = auth_test_env

    # Unknown user: mock token for an unregistered email
    res = client.post("/auth/google", json={"id_token": "mock_google_:stranger@gmail.com:sub_stranger_111:Stranger"})
    assert res.status_code == 403
    assert "Account not authorized" in res.json()["detail"]

    # Invariant: No user record created for unknown user
    assert store.get_user_by_email("stranger@gmail.com") is None


def test_3_pre_authorized_user_first_binding(auth_test_env):
    store, client = auth_test_env

    # Admin pre-authorizes user
    pre = store.create_authorized_user(
        email="developer@company.com",
        role=UserRole.USER.value,
        full_name="Jane Dev",
    )
    assert pre.google_sub is None

    # First Google sign in
    res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:Developer@Company.COM:goog_sub_99999:Jane Developer"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert body["user"]["email"] == "developer@company.com"
    assert body["user"]["role"] == UserRole.USER.value
    assert body["user"]["status"] == UserStatus.ACTIVE.value
    assert "session_token" in body

    # Verify cookie was set
    assert settings.SESSION_COOKIE_NAME in res.cookies

    # Verify identity bound in storage
    updated = store.get_user_by_email("developer@company.com")
    assert updated.google_sub == "goog_sub_99999"


def test_4_existing_google_sub_direct_lookup(auth_test_env):
    store, client = auth_test_env

    # User already has bound google_sub
    pre = store.create_authorized_user(email="alice@corp.com")
    store.bind_google_identity(pre.user_id, "goog_sub_alice_123")

    # Subsequent login using same google_sub
    res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:alice@corp.com:goog_sub_alice_123:Alice User"}
    )
    assert res.status_code == 200
    assert res.json()["user"]["email"] == "alice@corp.com"


def test_5_conflicting_google_sub_protection(auth_test_env):
    store, client = auth_test_env

    # User1 bound to sub_A
    u1 = store.create_authorized_user(email="user1@corp.com")
    store.bind_google_identity(u1.user_id, "sub_A")

    # User2 pre-authorized
    u2 = store.create_authorized_user(email="user2@corp.com")

    # User2 attempts login with sub_A (token collision / spoofing)
    res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:user2@corp.com:sub_A:User Two"}
    )
    assert res.status_code == 403


def test_6_root_admin_authentication(auth_test_env):
    store, client = auth_test_env

    # Root admin seeded with admin@codesentinel.dev
    res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:admin@codesentinel.dev:sub_admin_root_1:Root Admin"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["user"]["role"] == UserRole.ADMIN.value
    assert body["user"]["status"] == UserStatus.ACTIVE.value


def test_7_disabled_user_login_rejection(auth_test_env):
    store, client = auth_test_env

    # Create user and immediately disable
    u = store.create_authorized_user(email="disabled@corp.com")
    store.update_user_status(u.user_id, UserStatus.DISABLED.value)

    res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:disabled@corp.com:sub_disabled_99:Disabled Person"}
    )
    assert res.status_code == 403
    assert "Account is disabled" in res.json()["detail"]


# ---------------------------------------------------------------------------
# 2. Session Lifecycle & /auth/me & /auth/logout
# ---------------------------------------------------------------------------
def test_8_auth_me_without_session(auth_test_env):
    store, client = auth_test_env

    client.cookies.clear()
    res = client.get("/auth/me")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_9_auth_me_with_valid_session(auth_test_env):
    store, client = auth_test_env

    # Login
    store.create_authorized_user(email="active@corp.com")
    login_res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:active@corp.com:sub_active_1:Active User"}
    )
    assert login_res.status_code == 200

    # Call /auth/me with cookie automatically included
    me_res = client.get("/auth/me")
    assert me_res.status_code == 200
    user_data = me_res.json()["user"]
    assert user_data["email"] == "active@corp.com"
    assert user_data["status"] == "ACTIVE"
    # Ensure internal audit details are NOT leaked in public response
    assert "created_by" not in user_data


def test_10_auth_me_disabled_mid_session(auth_test_env):
    store, client = auth_test_env

    u = store.create_authorized_user(email="victim@corp.com")
    login_res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:victim@corp.com:sub_victim:Victim User"}
    )
    assert login_res.status_code == 200

    # Admin disables user mid-session
    store.update_user_status(u.user_id, UserStatus.DISABLED.value)

    # Next request must immediately be blocked with 403
    me_res = client.get("/auth/me")
    assert me_res.status_code == 403
    assert "Account is disabled" in me_res.json()["detail"]


def test_11_logout_and_session_invalidation(auth_test_env):
    store, client = auth_test_env

    store.create_authorized_user(email="logout_test@corp.com")
    login_res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:logout_test@corp.com:sub_logout:Logout User"}
    )
    assert login_res.status_code == 200
    session_token = login_res.json()["session_token"]

    # Verify /auth/me works
    assert client.get("/auth/me").status_code == 200

    # Execute logout
    logout_res = client.post("/auth/logout")
    assert logout_res.status_code == 200
    assert logout_res.json()["status"] == "success"

    # Subsequent /auth/me must fail with 401
    assert client.get("/auth/me").status_code == 401

    # Direct token in Bearer header must also be rejected because DB marked it revoked
    expired_res = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {session_token}"}
    )
    assert expired_res.status_code == 401


def test_12_invalid_or_expired_session_string(auth_test_env):
    store, client = auth_test_env

    res = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer sess_non_existent_fake_id"}
    )
    assert res.status_code == 401
    assert "Session is invalid or has expired" in res.json()["detail"]


def test_13_email_normalization(auth_test_env):
    store, client = auth_test_env

    # Pre-authorized with lowercase
    store.create_authorized_user(email="cased.user@corp.com")

    # Google token provides mixed-case email
    res = client.post(
        "/auth/google",
        json={"id_token": "mock_google_:  Cased.User@Corp.COM  :sub_cased_1:Cased User"}
    )
    assert res.status_code == 200
    assert res.json()["user"]["email"] == "cased.user@corp.com"


# ---------------------------------------------------------------------------
# 3. Security Hardening & Isolation Invariants
# ---------------------------------------------------------------------------
def test_14_security_headers_present_on_auth_endpoints(auth_test_env):
    store, client = auth_test_env

    res = client.get("/auth/me")
    # Even on 401 response, security headers middleware must be active
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src" in res.headers.get("Content-Security-Policy", "")


def test_15_public_endpoints_unaffected(auth_test_env):
    store, client = auth_test_env

    client.cookies.clear()

    # /health
    h_res = client.get("/health")
    assert h_res.status_code == 200

    # /platform/health
    ph_res = client.get("/platform/health")
    assert ph_res.status_code == 200

    # /platform/readiness
    pr_res = client.get("/platform/readiness")
    assert pr_res.status_code == 200

    # /platform/info
    pi_res = client.get("/platform/info")
    assert pi_res.status_code == 200


def test_16_github_webhook_remains_hmac_boundary(auth_test_env):
    store, client = auth_test_env

    client.cookies.clear()
    # Webhook endpoint does NOT check user sessions or cookies
    # When no HMAC signature is provided in production or with secret, it rejects based on HMAC, not user auth
    res = client.post("/github/webhook", json={"event": "ping"})
    # In dev without secret, it parses webhook; with secret it checks signature
    # It must never return 401 'Authentication required'
    assert res.status_code != 401 or "X-Hub-Signature-256" in res.json().get("detail", "")
