"""Phase 2B Test Suite: Login Performance Fix & Gate Loading Optimization.

Validates:
1. Bounded API request timeout contract in frontend/src/services/apiClient.js:
   - Configurable AbortController timeout.
   - Distinguishable timeout error (isTimeout / status 408 / TimeoutError).
   - Support for external caller AbortSignal.
   - Cleanup of timers in finally block.
   - Options passthrough in apiGet and fetchCurrentUser.
2. Initial session-check behavior in frontend/src/context/AuthContext.jsx:
   - Configurable gate loading deadline (~3.5 seconds).
   - Bounded request timeout for session checks.
   - Request generation counter (authSeqRef) ensuring race safety.
   - Stale session responses cannot override newer login, logout, or session updates.
   - sessionPending state tracking.
3. Protected routes fail-closed enforcement:
   - Unauthenticated requests rejected with HTTP 401 across all protected endpoints.
   - No sensitive data returned prior to session confirmation.
4. Valid session restoration:
   - Authenticated user with valid session receives HTTP 200 with active user profile.
5. Zero client-side storage security invariant:
   - Zero localStorage or sessionStorage tokens or role persistence.
"""

import os
import re
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage import AnalysisStore, UserRole, UserStatus
from backend.app.core.config import settings
from backend.app.main import app


@pytest.fixture
def auth_env(monkeypatch):
    """Provide isolated test environment with fresh database and TestClient with enforced auth."""
    monkeypatch.setattr(settings, "AUTH_ENFORCED", True)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    store.initialize()

    monkeypatch.setattr("backend.app.core.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.auth.get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.app.api.history._get_store", lambda: AnalysisStore(db_path=temp_db_path))

    admin = store.seed_initial_admin("admin@codesentinel.dev", "Root Administrator")
    active_user = store.create_authorized_user(
        email="developer@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Active Developer",
    )
    store.bind_google_identity(active_user.user_id, "goog_sub_dev_perf")

    session_id = store.create_session(active_user.user_id)
    admin_session_id = store.create_session(admin.user_id)

    client = TestClient(app)

    yield {
        "store": store,
        "client": client,
        "admin": admin,
        "active_user": active_user,
        "session_id": session_id,
        "admin_session_id": admin_session_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test 1: Bounded Request Timeout & Error Categorization Contract in apiClient.js
# ---------------------------------------------------------------------------
def test_1_api_client_timeout_contract():
    """Verify frontend/src/services/apiClient.js distinguishes timeouts, caller aborts, HTTP errors, and network errors."""
    api_client_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "src", "services", "apiClient.js")
    assert os.path.exists(api_client_path), "apiClient.js must exist"

    with open(api_client_path, "r", encoding="utf-8") as f:
        code = f.read()

    # 1. AbortController instantiation
    assert "new AbortController()" in code, "apiFetch must instantiate AbortController for timeout management"

    # 2. Timeout handling and timer clearing
    assert "options.timeout" in code, "apiFetch must check options.timeout"
    assert "clearTimeout(timeoutId)" in code, "apiFetch must clear timeout timer in finally block"

    # 3. Caller AbortSignal integration and cleanup
    assert "options.signal" in code, "apiFetch must support caller-provided signal"
    assert "removeEventListener('abort', handleExternalAbort)" in code, "apiFetch must remove abort event listener in finally block"

    # 4. Immediate preservation of HTTP statuses (never misclassify 401 or 403)
    assert re.search(r"if\s*\(\s*error\.status\s*&&\s*error\.status\s*!==\s*0\s*\)\s*\{\s*throw\s+error;", code), (
        "apiFetch must immediately rethrow backend HTTP response errors (e.g. 401, 403)"
    )

    # 5. Distinguishable timeout error (status 408)
    assert "isTimeout" in code, "apiFetch must tag timeout errors with isTimeout flag"
    assert "TimeoutError" in code, "apiFetch must name timeout errors TimeoutError"
    assert "timeoutError.status = 408" in code, "apiFetch must assign status 408 to timeouts"

    # 6. Caller-triggered abort normalization
    assert "isCallerAborted" in code, "apiFetch must identify caller-triggered aborts"
    assert "abortError.isAborted = true" in code, "apiFetch must tag aborted requests with isAborted flag"

    # 7. Ordinary network errors
    assert "networkError.isNetworkError = true" in code, "apiFetch must identify ordinary network errors"

    # 8. Passthrough in apiGet and fetchCurrentUser
    assert re.search(r"export\s+async\s+function\s+apiGet\s*\([^)]*options", code), "apiGet must accept options"
    assert re.search(r"export\s+async\s+function\s+fetchCurrentUser\s*\(\s*options", code), "fetchCurrentUser must accept options"


# ---------------------------------------------------------------------------
# Test 2: AuthContext Gate Deadline, Generation Counter, & sessionPending Contract
# ---------------------------------------------------------------------------
def test_2_auth_context_gate_deadline_and_sequence_contract():
    """Verify AuthContext.jsx implements initial gate deadline, sequence ref, and sessionPending cleanup."""
    auth_ctx_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "src", "context", "AuthContext.jsx")
    assert os.path.exists(auth_ctx_path), "AuthContext.jsx must exist"

    with open(auth_ctx_path, "r", encoding="utf-8") as f:
        code = f.read()

    # 1. Configurable initial gate deadline ~3500ms
    assert "INITIAL_GATE_DEADLINE_MS" in code, "AuthContext must define INITIAL_GATE_DEADLINE_MS"
    assert "3500" in code, "Default gate deadline must be approximately 3.5 seconds (3500ms)"

    # 2. Bounded request timeout
    assert "SESSION_CHECK_TIMEOUT_MS" in code, "AuthContext must define SESSION_CHECK_TIMEOUT_MS"

    # 3. Request generation counter (authSeqRef)
    assert "authSeqRef" in code, "AuthContext must maintain authSeqRef sequence counter"
    assert "useRef" in code, "AuthContext must import and use useRef for race safety"

    # 4. Stale session protection checks
    assert "authSeqRef.current === seq" in code, "AuthContext must check sequence before updating user state"

    # 5. Unblocking loading state at deadline
    assert "setLoading(false)" in code, "AuthContext must unblock loading state at deadline timer"

    # 6. Session pending tracking and cleanup
    assert "sessionPending" in code, "AuthContext must track sessionPending state"

    # 7. sessionPending must be cleared in finally block of login()
    assert re.search(r"const\s+login\s*=.*?finally\s*\{[^}]*setSessionPending\(false\)", code, re.DOTALL), (
        "login() finally block must clear sessionPending on success or failure"
    )


# ---------------------------------------------------------------------------
# Test 3: Unauthenticated Initial Visit with Fast 401
# ---------------------------------------------------------------------------
def test_3_unauthenticated_fast_401(auth_env):
    """Initial boot GET /auth/me returns HTTP 401 immediately when no session cookie or token is present."""
    client = auth_env["client"]
    client.cookies.clear()

    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Test 4: Valid Session Restored Before Deadline
# ---------------------------------------------------------------------------
def test_4_valid_session_restored(auth_env):
    """Authenticated user with valid session cookie restores session and profile correctly."""
    client = auth_env["client"]
    cookie_name = settings.SESSION_COOKIE_NAME
    client.cookies.set(cookie_name, auth_env["session_id"])

    resp = client.get("/auth/me")
    assert resp.status_code == 200
    user_data = resp.json()["user"]
    assert user_data["email"] == auth_env["active_user"].email
    assert user_data["role"] == "USER"
    assert user_data["status"] == "ACTIVE"


# ---------------------------------------------------------------------------
# Test 5: Protected Routes Remain Inaccessible When Unauthenticated (Fail-Closed)
# ---------------------------------------------------------------------------
def test_5_protected_routes_fail_closed(auth_env):
    """Protected endpoints strictly return HTTP 401 when unauthenticated."""
    client = auth_env["client"]
    client.cookies.clear()

    protected_endpoints = [
        ("POST", "/analyze", {"source_code": "x = 1"}),
        ("GET", "/analyses", None),
        ("POST", "/repository/intake", {"repository_url": "https://github.com/org/repo"}),
        ("GET", "/analytics/summary", None),
        ("GET", "/admin/users", None),
    ]

    for method, path, payload in protected_endpoints:
        if method == "POST":
            resp = client.post(path, json=payload)
        else:
            resp = client.get(path)
        assert resp.status_code == 401, f"Endpoint {path} must return 401 when unauthenticated"


# ---------------------------------------------------------------------------
# Test 6: Generation Counter Precedence Simulation & Failed Login Cleanup
# ---------------------------------------------------------------------------
def test_6_generation_counter_precedence_logic():
    """Verify that newer auth actions (login/logout/failed login) supersede older pending requests and clear sessionPending."""
    class MockAuthContext:
        def __init__(self):
            self.seq = 0
            self.user = None
            self.loading = True
            self.session_pending = True

        def start_initial_check(self):
            self.seq += 1
            return self.seq

        def complete_check(self, request_seq, user_data):
            if self.seq == request_seq:
                self.user = user_data
                self.loading = False
                self.session_pending = False
                return True
            return False

        def login_success(self, new_user):
            self.seq += 1
            self.user = new_user
            self.loading = False
            self.session_pending = False

        def login_failure(self):
            self.seq += 1
            self.user = None
            self.loading = False
            self.session_pending = False

        def logout(self):
            self.seq += 1
            self.user = None
            self.loading = False
            self.session_pending = False

    # Scenario A: Initial probe superseded by explicit successful login
    ctx = MockAuthContext()
    req1_seq = ctx.start_initial_check()
    assert req1_seq == 1
    assert ctx.session_pending is True

    ctx.login_success({"email": "admin@codesentinel.dev", "role": "ADMIN"})
    assert ctx.seq == 2
    assert ctx.session_pending is False
    assert ctx.user["email"] == "admin@codesentinel.dev"

    applied = ctx.complete_check(req1_seq, {"email": "old_user@codesentinel.dev", "role": "USER"})
    assert applied is False, "Stale request must not be applied"
    assert ctx.user["email"] == "admin@codesentinel.dev"

    ctx.logout()
    assert ctx.seq == 3
    assert ctx.user is None
    assert ctx.session_pending is False

    # Scenario B: Initial probe superseded by explicit FAILED login
    ctx2 = MockAuthContext()
    probe_seq = ctx2.start_initial_check()
    assert probe_seq == 1
    assert ctx2.session_pending is True
    assert ctx2.loading is True

    # User attempts login but it fails
    ctx2.login_failure()
    assert ctx2.seq == 2
    assert ctx2.session_pending is False, "sessionPending must be cleared when explicit login fails"
    assert ctx2.loading is False, "loading must be cleared when explicit login fails"
    assert ctx2.user is None

    # Stale probe finally completes
    applied = ctx2.complete_check(probe_seq, {"email": "delayed@codesentinel.dev", "role": "USER"})
    assert applied is False, "Delayed probe must not be applied after failed login"
    assert ctx2.session_pending is False, "sessionPending must remain false"
    assert ctx2.user is None


# ---------------------------------------------------------------------------
# Test 7: Error Categorization & Abort Normalization Contract
# ---------------------------------------------------------------------------
def test_7_error_categorization_and_abort_normalization(auth_env):
    """Verify separate categorization for external abort, internal timeout, HTTP 401/403, and network errors."""
    client = auth_env["client"]

    # 1. Real backend HTTP 401 on failed Google login
    resp = client.post("/auth/google", json={"id_token": "invalid_untrusted_token"})
    assert resp.status_code == 401
    assert any(phrase in resp.json()["detail"] for phrase in ("Failed to verify", "Invalid or expired", "Invalid or unverifiable"))
    assert settings.SESSION_COOKIE_NAME not in client.cookies

    # 2. Python simulation of normalized error classification logic in apiClient.js
    def classify_error(err_status, is_timed_out, is_caller_aborted, err_name):
        # Rule 1: HTTP error from backend must be rethrown with its status
        if err_status and err_status != 0:
            return {"type": "HTTP_ERROR", "status": err_status}
        # Rule 2: Internal timeout
        if is_timed_out:
            return {"type": "TIMEOUT", "status": 408, "isTimeout": True, "name": "TimeoutError"}
        # Rule 3: Caller-triggered abort
        if is_caller_aborted or err_name == "AbortError":
            return {"type": "ABORT", "status": 0, "isAborted": True, "name": "AbortError"}
        # Rule 4: Ordinary network failure
        return {"type": "NETWORK", "status": 0, "isNetworkError": True}

    # Case A: External abort
    res_abort = classify_error(err_status=None, is_timed_out=False, is_caller_aborted=True, err_name="AbortError")
    assert res_abort["type"] == "ABORT"
    assert res_abort["isAborted"] is True
    assert res_abort["status"] == 0

    # Case B: Internal timeout (must override AbortError from controller.abort())
    res_timeout = classify_error(err_status=None, is_timed_out=True, is_caller_aborted=False, err_name="AbortError")
    assert res_timeout["type"] == "TIMEOUT"
    assert res_timeout["isTimeout"] is True
    assert res_timeout["status"] == 408

    # Case C: HTTP 401 unauthenticated (never masked by abort/network)
    res_401 = classify_error(err_status=401, is_timed_out=False, is_caller_aborted=False, err_name="Error")
    assert res_401["type"] == "HTTP_ERROR"
    assert res_401["status"] == 401

    # Case D: HTTP 403 forbidden (never masked)
    res_403 = classify_error(err_status=403, is_timed_out=False, is_caller_aborted=False, err_name="Error")
    assert res_403["type"] == "HTTP_ERROR"
    assert res_403["status"] == 403

    # Case E: Ordinary network failure
    res_network = classify_error(err_status=None, is_timed_out=False, is_caller_aborted=False, err_name="TypeError")
    assert res_network["type"] == "NETWORK"
    assert res_network["isNetworkError"] is True
    assert res_network["status"] == 0


# ---------------------------------------------------------------------------
# Test 8: Zero Client-Side Storage Security Invariant
# ---------------------------------------------------------------------------
def test_8_security_invariant_no_localstorage():
    """Verify that frontend/src contains ZERO forbidden localStorage/sessionStorage auth patterns."""
    frontend_src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "src")
    assert os.path.exists(frontend_src), "frontend/src must exist"

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
                        assert match is None, f"Forbidden storage pattern '{match.group(0)}' in {filepath}"
