"""Phase 3D-1 Verification Test Suite: Analysis Ownership and IDOR Remediation.

Tests server-side ownership enforcement across all analysis, findings, false-positive,
feedback, and repository report endpoints:
1. User A lists analyses and sees only User A's records.
2. User A cannot retrieve User B's analysis detail (HTTP 404).
3. User A cannot retrieve User B's findings (HTTP 404).
4. User A cannot set a false-positive flag on User B's finding (HTTP 404).
5. User A cannot read User B's finding feedback (HTTP 404).
6. User A cannot revoke User B's false-positive flag (HTTP 404).
7. User A cannot retrieve User B's repository report (HTTP 404).
8. Authenticated administrator can access records across users.
9. Unowned or legacy records (user_id = NULL) are not exposed to ordinary users (HTTP 404).
10. A user can access their own analyses and findings normally (HTTP 200).
11. A finding ID from a different analysis cannot bypass parent-analysis ownership checks (HTTP 404).
12. New direct analyses (/analyze) and repository analyses persist the authenticated platform user ID.
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from fastapi import HTTPException
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
from backend.app.core.config import Settings, settings
from backend.app.core.auth import get_current_user
from backend.app.main import app
from backend.repository.acquirer import acquire_repository


@pytest.fixture
def p3d_env(monkeypatch):
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
    monkeypatch.setattr("backend.app.api.repository_analysis._get_store", lambda: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.analysis.orchestrator.AnalysisStore", lambda *args, **kwargs: AnalysisStore(db_path=temp_db_path))
    monkeypatch.setattr("backend.analysis.repository_orchestrator.AnalysisStore", lambda *args, **kwargs: AnalysisStore(db_path=temp_db_path))

    # Enable AUTH_ENFORCED
    monkeypatch.setattr(settings, "AUTH_ENFORCED", True)

    # 1. Seed Root Admin
    root_admin = store.seed_initial_admin("admin@codesentinel.dev", "Root Administrator")
    store.bind_google_identity(root_admin.user_id, "goog_sub_root_admin")
    admin_session_id = store.create_session(root_admin.user_id)

    # 2. Seed User A (Alice)
    user_a = store.create_authorized_user(
        email="alice@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Alice Developer",
        created_by=root_admin.email,
    )
    store.bind_google_identity(user_a.user_id, "goog_sub_alice")
    alice_session_id = store.create_session(user_a.user_id)

    # 3. Seed User B (Bob)
    user_b = store.create_authorized_user(
        email="bob@codesentinel.dev",
        role=UserRole.USER.value,
        full_name="Bob Developer",
        created_by=root_admin.email,
    )
    store.bind_google_identity(user_b.user_id, "goog_sub_bob")
    bob_session_id = store.create_session(user_b.user_id)

    # 4. Seed Alice's Analysis
    alice_analysis_id = "analysis_alice_001"
    store.save_analysis({
        "status": "success",
        "analysis_id": alice_analysis_id,
        "query": "alice security scan",
        "user_id": user_a.user_id,
        "repository": {"owner": "alice-org", "repository": "alice-repo", "branch": "main", "path": "."},
        "summary": {"total_findings": 1, "high_count": 1},
        "findings": [
            {
                "finding_id": "finding_alice_sqli",
                "title": "SQL Injection in auth handler",
                "description": "Unescaped user input passed to db query",
                "severity": "high",
                "confidence": "high",
                "category": "CWE-89",
                "evidence": [
                    {
                        "document_id": "auth.py",
                        "line_start": 42,
                        "line_end": 42,
                        "signal_type": "sql_injection",
                        "signal_name": "execute",
                    }
                ],
            }
        ],
    })

    # 5. Seed Bob's Analysis
    bob_analysis_id = "analysis_bob_002"
    store.save_analysis({
        "status": "success",
        "analysis_id": bob_analysis_id,
        "query": "bob security scan",
        "user_id": user_b.user_id,
        "repository": {"owner": "bob-org", "repository": "bob-repo", "branch": "main", "path": "."},
        "summary": {"total_findings": 1, "critical_count": 1},
        "findings": [
            {
                "finding_id": "finding_bob_rce",
                "title": "Remote Code Execution via deserialization",
                "description": "Insecure pickle load on untrusted input",
                "severity": "critical",
                "confidence": "high",
                "category": "CWE-502",
                "evidence": [
                    {
                        "document_id": "server.py",
                        "line_start": 99,
                        "line_end": 99,
                        "signal_type": "rce",
                        "signal_name": "pickle.loads",
                    }
                ],
            }
        ],
    })

    # 6. Seed Legacy / Unowned Analysis (user_id = NULL)
    legacy_analysis_id = "analysis_legacy_999"
    store.save_analysis({
        "status": "success",
        "analysis_id": legacy_analysis_id,
        "query": "legacy unowned scan",
        "user_id": None,
        "repository": {"owner": "legacy-org", "repository": "legacy-repo", "branch": "main", "path": "."},
        "summary": {"total_findings": 1, "low_count": 1},
        "findings": [
            {
                "finding_id": "finding_legacy_info",
                "title": "Information Disclosure",
                "description": "Server header exposed",
                "severity": "low",
                "confidence": "medium",
                "category": "CWE-200",
                "evidence": [],
            }
        ],
    })

    client = TestClient(app)

    yield {
        "store": store,
        "client": client,
        "root_admin": root_admin,
        "user_a": user_a,
        "user_b": user_b,
        "admin_session_id": admin_session_id,
        "alice_session_id": alice_session_id,
        "bob_session_id": bob_session_id,
        "alice_analysis_id": alice_analysis_id,
        "bob_analysis_id": bob_analysis_id,
        "legacy_analysis_id": legacy_analysis_id,
    }

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


def test_1_user_a_lists_only_own_analyses(p3d_env):
    """User A lists analyses and sees only User A's records, not User B's or unowned."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    resp = client.get("/analyses", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    analyses = data["analyses"]
    # Alice should see exactly 1 analysis (her own)
    assert len(analyses) == 1
    assert analyses[0]["analysis_id"] == p3d_env["alice_analysis_id"]
    assert data["total_count"] == 1


def test_2_user_a_cannot_retrieve_user_b_analysis(p3d_env):
    """User A attempting to retrieve User B's analysis detail receives HTTP 404."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    resp = client.get(f"/analyses/{p3d_env['bob_analysis_id']}", headers=headers)
    assert resp.status_code == 404
    assert f"Analysis '{p3d_env['bob_analysis_id']}' not found" in resp.json()["detail"]


def test_3_user_a_cannot_retrieve_user_b_findings(p3d_env):
    """User A attempting to retrieve User B's findings receives HTTP 404."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    resp = client.get(f"/analyses/{p3d_env['bob_analysis_id']}/findings", headers=headers)
    assert resp.status_code == 404
    assert f"Analysis '{p3d_env['bob_analysis_id']}' not found" in resp.json()["detail"]


def test_4_user_a_cannot_mark_false_positive_on_user_b_finding(p3d_env):
    """User A attempting to mark a false positive on User B's finding receives HTTP 404."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    payload = {"reason": "Not a vulnerability in our setup", "reason_code": "ACCEPTED_RISK"}
    resp = client.post(
        f"/analyses/{p3d_env['bob_analysis_id']}/findings/finding_bob_rce/false-positive",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 404
    assert f"Analysis '{p3d_env['bob_analysis_id']}' not found" in resp.json()["detail"]


def test_5_user_a_cannot_read_user_b_finding_feedback(p3d_env):
    """User A attempting to read User B's finding feedback receives HTTP 404."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    resp = client.get(
        f"/analyses/{p3d_env['bob_analysis_id']}/findings/finding_bob_rce/feedback",
        headers=headers,
    )
    assert resp.status_code == 404
    assert f"Analysis '{p3d_env['bob_analysis_id']}' not found" in resp.json()["detail"]


def test_6_user_a_cannot_revoke_user_b_false_positive(p3d_env):
    """User A attempting to revoke User B's false positive receives HTTP 404."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    resp = client.delete(
        f"/analyses/{p3d_env['bob_analysis_id']}/findings/finding_bob_rce/false-positive",
        headers=headers,
    )
    assert resp.status_code == 404
    assert f"Analysis '{p3d_env['bob_analysis_id']}' not found" in resp.json()["detail"]


def test_7_user_a_cannot_retrieve_user_b_repository_report(p3d_env):
    """User A attempting to read User B's repository report receives HTTP 404."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    resp = client.get(
        f"/repository/reports/{p3d_env['bob_analysis_id']}",
        headers=headers,
    )
    assert resp.status_code == 404
    assert f"Analysis '{p3d_env['bob_analysis_id']}' not found" in resp.json()["detail"]


def test_8_admin_can_access_records_across_all_users(p3d_env):
    """Authenticated administrator can access records across all users."""
    client = p3d_env["client"]
    admin_headers = {"Authorization": f"Bearer {p3d_env['admin_session_id']}"}

    # 1. Admin lists all analyses
    resp_list = client.get("/analyses", headers=admin_headers)
    assert resp_list.status_code == 200
    all_analyses = resp_list.json()["analyses"]
    # Admin sees Alice's, Bob's, and legacy analyses
    assert len(all_analyses) == 3

    # 2. Admin retrieves Alice's detail
    resp_alice = client.get(f"/analyses/{p3d_env['alice_analysis_id']}", headers=admin_headers)
    assert resp_alice.status_code == 200
    assert resp_alice.json()["analysis"]["analysis_id"] == p3d_env["alice_analysis_id"]

    # 3. Admin retrieves Bob's detail
    resp_bob = client.get(f"/analyses/{p3d_env['bob_analysis_id']}", headers=admin_headers)
    assert resp_bob.status_code == 200
    assert resp_bob.json()["analysis"]["analysis_id"] == p3d_env["bob_analysis_id"]

    # 4. Admin retrieves Bob's repository report
    resp_report = client.get(f"/repository/reports/{p3d_env['bob_analysis_id']}", headers=admin_headers)
    assert resp_report.status_code == 200
    assert resp_report.json()["analysis_id"] == p3d_env["bob_analysis_id"]


def test_9_unowned_or_legacy_records_inaccessible_to_ordinary_users(p3d_env):
    """Ordinary users cannot access legacy/unowned records (user_id = NULL)."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    # Detail lookup -> 404
    resp = client.get(f"/analyses/{p3d_env['legacy_analysis_id']}", headers=headers)
    assert resp.status_code == 404

    # Findings lookup -> 404
    resp_findings = client.get(f"/analyses/{p3d_env['legacy_analysis_id']}/findings", headers=headers)
    assert resp_findings.status_code == 404

    # Report lookup -> 404
    resp_report = client.get(f"/repository/reports/{p3d_env['legacy_analysis_id']}", headers=headers)
    assert resp_report.status_code == 404


def test_10_user_can_access_own_analyses_and_findings_normally(p3d_env):
    """User can access their own analyses, findings, and manage false positives normally."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    # 1. Get analysis detail
    resp = client.get(f"/analyses/{p3d_env['alice_analysis_id']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["analysis"]["analysis_id"] == p3d_env["alice_analysis_id"]

    # 2. Get findings
    resp_findings = client.get(f"/analyses/{p3d_env['alice_analysis_id']}/findings", headers=headers)
    assert resp_findings.status_code == 200
    assert resp_findings.json()["finding_count"] == 1

    # 3. Mark false positive
    fp_payload = {"reason": "Verified safe test environment", "reason_code": "TEST_OR_MOCK"}
    resp_fp = client.post(
        f"/analyses/{p3d_env['alice_analysis_id']}/findings/finding_alice_sqli/false-positive",
        json=fp_payload,
        headers=headers,
    )
    assert resp_fp.status_code == 200
    assert resp_fp.json()["suppression"]["status"] == "ACTIVE"

    # 4. Get feedback
    resp_fb = client.get(
        f"/analyses/{p3d_env['alice_analysis_id']}/findings/finding_alice_sqli/feedback",
        headers=headers,
    )
    assert resp_fb.status_code == 200
    assert resp_fb.json()["is_false_positive"] is True

    # 5. Revoke false positive
    resp_rev = client.delete(
        f"/analyses/{p3d_env['alice_analysis_id']}/findings/finding_alice_sqli/false-positive",
        headers=headers,
    )
    assert resp_rev.status_code == 200
    assert resp_rev.json()["revoked"] is True

    # 6. Get repository report
    resp_rep = client.get(f"/repository/reports/{p3d_env['alice_analysis_id']}", headers=headers)
    assert resp_rep.status_code == 200
    assert resp_rep.json()["analysis_id"] == p3d_env["alice_analysis_id"]


def test_11_finding_id_from_different_analysis_cannot_bypass_checks(p3d_env):
    """A finding ID belonging to Analysis B cannot be accessed or manipulated under Analysis A."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    # finding_bob_rce exists in Bob's analysis, but Alice attempts to target it under Alice's analysis
    resp = client.post(
        f"/analyses/{p3d_env['alice_analysis_id']}/findings/finding_bob_rce/false-positive",
        json={"reason": "Hijack attempt", "reason_code": "FALSE_POSITIVE"},
        headers=headers,
    )
    assert resp.status_code == 404
    assert f"Finding 'finding_bob_rce' not found in analysis '{p3d_env['alice_analysis_id']}'" in resp.json()["detail"]

    resp_fb = client.get(
        f"/analyses/{p3d_env['alice_analysis_id']}/findings/finding_bob_rce/feedback",
        headers=headers,
    )
    assert resp_fb.status_code == 404

    resp_rev = client.delete(
        f"/analyses/{p3d_env['alice_analysis_id']}/findings/finding_bob_rce/false-positive",
        headers=headers,
    )
    assert resp_rev.status_code == 404


def test_12_new_analyses_persist_authenticated_platform_user_id(p3d_env):
    """Direct analysis (/analyze) records the authenticated user's ID into persistent storage."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    # Trigger direct analysis
    payload = {
        "source_code": "import sqlite3\ndef query_user(u):\n    conn.execute(f'SELECT * FROM users WHERE id = {u}')\n",
        "query": "sql injection check",
    }
    resp = client.post("/analyze", json=payload, headers=headers)
    assert resp.status_code == 200
    analysis_id = resp.json()["analysis_id"]

    # Verify in storage
    store = p3d_env["store"]
    record = store.get_analysis(analysis_id)
    assert record is not None
    assert record.get("user_id") == p3d_env["user_a"].user_id

    # Alice should be able to view this new analysis
    resp_get = client.get(f"/analyses/{analysis_id}", headers=headers)
    assert resp_get.status_code == 200
    assert resp_get.json()["analysis"]["analysis_id"] == analysis_id

    # Bob should NOT be able to view Alice's new analysis
    bob_headers = {"Authorization": f"Bearer {p3d_env['bob_session_id']}"}
    resp_bob = client.get(f"/analyses/{analysis_id}", headers=bob_headers)
    assert resp_bob.status_code == 404


def test_13_authenticated_user_repository_analysis_persists_ownership(p3d_env, monkeypatch):
    """Authenticated user calls POST /repository/analyze; proves end-to-end user_id persistence."""
    client = p3d_env["client"]
    headers = {"Authorization": f"Bearer {p3d_env['alice_session_id']}"}

    with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as ws_root:
        # Create a sample repository
        src_dir = os.path.join(repo_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write("import os\ndef run_cmd(cmd):\n    os.system(cmd)\n")

        acq = acquire_repository(
            repository_url="https://github.com/example/api-compat",
            local_path=repo_dir,
            workspace_root=ws_root,
        )

        monkeypatch.setattr(
            "backend.repository.acquirer.get_default_workspace_root",
            lambda: Path(ws_root).resolve(),
        )

        # 1. Regular authenticated platform user calls POST /repository/analyze
        post_resp = client.post(
            "/repository/analyze",
            json={
                "acquisition_id": acq["acquisition"]["acquisition_id"],
                "query": "security audit",
            },
            headers=headers,
        )
        assert post_resp.status_code == 200
        data = post_resp.json()
        assert data["status"] in ("success", "completed")
        analysis_id = data["analysis_id"]

        # 2. Retrieve persisted record using storage API
        store = p3d_env["store"]
        record = store.get_analysis(analysis_id)
        assert record is not None

        # 3. Assert user_id exactly matches Alice's internal platform user ID
        alice_user_id = p3d_env["user_a"].user_id
        assert record.get("user_id") == alice_user_id

        # 4. Assert user_id is NOT inferred from GitHub owner, repo name, email, or commit author
        assert record.get("user_id") != "example"
        assert record.get("user_id") != "api-compat"
        assert record.get("user_id") != p3d_env["user_a"].email
        assert record.get("user_id") != record.get("author")

        # 5. Alice can retrieve her repository report
        rep_resp = client.get(f"/repository/reports/{analysis_id}", headers=headers)
        assert rep_resp.status_code == 200
        assert rep_resp.json()["analysis_id"] == analysis_id

        # 6. Bob cannot retrieve Alice's repository report (HTTP 404)
        bob_headers = {"Authorization": f"Bearer {p3d_env['bob_session_id']}"}
        bob_resp = client.get(f"/repository/reports/{analysis_id}", headers=bob_headers)
        assert bob_resp.status_code == 404


def test_14_production_rejects_disabled_auth():
    """APP_ENV=production with AUTH_ENFORCED=False fails security configuration validation."""
    cfg = Settings(APP_ENV="production", AUTH_ENFORCED=False)
    is_valid, errors = cfg.validate_security_configuration()
    assert not is_valid
    assert any("AUTH_ENFORCED must be True when APP_ENV is 'production'" in err for err in errors)


def test_15_production_accepts_enabled_auth():
    """APP_ENV=production with AUTH_ENFORCED=True passes security configuration validation."""
    cfg = Settings(APP_ENV="production", AUTH_ENFORCED=True)
    is_valid, errors = cfg.validate_security_configuration()
    assert is_valid, f"Expected valid production configuration, got: {errors}"


def test_16_production_case_insensitivity():
    """Case variations of 'production' (e.g. PRODUCTION, Production, '  production  ') are rejected if auth disabled."""
    for env_val in ("PRODUCTION", "Production", "  production  ", "PrOdUcTiOn"):
        cfg = Settings(APP_ENV=env_val, AUTH_ENFORCED=False)
        is_valid, errors = cfg.validate_security_configuration()
        assert not is_valid, f"Failed to reject invalid config for APP_ENV='{env_val}'"
        assert any("AUTH_ENFORCED must be True" in err for err in errors)


def test_17_development_allows_disabled_auth():
    """Development and test configurations intentionally disabling auth continue to validate cleanly."""
    for env_val in ("development", "test", "local"):
        cfg = Settings(APP_ENV=env_val, AUTH_ENFORCED=False)
        is_valid, errors = cfg.validate_security_configuration()
        assert is_valid, f"Expected clean validation for non-prod '{env_val}', got: {errors}"


def test_18_production_startup_fails_if_auth_disabled(monkeypatch):
    """Application startup event raises RuntimeError in production if AUTH_ENFORCED=False."""
    from backend.app.main import startup_event
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "AUTH_ENFORCED", False)
    with pytest.raises(RuntimeError) as exc_info:
        startup_event()
    assert "Invalid production security configuration" in str(exc_info.value)
    assert "AUTH_ENFORCED must be True" in str(exc_info.value)


def test_19_production_get_current_user_blocks_bypass(monkeypatch):
    """In production with AUTH_ENFORCED=False, get_current_user raises HTTP 401 instead of bypass admin."""
    from starlette.requests import Request
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "AUTH_ENFORCED", False)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/analyses",
        "headers": [],
    }
    req = Request(scope)
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(req)
    assert exc_info.value.status_code == 401
    assert "prohibited in production" in exc_info.value.detail
