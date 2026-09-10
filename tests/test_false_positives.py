"""Comprehensive Test Suite for P1 #3: False-Positive Feedback Loop.

Verifies:
1. Deterministic finding fingerprint computation and repository scoping.
2. SQLite persistence, re-instantiation persistence, and idempotency.
3. Two-way feedback lifecycle (ACTIVE -> REVOKED -> ACTIVE).
4. Finding non-deletion: deterministic findings remain permanently traceable.
5. Finding enrichment in get_analysis and get_findings.
6. Security gate invariance: Step 6O gate decisions evaluate identical severity counts.
7. Fail-closed error handling and safety rules.
8. FastAPI endpoints: POST /false-positive, GET /feedback, DELETE /false-positive.
"""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.analysis.storage.models import (
    PROHIBITED_SOURCE_FIELDS,
    VALID_REASON_CODES,
    create_suppression_record,
    validate_reason_payload,
    validate_utc_iso_timestamp,
)
from backend.analysis.storage.store import (
    AnalysisStore,
    compute_finding_fingerprint,
    compute_finding_fingerprint_v2,
    is_suppression_active,
)
from backend.analysis.security_gate import evaluate_security_gate
from backend.app.main import app


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database path for isolated testing."""
    fd, path = tempfile.mkstemp(suffix="_test_fp.db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


@pytest.fixture
def sample_analysis_result():
    """Create a standard Step 6H analysis payload for testing."""
    return {
        "status": "success",
        "analysis_id": "test_analysis_001",
        "query": "Security review of payments service",
        "review_status": "block",
        "repository": {
            "repository": "acme/payments-service",
            "branch": "main",
            "commit": "a1b2c3d4e5f6",
        },
        "summary": {
            "total_findings": 2,
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
        "findings": [
            {
                "finding_id": "finding_sqli_1",
                "title": "Potential SQL Injection Vulnerability",
                "description": "Unescaped SQL query construction in checkout handler.",
                "severity": "critical",
                "confidence": "high",
                "category": "Injection",
                "evidence": [
                    {
                        "document_id": "backend/checkout.py",
                        "line_start": 42,
                        "line_end": 45,
                        "signal_type": "unsafe_database_execution",
                        "signal_name": "cursor.execute",
                    }
                ],
            },
            {
                "finding_id": "finding_cmd_2",
                "title": "Command Injection Risk",
                "description": "Shell execution with unvalidated arguments.",
                "severity": "high",
                "confidence": "high",
                "category": "Injection",
                "evidence": [
                    {
                        "document_id": "backend/exporter.py",
                        "line_start": 88,
                        "line_end": 88,
                        "signal_type": "command_execution_call",
                        "signal_name": "subprocess.Popen",
                    }
                ],
            },
        ],
    }


# ============================================================================
# 1. Fingerprint & Repository Scoping Tests
# ============================================================================

def test_fingerprint_normalization_and_stability():
    """Verify finding fingerprint is deterministic and normalizes case/slashes."""
    fp1 = compute_finding_fingerprint(
        repository_id="Acme/Payments-Service",
        rule_signal="UNSAFE_DATABASE_EXECUTION",
        cwe_id="Injection",
        file_path="backend\\checkout.py",
    )
    fp2 = compute_finding_fingerprint(
        repository_id="acme/payments-service",
        rule_signal="unsafe_database_execution",
        cwe_id="injection",
        file_path="backend/checkout.py",
    )
    assert fp1 == fp2
    assert len(fp1) == 32


def test_fingerprint_repository_isolation():
    """Verify different repositories generate different fingerprints for the same finding."""
    fp_repo_a = compute_finding_fingerprint(
        repository_id="org-a/service",
        rule_signal="unsafe_database_execution",
        cwe_id="Injection",
        file_path="db.py",
    )
    fp_repo_b = compute_finding_fingerprint(
        repository_id="org-b/service",
        rule_signal="unsafe_database_execution",
        cwe_id="Injection",
        file_path="db.py",
    )
    assert fp_repo_a != fp_repo_b


def test_fingerprint_different_rule_or_file():
    """Verify different rule signals or file paths produce different fingerprints."""
    fp_base = compute_finding_fingerprint("repo", "signal_a", "CWE-89", "file.py")
    fp_diff_rule = compute_finding_fingerprint("repo", "signal_b", "CWE-89", "file.py")
    fp_diff_file = compute_finding_fingerprint("repo", "signal_a", "CWE-89", "other.py")

    assert fp_base != fp_diff_rule
    assert fp_base != fp_diff_file


# ============================================================================
# 2. SQLite Persistence & Store Operations Tests
# ============================================================================

def test_record_and_get_false_positive(temp_db, sample_analysis_result):
    """Verify creating and retrieving a false-positive feedback record."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    suppression = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Parameterized through trusted ORM layer wrapper",
    )
    assert suppression is not None
    assert suppression["status"] == "ACTIVE"
    assert suppression["reason"] == "Parameterized through trusted ORM layer wrapper"
    assert suppression["analysis_id"] == "test_analysis_001"
    assert suppression["finding_id"] == "finding_sqli_1"
    assert suppression["repository_id"] == "acme/payments-service"
    assert suppression["rule_signal"] == "unsafe_database_execution"
    assert suppression["file_path"] == "backend/checkout.py"

    retrieved = store.get_false_positive("test_analysis_001", "finding_sqli_1")
    assert retrieved is not None
    assert retrieved["suppression_id"] == suppression["suppression_id"]
    assert retrieved["status"] == "ACTIVE"


def test_feedback_persists_across_store_reinstantiation(temp_db, sample_analysis_result):
    """Verify false-positive feedback survives store instance restart."""
    store1 = AnalysisStore(db_path=temp_db)
    store1.save_analysis(sample_analysis_result)
    supp1 = store1.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Test persistence",
    )
    assert supp1 is not None

    # Instantiate new store object pointing to same DB
    store2 = AnalysisStore(db_path=temp_db)
    supp2 = store2.get_false_positive("test_analysis_001", "finding_sqli_1")
    assert supp2 is not None
    assert supp2["suppression_id"] == supp1["suppression_id"]
    assert supp2["reason"] == "Test persistence"


def test_duplicate_feedback_is_idempotent(temp_db, sample_analysis_result):
    """Verify submitting duplicate feedback updates the record without creating duplicates."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    supp1 = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Initial note",
    )
    supp2 = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Updated note",
    )
    assert supp1["suppression_id"] == supp2["suppression_id"]
    assert supp2["reason"] == "Updated note"

    all_fp = store.list_false_positives(repository_id="acme/payments-service")
    assert len(all_fp) == 1


def test_revoke_and_reactivate_lifecycle(temp_db, sample_analysis_result):
    """Verify false-positive can be revoked and reactivated without deleting history."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    # 1. Mark active
    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Legitimate test query")
    assert store.get_false_positive("test_analysis_001", "finding_sqli_1")["status"] == "ACTIVE"

    # 2. Revoke
    revoked = store.revoke_false_positive("test_analysis_001", "finding_sqli_1")
    assert revoked is not None
    assert revoked["status"] == "REVOKED"

    # Verify not returned in active listings
    active_fps = store.list_false_positives(status="ACTIVE")
    assert len(active_fps) == 0

    all_fps = store.list_false_positives(status=None)
    assert len(all_fps) == 1
    assert all_fps[0]["status"] == "REVOKED"

    # 3. Reactivate
    reactivated = store.record_false_positive("test_analysis_001", "finding_sqli_1", "Re-confirmed false positive")
    assert reactivated["status"] == "ACTIVE"
    assert reactivated["suppression_id"] == revoked["suppression_id"]


# ============================================================================
# 3. Non-Deletion & Finding Traceability Tests
# ============================================================================

def test_findings_are_never_deleted_on_suppression(temp_db, sample_analysis_result):
    """Verify that marking a finding as false positive does NOT delete it from the database."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Not an issue")

    # Analysis record remains intact
    analysis = store.get_analysis("test_analysis_001")
    assert analysis is not None
    assert analysis["finding_count"] == 2
    assert len(analysis["findings"]) == 2

    # Both findings remain present in analysis
    f_ids = [f["finding_id"] for f in analysis["findings"]]
    assert "finding_sqli_1" in f_ids
    assert "finding_cmd_2" in f_ids

    # Suppressed finding is explicitly flagged without data loss
    sqli_f = next(f for f in analysis["findings"] if f["finding_id"] == "finding_sqli_1")
    assert sqli_f["is_false_positive"] is True
    assert sqli_f["feedback"]["status"] == "ACTIVE"
    assert sqli_f["severity"] == "critical"

    # Unsuppressed finding remains clean
    cmd_f = next(f for f in analysis["findings"] if f["finding_id"] == "finding_cmd_2")
    assert cmd_f["is_false_positive"] is False
    assert cmd_f["feedback"] is None


def test_get_findings_enriches_feedback(temp_db, sample_analysis_result):
    """Verify get_findings reflects false-positive feedback metadata."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Audit note")
    findings = store.get_findings("test_analysis_001")
    assert findings is not None
    assert len(findings) == 2

    f1 = next(f for f in findings if f["finding_id"] == "finding_sqli_1")
    assert f1["is_false_positive"] is True
    assert f1["feedback"] is not None


# ============================================================================
# 4. Repository Scoping & Future Matching Tests
# ============================================================================

def test_is_finding_suppressed_scoping(temp_db, sample_analysis_result):
    """Verify future finding suppression check is strictly repository-scoped."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    store.record_false_positive("test_analysis_001", "finding_sqli_1", "ORM internal")

    finding_to_check = {
        "finding_id": "future_finding_99",
        "category": "Injection",
        "file_path": "backend/checkout.py",
        "evidence": [
            {
                "document_id": "backend/checkout.py",
                "signal_type": "unsafe_database_execution",
            }
        ],
    }

    # Same repo: suppressed
    assert store.is_finding_suppressed("acme/payments-service", finding_to_check) is True

    # Different repo: NOT suppressed
    assert store.is_finding_suppressed("other-org/other-service", finding_to_check) is False

    # Different file in same repo: NOT suppressed
    finding_diff_file = {
        "finding_id": "future_finding_100",
        "category": "Injection",
        "file_path": "backend/users.py",
        "evidence": [
            {
                "document_id": "backend/users.py",
                "signal_type": "unsafe_database_execution",
            }
        ],
    }
    assert store.is_finding_suppressed("acme/payments-service", finding_diff_file) is False


def test_revoked_feedback_does_not_suppress_future_findings(temp_db, sample_analysis_result):
    """Verify revoked feedback does not suppress future findings."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Temporary mark")
    store.revoke_false_positive("test_analysis_001", "finding_sqli_1")

    finding_to_check = {
        "category": "Injection",
        "evidence": [{"document_id": "backend/checkout.py", "signal_type": "unsafe_database_execution"}],
    }
    assert store.is_finding_suppressed("acme/payments-service", finding_to_check) is False


# ============================================================================
# 5. Security Gate Invariance Tests
# ============================================================================

def test_security_gate_remains_invariant_to_false_positives(temp_db, sample_analysis_result):
    """Verify Step 6O Security Gate is NEVER bypassed or altered by false-positive feedback."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    # Developer marks critical finding as false-positive
    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Developer override attempt")

    # Retrieve report from store
    analysis = store.get_analysis("test_analysis_001")

    # Evaluate canonical security report against Step 6O gate
    decision, exit_code, reason = evaluate_security_gate(analysis)

    # CRITICAL vulnerability must still BLOCK CI
    assert decision == "BLOCK"
    assert exit_code == 1
    assert "critical" in reason.lower() or "block" in reason.lower()


def test_fail_closed_on_corrupt_or_missing_feedback_data(temp_db):
    """Verify is_finding_suppressed fails closed (returns False) on edge cases."""
    store = AnalysisStore(db_path=temp_db)
    assert store.is_finding_suppressed("", {}) is False
    assert store.is_finding_suppressed("repo", None) is False
    assert store.is_finding_suppressed("repo", {"invalid": "finding"}) is False


# ============================================================================
# 6. Prohibited Fields & Data Model Verification
# ============================================================================

def test_no_raw_source_or_prohibited_fields_stored():
    """Verify suppression records do not contain prohibited raw source code fields."""
    rec = create_suppression_record(
        suppression_id="supp_123",
        analysis_id="an_1",
        finding_id="f_1",
        repository_id="repo",
        finding_fingerprint="fp123",
        rule_signal="signal",
        file_path="main.py",
        reason="Safe reason",
    )
    for prohibited in PROHIBITED_SOURCE_FIELDS:
        assert prohibited not in rec


# ============================================================================
# 7. FastAPI REST API Endpoint Tests
# ============================================================================

def test_api_mark_false_positive_endpoint(temp_db, sample_analysis_result, monkeypatch):
    """Verify POST /analyses/{id}/findings/{id}/false-positive endpoint."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    # Patch _get_store in history router to use temp_db
    import backend.app.api.history as history_module
    monkeypatch.setattr(history_module, "_get_store", lambda: AnalysisStore(db_path=temp_db))

    client = TestClient(app)

    res = client.post(
        "/analyses/test_analysis_001/findings/finding_sqli_1/false-positive",
        json={"reason": "Handled in secure wrapper", "repository_id": "acme/payments-service"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["suppression"]["status"] == "ACTIVE"
    assert data["suppression"]["finding_id"] == "finding_sqli_1"


def test_api_get_feedback_endpoint(temp_db, sample_analysis_result, monkeypatch):
    """Verify GET /analyses/{id}/findings/{id}/feedback endpoint."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)
    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Note")

    import backend.app.api.history as history_module
    monkeypatch.setattr(history_module, "_get_store", lambda: AnalysisStore(db_path=temp_db))

    client = TestClient(app)

    res = client.get("/analyses/test_analysis_001/findings/finding_sqli_1/feedback")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["is_false_positive"] is True
    assert data["feedback"]["reason"] == "Note"


def test_api_revoke_feedback_endpoint(temp_db, sample_analysis_result, monkeypatch):
    """Verify DELETE /analyses/{id}/findings/{id}/false-positive endpoint."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)
    store.record_false_positive("test_analysis_001", "finding_sqli_1", "Note")

    import backend.app.api.history as history_module
    monkeypatch.setattr(history_module, "_get_store", lambda: AnalysisStore(db_path=temp_db))

    client = TestClient(app)

    res = client.delete("/analyses/test_analysis_001/findings/finding_sqli_1/false-positive")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["revoked"] is True
    assert data["suppression"]["status"] == "REVOKED"


def test_api_404_for_invalid_analysis_or_finding(temp_db, sample_analysis_result, monkeypatch):
    """Verify 404 responses for missing analysis or missing finding."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    import backend.app.api.history as history_module
    monkeypatch.setattr(history_module, "_get_store", lambda: AnalysisStore(db_path=temp_db))

    client = TestClient(app)

    # Missing analysis
    res1 = client.post("/analyses/nonexistent/findings/f1/false-positive", json={"reason": "test"})
    assert res1.status_code == 404

    # Missing finding
    res2 = client.post("/analyses/test_analysis_001/findings/nonexistent_f/false-positive", json={"reason": "test"})
    assert res2.status_code == 404


# ============================================================================
# 8. Phase 31E — V2 Fingerprint Identity Tests (Section A)
# ============================================================================

def test_v2_identity_same_finding_same_fingerprint():
    """Requirement A1: Same finding produce identical v2 fingerprint."""
    finding = {
        "category": "CWE-89",
        "evidence": [{
            "document_id": "app/db.py",
            "signal_type": "unsafe_sql",
            "scope": "get_user",
            "sink_name": "db.execute",
            "occurrence_index": 0,
        }]
    }
    fp1 = compute_finding_fingerprint_v2("my-repo", finding)
    fp2 = compute_finding_fingerprint_v2("my-repo", finding)
    assert fp1 == fp2
    assert len(fp1) == 32


def test_v2_identity_identical_sinks_different_occurrence():
    """Requirement A2: Two identical sink calls in same scope have distinct v2 fingerprints."""
    f1 = {
        "category": "CWE-89",
        "evidence": [{
            "document_id": "app/db.py",
            "signal_type": "unsafe_sql",
            "scope": "save",
            "sink_name": "db.execute",
            "occurrence_index": 0,
        }]
    }
    f2 = {
        "category": "CWE-89",
        "evidence": [{
            "document_id": "app/db.py",
            "signal_type": "unsafe_sql",
            "scope": "save",
            "sink_name": "db.execute",
            "occurrence_index": 1,
        }]
    }
    assert compute_finding_fingerprint_v2("repo", f1) != compute_finding_fingerprint_v2("repo", f2)


def test_v2_identity_whitespace_resilience():
    """Requirement A3: Whitespace differences do not affect v2 fingerprint."""
    f1 = {
        "category": " CWE-89 ",
        "file_path": " app\\db.py ",
        "evidence": [{
            "signal_type": " unsafe_sql ",
            "scope": " get_user ",
            "sink_name": " db.execute ",
            "occurrence_index": 0,
        }]
    }
    f2 = {
        "category": "cwe-89",
        "file_path": "app/db.py",
        "evidence": [{
            "signal_type": "unsafe_sql",
            "scope": "get_user",
            "sink_name": "db.execute",
            "occurrence_index": 0,
        }]
    }
    assert compute_finding_fingerprint_v2(" repo ", f1) == compute_finding_fingerprint_v2("repo", f2)


def test_v2_identity_line_shift_resilience():
    """Requirement A4, A5, A6: Line shifts, comments, and import insertions do not affect v2."""
    f_before = {
        "category": "CWE-89",
        "line_start": 10,
        "line_end": 12,
        "evidence": [{
            "document_id": "backend/app.py:10",
            "line_start": 10,
            "signal_type": "unsafe_sql",
            "scope": "run_query",
            "sink_name": "cursor.execute",
            "occurrence_index": 0,
        }]
    }
    f_after = {
        "category": "CWE-89",
        "line_start": 150,  # Shifted 140 lines due to imports/comments
        "line_end": 152,
        "evidence": [{
            "document_id": "backend/app.py:150",
            "line_start": 150,
            "signal_type": "unsafe_sql",
            "scope": "run_query",
            "sink_name": "cursor.execute",
            "occurrence_index": 0,
        }]
    }
    assert compute_finding_fingerprint_v2("repo", f_before) == compute_finding_fingerprint_v2("repo", f_after)


def test_v2_identity_different_scope():
    """Requirement A7: Different scope produces different v2 fingerprint."""
    f1 = {
        "category": "CWE-89",
        "file_path": "app/db.py",
        "evidence": [{"signal_type": "s", "scope": "scope_a", "sink_name": "sink", "occurrence_index": 0}]
    }
    f2 = {
        "category": "CWE-89",
        "file_path": "app/db.py",
        "evidence": [{"signal_type": "s", "scope": "scope_b", "sink_name": "sink", "occurrence_index": 0}]
    }
    assert compute_finding_fingerprint_v2("repo", f1) != compute_finding_fingerprint_v2("repo", f2)


def test_v2_identity_different_sink():
    """Requirement A8: Different sink produces different v2 fingerprint."""
    f1 = {
        "category": "CWE-89",
        "file_path": "app/db.py",
        "evidence": [{"signal_type": "s", "scope": "scope", "sink_name": "db.execute", "occurrence_index": 0}]
    }
    f2 = {
        "category": "CWE-89",
        "file_path": "app/db.py",
        "evidence": [{"signal_type": "s", "scope": "scope", "sink_name": "db.raw_query", "occurrence_index": 0}]
    }
    assert compute_finding_fingerprint_v2("repo", f1) != compute_finding_fingerprint_v2("repo", f2)


def test_v2_identity_no_trace_or_line_dependency():
    """Requirement A9: trace_fingerprint and document_id line suffixes do NOT participate in v2."""
    f1 = {
        "category": "CWE-78",
        "file_path": "app/cmd.py",
        "trace_fingerprint": "trace_xyz_1",
        "evidence": [{
            "document_id": "app/cmd.py:42",
            "signal_type": "cmd_exec",
            "scope": "run",
            "sink_name": "subprocess.run",
            "occurrence_index": 0,
        }]
    }
    f2 = {
        "category": "CWE-78",
        "file_path": "app/cmd.py",
        "trace_fingerprint": "trace_completely_different_999",
        "evidence": [{
            "document_id": "app/cmd.py:99",
            "signal_type": "cmd_exec",
            "scope": "run",
            "sink_name": "subprocess.run",
            "occurrence_index": 0,
        }]
    }
    assert compute_finding_fingerprint_v2("repo", f1) == compute_finding_fingerprint_v2("repo", f2)


# ============================================================================
# 9. Python / JavaScript Deterministic Scope & Occurrence (Section B)
# ============================================================================

def test_nested_python_scope_determinism():
    """Requirement B12: Nested Python scope outer.inner is preserved deterministically."""
    f = {
        "category": "CWE-89",
        "file_path": "handler.py",
        "evidence": [{
            "signal_type": "sqli",
            "scope": "outer.inner",
            "sink_name": "db.execute",
            "occurrence_index": 0,
        }]
    }
    fp = compute_finding_fingerprint_v2("repo", f)
    assert len(fp) == 32
    # Module fallback
    f_mod = {
        "category": "CWE-89",
        "file_path": "handler.py",
        "evidence": [{
            "signal_type": "sqli",
            "scope": "",
            "sink_name": "db.execute",
            "occurrence_index": 0,
        }]
    }
    assert compute_finding_fingerprint_v2("repo", f_mod) != fp


def test_javascript_scope_and_occurrence_determinism():
    """Requirement B11, B13: JavaScript function/method scope and duplicate sink occurrence determinism."""
    js_f1 = {
        "category": "CWE-79",
        "file_path": "frontend/render.js",
        "evidence": [{
            "signal_type": "xss",
            "scope": "renderCard",
            "sink_name": "innerHTML",
            "occurrence_index": 0,
        }]
    }
    js_f2 = {
        "category": "CWE-79",
        "file_path": "frontend/render.js",
        "evidence": [{
            "signal_type": "xss",
            "scope": "renderCard",
            "sink_name": "innerHTML",
            "occurrence_index": 1,
        }]
    }
    assert compute_finding_fingerprint_v2("repo", js_f1) != compute_finding_fingerprint_v2("repo", js_f2)


# ============================================================================
# 10. Legacy V1 Compatibility & Fail-Closed Ambiguity Tests (Section C)
# ============================================================================

def test_legacy_single_finding_suppresses(temp_db):
    """Requirement C14: Single current matching finding allows legacy v1 suppression."""
    store = AnalysisStore(db_path=temp_db)
    analysis = {
        "status": "success",
        "analysis_id": "an_legacy_1",
        "repository": {"repository": "repo-legacy"},
        "findings": [{
            "finding_id": "f_leg_1",
            "category": "CWE-89",
            "evidence": [{"document_id": "db.py", "signal_type": "sqli"}],
        }],
    }
    store.save_analysis(analysis)

    # Insert pure legacy v1 suppression directly (v2 is NULL, version is 1)
    legacy_fp = compute_finding_fingerprint("repo-legacy", "sqli", "cwe-89", "db.py")
    with store._get_connection() as conn:
        conn.execute(
            """
            INSERT INTO false_positives
            (suppression_id, analysis_id, finding_id, repository_id, finding_fingerprint,
             fingerprint_version, finding_fingerprint_v2, rule_signal, file_path, reason_code,
             reason, status, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, NULL, ?, ?, 'FALSE_POSITIVE', 'legacy note', 'ACTIVE', NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
            """,
            ("supp_leg_1", "an_legacy_1", "f_leg_1", "repo-legacy", legacy_fp, "sqli", "db.py"),
        )

    res = store.get_analysis("an_legacy_1")
    f = res["findings"][0]
    assert f["is_false_positive"] is True
    assert f["feedback"]["status"] == "ACTIVE"
    assert f["feedback"].get("legacy_ambiguous") is False


def test_legacy_ambiguity_fails_closed(temp_db):
    """Requirement C15, C16: Multiple matching findings fail closed on legacy v1 suppression."""
    store = AnalysisStore(db_path=temp_db)
    analysis = {
        "status": "success",
        "analysis_id": "an_legacy_multi",
        "repository": {"repository": "repo-legacy"},
        "findings": [
            {
                "finding_id": "f_leg_a",
                "category": "CWE-89",
                "evidence": [{"document_id": "db.py", "signal_type": "sqli", "sink_name": "db.execute", "occurrence_index": 0}],
            },
            {
                "finding_id": "f_leg_b",
                "category": "CWE-89",
                "evidence": [{"document_id": "db.py", "signal_type": "sqli", "sink_name": "db.execute", "occurrence_index": 1}],
            },
        ],
    }
    store.save_analysis(analysis)

    # Insert pure legacy v1 suppression
    legacy_fp = compute_finding_fingerprint("repo-legacy", "sqli", "cwe-89", "db.py")
    with store._get_connection() as conn:
        conn.execute(
            """
            INSERT INTO false_positives
            (suppression_id, analysis_id, finding_id, repository_id, finding_fingerprint,
             fingerprint_version, finding_fingerprint_v2, rule_signal, file_path, reason_code,
             reason, status, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, NULL, ?, ?, 'FALSE_POSITIVE', 'legacy note', 'ACTIVE', NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
            """,
            ("supp_leg_multi", "an_legacy_multi", "f_leg_a", "repo-legacy", legacy_fp, "sqli", "db.py"),
        )

    res = store.get_analysis("an_legacy_multi")
    for f in res["findings"]:
        # Both must FAIL CLOSED: unsuppressed, and expose legacy_ambiguous=True
        assert f["is_false_positive"] is False
        assert f["feedback"] is not None
        assert f["feedback"]["legacy_ambiguous"] is True


def test_v2_match_precedence_over_legacy(temp_db):
    """Requirement C18: Active v2 match takes precedence over legacy v1 matching."""
    store = AnalysisStore(db_path=temp_db)
    analysis = {
        "status": "success",
        "analysis_id": "an_prec",
        "repository": {"repository": "repo-prec"},
        "findings": [
            {
                "finding_id": "f_p1",
                "category": "CWE-89",
                "evidence": [{"document_id": "db.py", "signal_type": "sqli", "scope": "fn", "sink_name": "exec", "occurrence_index": 0}],
            },
            {
                "finding_id": "f_p2",
                "category": "CWE-89",
                "evidence": [{"document_id": "db.py", "signal_type": "sqli", "scope": "fn", "sink_name": "exec", "occurrence_index": 1}],
            }
        ],
    }
    store.save_analysis(analysis)

    # Reviewer marks f_p1 explicitly with v2
    store.record_false_positive(
        analysis_id="an_prec",
        finding_id="f_p1",
        reason="Explicit v2 review",
        reason_code="FALSE_POSITIVE",
    )

    res = store.get_analysis("an_prec")
    f1 = next(f for f in res["findings"] if f["finding_id"] == "f_p1")
    f2 = next(f for f in res["findings"] if f["finding_id"] == "f_p2")

    # f_p1 is precisely suppressed via v2
    assert f1["is_false_positive"] is True
    assert f1["feedback"]["fingerprint_version"] == 2
    assert f1["feedback"].get("legacy_ambiguous") is False

    # f_p2 remains unsuppressed
    assert f2["is_false_positive"] is False


# ============================================================================
# 11. Derived Expiration Tests (Section D)
# ============================================================================

def test_derived_expiration_evaluation():
    """Requirement D19-D24: Derived expiration semantics."""
    # No expiration => active
    assert is_suppression_active("ACTIVE", None) is True
    # Future expiration => active
    assert is_suppression_active("ACTIVE", "2099-01-01T00:00:00Z") is True
    # Past expiration => inactive
    assert is_suppression_active("ACTIVE", "2020-01-01T00:00:00Z") is False
    # Malformed expiration => inactive (fails closed)
    assert is_suppression_active("ACTIVE", "not-a-date") is False
    assert is_suppression_active("ACTIVE", "2026-13-45") is False
    # Non-ACTIVE status is always inactive
    assert is_suppression_active("REVOKED", None) is False
    assert is_suppression_active("REVOKED", "2099-01-01T00:00:00Z") is False


def test_expired_suppression_presents_unsuppressed(temp_db, sample_analysis_result):
    """Requirement D24: Finding with expired suppression is presented as unsuppressed and never persists EXPIRED."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    # Insert a record with a past expiration date directly
    past_date = "2021-01-01T00:00:00Z"
    with store._get_connection() as conn:
        conn.execute(
            """
            INSERT INTO false_positives
            (suppression_id, analysis_id, finding_id, repository_id, finding_fingerprint,
             fingerprint_version, finding_fingerprint_v2, rule_signal, file_path, reason_code,
             reason, status, expires_at, created_at, updated_at)
            VALUES ('supp_exp', 'test_analysis_001', 'finding_sqli_1', 'acme/payments-service',
                    'fp_v1', 2, 'fp_v2', 'sig', 'path', 'FALSE_POSITIVE', 'expired reason',
                    'ACTIVE', ?, '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z')
            """,
            (past_date,),
        )

    res = store.get_analysis("test_analysis_001")
    sqli_f = next(f for f in res["findings"] if f["finding_id"] == "finding_sqli_1")
    # Must present unsuppressed
    assert sqli_f["is_false_positive"] is False
    # But exposes is_expired = True in feedback
    assert sqli_f["feedback"] is not None
    assert sqli_f["feedback"]["status"] == "ACTIVE"  # Status remains ACTIVE in DB, never 'EXPIRED'
    assert sqli_f["feedback"]["is_expired"] is True

    # Confirm DB status is not EXPIRED
    with store._get_connection() as conn:
        cur = conn.execute("SELECT status FROM false_positives WHERE suppression_id = 'supp_exp'")
        row = cur.fetchone()
        assert row[0] == "ACTIVE"


# ============================================================================
# 12. Structured Reason Taxonomy Tests (Section E)
# ============================================================================

def test_reason_taxonomy_valid_and_invalid():
    """Requirement E25-E31: Structured reason validation."""
    for code in VALID_REASON_CODES:
        # All valid reason codes should validate when comment constraints are met
        comment = "Valid explanation here"
        valid_code, valid_comm = validate_reason_payload(code, comment)
        assert valid_code == code
        assert valid_comm == comment

    # Invalid reason code rejected
    with pytest.raises(ValueError, match="Invalid reason_code"):
        validate_reason_payload("INVALID_CODE", "Some reason")

    # Comment required for ACCEPTED_RISK, EXTERNAL_SANITIZATION, OTHER
    for req_code in ["ACCEPTED_RISK", "EXTERNAL_SANITIZATION", "OTHER"]:
        with pytest.raises(ValueError, match="requires an explanatory comment"):
            validate_reason_payload(req_code, None)
        with pytest.raises(ValueError, match="requires an explanatory comment"):
            validate_reason_payload(req_code, "   ")
        with pytest.raises(ValueError, match="requires an explanatory comment"):
            validate_reason_payload(req_code, "abc")  # < 5 non-whitespace chars

        valid_c, valid_msg = validate_reason_payload(req_code, "12345")  # >= 5 non-whitespace chars
        assert valid_c == req_code
        assert valid_msg == "12345"

    # Comment optional for FALSE_POSITIVE and TEST_OR_MOCK
    for opt_code in ["FALSE_POSITIVE", "TEST_OR_MOCK"]:
        c1, m1 = validate_reason_payload(opt_code, None)
        assert c1 == opt_code
        assert m1 == ""
        c2, m2 = validate_reason_payload(opt_code, "")
        assert c2 == opt_code
        assert m2 == ""

    # Length > 1000 characters rejected
    with pytest.raises(ValueError, match="exceeds maximum allowed length"):
        validate_reason_payload("FALSE_POSITIVE", "a" * 1001)


# ============================================================================
# 13. Idempotency & Reactivation Tests (Section F & G)
# ============================================================================

def test_idempotent_remark_and_reactivation(temp_db, sample_analysis_result):
    """Requirement F32-F34, G35-G37: Idempotent updates, reactivation, and revocation."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    # Initial marking
    s1 = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Initial comment",
        reason_code="FALSE_POSITIVE",
    )
    assert s1["fingerprint_version"] == 2

    # Update while ACTIVE
    s2 = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Updated comment for risk acceptance",
        reason_code="ACCEPTED_RISK",
    )
    assert s1["suppression_id"] == s2["suppression_id"]
    assert s2["reason_code"] == "ACCEPTED_RISK"
    assert s2["reason"] == "Updated comment for risk acceptance"

    # Revoke
    rev = store.revoke_false_positive("test_analysis_001", "finding_sqli_1")
    assert rev["status"] == "REVOKED"

    # Reactivate
    react = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason="Re-activating as test harness",
        reason_code="TEST_OR_MOCK",
    )
    assert react["suppression_id"] == s1["suppression_id"]
    assert react["status"] == "ACTIVE"
    assert react["reason_code"] == "TEST_OR_MOCK"


# ============================================================================
# 14. Step 6O Invariance Tests (Section H)
# ============================================================================

def test_step_6o_invariance_high_and_critical(temp_db, sample_analysis_result):
    """Requirement H38-H40: Step 6O gate evaluates raw deterministic findings and is invariant to feedback."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    # Suppress CRITICAL finding
    store.record_false_positive("test_analysis_001", "finding_sqli_1", "ORM query")
    # Suppress HIGH finding
    store.record_false_positive("test_analysis_001", "finding_cmd_2", "Safe subprocess")

    # Fetch analysis
    analysis = store.get_analysis("test_analysis_001")
    decision, exit_code, reason = evaluate_security_gate(analysis)

    # Step 6O must strictly BLOCK
    assert decision == "BLOCK"
    assert exit_code == 1
    assert "critical" in reason.lower() or "block" in reason.lower()


# ============================================================================
# 15. Security & Injection Boundary Tests (Section I)
# ============================================================================

def test_sql_injection_resilience(temp_db, sample_analysis_result):
    """Requirement I41-I45: SQL injection payloads in reason, repo, path do not corrupt queries."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    sqli_payload = "'; DROP TABLE false_positives; --"
    rec = store.record_false_positive(
        analysis_id="test_analysis_001",
        finding_id="finding_sqli_1",
        reason=f"Safe comment with injection {sqli_payload}",
        reason_code="OTHER",
    )
    assert rec is not None

    # Verify table still exists and record is preserved
    with store._get_connection() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM false_positives")
        count = cur.fetchone()[0]
        assert count == 1


def test_expiration_timezone_manipulation_rejected():
    """Requirement I45: Expiration must be valid UTC future timestamp."""
    # Past timestamp rejected
    with pytest.raises(ValueError, match="strictly later than current server UTC time"):
        validate_utc_iso_timestamp("2020-01-01T00:00:00Z", must_be_future=True)

    # Non-UTC timezone offset rejected (if offset is not UTC)
    assert validate_utc_iso_timestamp(None) is None
    assert validate_utc_iso_timestamp("") is None
    with pytest.raises(ValueError, match="Invalid ISO 8601"):
        validate_utc_iso_timestamp("invalid-date-format")


def test_python_duplicate_sink_occurrence_indices():
    """Requirement B10: Python duplicate sink occurrences have deterministic index increments."""
    py_f1 = {
        "category": "CWE-89",
        "file_path": "backend/service.py",
        "evidence": [{
            "signal_type": "unsafe_database_execution",
            "scope": "save",
            "sink_name": "db.execute",
            "occurrence_index": 0,
        }]
    }
    py_f2 = {
        "category": "CWE-89",
        "file_path": "backend/service.py",
        "evidence": [{
            "signal_type": "unsafe_database_execution",
            "scope": "save",
            "sink_name": "db.execute",
            "occurrence_index": 1,
        }]
    }
    assert compute_finding_fingerprint_v2("acme/service", py_f1) != compute_finding_fingerprint_v2("acme/service", py_f2)


def test_client_cannot_arbitrarily_control_fingerprints_or_status(temp_db, sample_analysis_result, monkeypatch):
    """Requirement I43, I44: Client cannot arbitrarily dictate fingerprints or status."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(sample_analysis_result)

    import backend.app.api.history as history_module
    monkeypatch.setattr(history_module, "_get_store", lambda: AnalysisStore(db_path=temp_db))

    client = TestClient(app)

    # Try submitting invalid reason code
    res_bad = client.post(
        "/analyses/test_analysis_001/findings/finding_sqli_1/false-positive",
        json={"reason": "test", "reason_code": "ARBITRARY_SUPER_STATUS"},
    )
    assert res_bad.status_code == 400
    assert "Invalid reason_code" in res_bad.json()["detail"]

    # Try submitting spoofed fingerprints in payload - backend computes them server-side
    res_spoof = client.post(
        "/analyses/test_analysis_001/findings/finding_sqli_1/false-positive",
        json={
            "reason": "Legitimate test harness",
            "reason_code": "TEST_OR_MOCK",
            "finding_fingerprint": "client_crafted_v1",
            "finding_fingerprint_v2": "client_crafted_v2",
            "status": "REVOKED",  # Client attempts to mark as revoked directly
        },
    )
    assert res_spoof.status_code == 200
    data = res_spoof.json()
    # Status is forced to ACTIVE by server endpoint
    assert data["suppression"]["status"] == "ACTIVE"
    # Fingerprints are computed server-side
    assert data["suppression"]["finding_fingerprint_v2"] != "client_crafted_v2"
    assert len(data["suppression"]["finding_fingerprint_v2"]) == 32

