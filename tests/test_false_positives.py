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

from backend.analysis.storage.models import PROHIBITED_SOURCE_FIELDS, create_suppression_record
from backend.analysis.storage.store import (
    AnalysisStore,
    compute_finding_fingerprint,
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
