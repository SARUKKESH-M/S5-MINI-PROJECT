"""Comprehensive Test Suite for P1 #4: Developer Security Analytics.

Verifies:
1. Author metadata persistence in SQLite analyses store.
2. Developer aggregation logic in AnalysisStore.get_developer_analytics().
3. Metric calculations: total_analyses, total_findings, critical/high/med/low, gate blocks/reviews/allows.
4. Repository deduplication and repository-scoped filtering.
5. Last activity timestamp tracking.
6. Deterministic ordering without row-order nondeterminism.
7. Safe fallback for missing, unknown, or malformed author fields.
8. Non-interference with Step 6O Security Gate policies.
9. Compatibility with P1 #3 false-positive feedback records.
10. REST API endpoint GET /platform/developers contract and query parameter validation.
"""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.analysis.storage.store import AnalysisStore
from backend.analysis.security_gate import evaluate_security_gate
from backend.app.main import app


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database path for isolated testing."""
    fd, path = tempfile.mkstemp(suffix="_test_dev_analytics.db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _create_sample_record(
    analysis_id: str,
    author: str = "alice",
    repo_name: str = "acme/payments",
    review_status: str = "block",
    critical: int = 1,
    high: int = 1,
    medium: int = 0,
    low: int = 0,
    created_at: str = "2026-09-01T10:00:00Z",
):
    """Helper to construct a standardized analysis record dictionary."""
    total = critical + high + medium + low
    findings = []
    for idx in range(total):
        findings.append({
            "finding_id": f"f_{analysis_id}_{idx}",
            "title": f"Finding {idx}",
            "description": "AST security evidence",
            "severity": "critical" if idx < critical else "high" if idx < (critical + high) else "medium",
            "confidence": "high",
            "category": "Injection",
            "evidence": [{"document_id": "app.py", "line_start": 10, "line_end": 12, "signal_type": "call", "signal_name": "exec"}],
        })

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "query": f"PR Analysis: {repo_name}",
        "created_at": created_at,
        "review_status": review_status,
        "author": author,
        "repository": {
            "owner": repo_name.split("/")[0] if "/" in repo_name else "acme",
            "repository": repo_name.split("/")[1] if "/" in repo_name else repo_name,
            "branch": "main",
            "path": ".",
            "author": author,
        },
        "summary": {
            "total_findings": total,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "info_count": 0,
        },
        "findings": findings,
    }


# ============================================================================
# 1. Author Metadata Persistence Tests
# ============================================================================

def test_author_metadata_is_persisted_in_store(temp_db):
    """Verify that author identity is preserved in summary_json and get_analysis."""
    store = AnalysisStore(db_path=temp_db)
    rec = _create_sample_record("ana_1", author="octocat", repo_name="acme/auth")
    store.save_analysis(rec)

    retrieved = store.get_analysis("ana_1")
    assert retrieved is not None
    assert retrieved.get("author") == "octocat"
    assert retrieved["summary"]["total_findings"] == 2


def test_author_extracted_from_nested_repository_metadata(temp_db):
    """Verify author is extracted even if only provided in repository dict."""
    store = AnalysisStore(db_path=temp_db)
    rec = {
        "status": "success",
        "analysis_id": "ana_nested_author",
        "query": "Test query",
        "repository": {"owner": "org", "repository": "repo", "author": "nested_dev"},
        "summary": {"total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": [],
    }
    store.save_analysis(rec)

    retrieved = store.get_analysis("ana_nested_author")
    assert retrieved is not None
    assert retrieved.get("author") == "nested_dev"


# ============================================================================
# 2. Developer Aggregator Core Logic Tests
# ============================================================================

def test_empty_database_returns_empty_developers(temp_db):
    """Verify empty database returns empty developer analytics list."""
    store = AnalysisStore(db_path=temp_db)
    devs = store.get_developer_analytics()
    assert devs == []


def test_single_developer_single_analysis(temp_db):
    """Verify aggregation for a single developer with one analysis."""
    store = AnalysisStore(db_path=temp_db)
    rec = _create_sample_record("ana_1", author="alice", repo_name="acme/payments", review_status="block", critical=2, high=1, medium=1, low=0)
    store.save_analysis(rec)

    devs = store.get_developer_analytics()
    assert len(devs) == 1
    d = devs[0]
    assert d["developer"] == "alice"
    assert d["total_analyses"] == 1
    assert d["total_findings"] == 4
    assert d["critical_count"] == 2
    assert d["high_count"] == 1
    assert d["medium_count"] == 1
    assert d["low_count"] == 0
    assert d["block_count"] == 1
    assert d["review_count"] == 0
    assert d["allow_count"] == 0
    assert d["repositories"] == ["acme/payments"]
    assert d["last_activity"] == "2026-09-01T10:00:00Z"


def test_single_developer_multiple_analyses(temp_db):
    """Verify aggregation correctly sums metrics across multiple analyses for the same developer."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("ana_1", author="bob", repo_name="acme/repo-a", review_status="block", critical=1, high=0, created_at="2026-09-01T10:00:00Z"))
    store.save_analysis(_create_sample_record("ana_2", author="bob", repo_name="acme/repo-b", review_status="review", critical=0, high=2, medium=1, created_at="2026-09-02T12:00:00Z"))
    store.save_analysis(_create_sample_record("ana_3", author="bob", repo_name="acme/repo-a", review_status="allow", critical=0, high=0, created_at="2026-09-03T14:00:00Z"))

    devs = store.get_developer_analytics()
    assert len(devs) == 1
    d = devs[0]
    assert d["developer"] == "bob"
    assert d["total_analyses"] == 3
    assert d["total_findings"] == 4
    assert d["critical_count"] == 1
    assert d["high_count"] == 2
    assert d["medium_count"] == 1
    assert d["block_count"] == 1
    assert d["review_count"] == 1
    assert d["allow_count"] == 1
    assert d["repositories"] == ["acme/repo-a", "acme/repo-b"]
    assert d["last_activity"] == "2026-09-03T14:00:00Z"


def test_multiple_developers_aggregation(temp_db):
    """Verify multiple developers are isolated and tracked independently."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("ana_alice_1", author="alice", critical=2))
    store.save_analysis(_create_sample_record("ana_bob_1", author="bob", critical=0, high=1))
    store.save_analysis(_create_sample_record("ana_charlie_1", author="charlie", critical=0, high=0))

    devs = store.get_developer_analytics()
    assert len(devs) == 3
    dev_names = [d["developer"] for d in devs]
    assert "alice" in dev_names
    assert "bob" in dev_names
    assert "charlie" in dev_names


# ============================================================================
# 3. Deterministic Ordering & Ranking Tests
# ============================================================================

def test_deterministic_ranking_by_security_volume(temp_db):
    """Verify developers are ranked deterministically by critical, high, total findings."""
    store = AnalysisStore(db_path=temp_db)
    # dev_low has 0 critical, 0 high, 2 medium
    store.save_analysis(_create_sample_record("a1", author="dev_low", critical=0, high=0, medium=2))
    # dev_crit has 2 critical
    store.save_analysis(_create_sample_record("a2", author="dev_crit", critical=2, high=0, medium=0))
    # dev_high has 1 critical, 3 high
    store.save_analysis(_create_sample_record("a3", author="dev_high", critical=1, high=3, medium=0))

    devs = store.get_developer_analytics()
    assert devs[0]["developer"] == "dev_crit"
    assert devs[1]["developer"] == "dev_high"
    assert devs[2]["developer"] == "dev_low"


def test_alphabetical_tie_breaker(temp_db):
    """Verify identical metrics break ties alphabetically by developer username."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("a1", author="zara", critical=1, high=1))
    store.save_analysis(_create_sample_record("a2", author="adam", critical=1, high=1))

    devs = store.get_developer_analytics()
    assert devs[0]["developer"] == "adam"
    assert devs[1]["developer"] == "zara"


# ============================================================================
# 4. Repository Scoping & Filtering Tests
# ============================================================================

def test_repository_filtering(temp_db):
    """Verify repository filter returns only developers and analyses for that repository."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("a1", author="alice", repo_name="acme/payments"))
    store.save_analysis(_create_sample_record("a2", author="bob", repo_name="acme/frontend"))

    devs_payments = store.get_developer_analytics(repository="acme/payments")
    assert len(devs_payments) == 1
    assert devs_payments[0]["developer"] == "alice"

    devs_frontend = store.get_developer_analytics(repository="acme/frontend")
    assert len(devs_frontend) == 1
    assert devs_frontend[0]["developer"] == "bob"

    devs_nonexistent = store.get_developer_analytics(repository="acme/nonexistent")
    assert devs_nonexistent == []


def test_limit_parameter_bounds(temp_db):
    """Verify limit parameter caps the returned list length."""
    store = AnalysisStore(db_path=temp_db)
    for i in range(5):
        store.save_analysis(_create_sample_record(f"a_{i}", author=f"dev_{i}", critical=i))

    devs = store.get_developer_analytics(limit=2)
    assert len(devs) == 2


# ============================================================================
# 5. Missing / Malformed Metadata Safety Tests
# ============================================================================

def test_missing_or_blank_author_is_ignored_safely(temp_db):
    """Verify records without author are skipped without raising errors or fabricating users."""
    store = AnalysisStore(db_path=temp_db)
    # Record with no author
    no_author_rec = {
        "status": "success",
        "analysis_id": "ana_no_author",
        "query": "Ad-hoc scan",
        "summary": {"total_findings": 1, "critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": [],
    }
    store.save_analysis(no_author_rec)

    # Record with explicit author
    store.save_analysis(_create_sample_record("ana_with_author", author="valid_dev"))

    devs = store.get_developer_analytics()
    assert len(devs) == 1
    assert devs[0]["developer"] == "valid_dev"


def test_placeholder_tokens_are_ignored(temp_db):
    """Verify placeholder tokens like 'unknown', 'null', 'none' are filtered safely."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("a1", author="unknown"))
    store.save_analysis(_create_sample_record("a2", author="null"))
    store.save_analysis(_create_sample_record("a3", author="none"))
    store.save_analysis(_create_sample_record("a4", author="  "))
    store.save_analysis(_create_sample_record("a5", author="real_author"))

    devs = store.get_developer_analytics()
    assert len(devs) == 1
    assert devs[0]["developer"] == "real_author"


# ============================================================================
# 6. Security Gate Invariance Tests
# ============================================================================

def test_security_gate_remains_invariant_to_developer_analytics(temp_db):
    """Verify Step 6O Security Gate is completely independent of developer analytics."""
    store = AnalysisStore(db_path=temp_db)
    rec = _create_sample_record("ana_gate_test", author="expert_dev", critical=1, review_status="block")
    store.save_analysis(rec)

    # Compute analytics
    devs = store.get_developer_analytics()
    assert len(devs) == 1

    # Security gate still evaluates the report canonically
    analysis = store.get_analysis("ana_gate_test")
    decision, exit_code, reason = evaluate_security_gate(analysis)
    assert decision == "BLOCK"
    assert exit_code == 1


# ============================================================================
# 7. False-Positive Interaction Tests (P1 #3 Boundary)
# ============================================================================

def test_false_positive_feedback_preserves_developer_findings(temp_db):
    """Verify marking a finding as false-positive does not delete it or corrupt developer totals."""
    store = AnalysisStore(db_path=temp_db)
    rec = _create_sample_record("ana_fp_test", author="dave", critical=1, high=0)
    store.save_analysis(rec)

    # Developer marks finding as false-positive
    store.record_false_positive("ana_fp_test", "f_ana_fp_test_0", "Audited as safe wrapper")

    # Developer analytics continues to reflect historical findings
    devs = store.get_developer_analytics()
    assert len(devs) == 1
    assert devs[0]["developer"] == "dave"
    assert devs[0]["total_findings"] == 1


# ============================================================================
# 8. REST API GET /platform/developers Tests
# ============================================================================

def test_api_platform_developers_empty(monkeypatch, temp_db):
    """Verify GET /platform/developers returns 200 with empty list on fresh database."""
    import backend.analysis.storage.store as store_module
    monkeypatch.setattr(store_module, "get_default_db_path", lambda: temp_db)

    client = TestClient(app)
    res = client.get("/platform/developers")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["developers"] == []
    assert data["total_developers"] == 0


def test_api_platform_developers_populated(monkeypatch, temp_db):
    """Verify GET /platform/developers returns aggregated records with correct schema."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("ana_api_1", author="eve", repo_name="acme/service", critical=1, high=1))

    import backend.analysis.storage.store as store_module
    monkeypatch.setattr(store_module, "get_default_db_path", lambda: temp_db)

    client = TestClient(app)
    res = client.get("/platform/developers")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["total_developers"] == 1

    d = data["developers"][0]
    assert d["developer"] == "eve"
    assert d["total_analyses"] == 1
    assert d["total_findings"] == 2
    assert d["critical_count"] == 1
    assert d["high_count"] == 1
    assert d["repositories"] == ["acme/service"]


def test_api_platform_developers_query_params(monkeypatch, temp_db):
    """Verify limit and repository query parameters on GET /platform/developers."""
    store = AnalysisStore(db_path=temp_db)
    store.save_analysis(_create_sample_record("a1", author="user_a", repo_name="org/backend"))
    store.save_analysis(_create_sample_record("a2", author="user_b", repo_name="org/frontend"))

    import backend.analysis.storage.store as store_module
    monkeypatch.setattr(store_module, "get_default_db_path", lambda: temp_db)

    client = TestClient(app)

    # Test repository filter
    res = client.get("/platform/developers?repository=org/backend")
    assert res.status_code == 200
    data = res.json()
    assert data["total_developers"] == 1
    assert data["developers"][0]["developer"] == "user_a"

    # Test limit filter
    res_limit = client.get("/platform/developers?limit=1")
    assert res_limit.status_code == 200
    assert res_limit.json()["total_developers"] == 1
