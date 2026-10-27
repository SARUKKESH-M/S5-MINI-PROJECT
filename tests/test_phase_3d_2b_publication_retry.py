"""Phase 3D-2B Test Suite: Publication Retry, Check Run Deduplication, and Stale-Head Safety.

Verifies:
1. Existing analysis with completed publication returns already_analyzed without republishing.
2. Existing analysis with incomplete publication is republished without rerunning AST analysis.
3. Check Run creation failure during retry releases reservation.
4. Commit Status publication failure during retry releases reservation.
5. PR comment publication failure during retry releases reservation.
6. Partial publication success followed by a successful retry completes reservation.
7. Reuse and update of an existing Check Run without duplication.
8. New Check Run creation when none exists.
9. Duplicate delivery handling.
10. Concurrent reservation attempts during republication.
11. Stale or changed PR head SHA protection (never publish mismatched findings).
12. Reservation completion on full publication success.
13. Reservation release on failure and unexpected exceptions.
14. Frozen report schema remains strictly preserved.
"""

import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch
import pytest

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage.store import AnalysisStore
from backend.github.orchestrator import orchestrate_webhook_event
from backend.github.publisher import find_existing_check_run_id, CHECK_RUN_NAME

VALID_HEAD_SHA = "a" * 40
VALID_BASE_SHA = "b" * 40
ALT_HEAD_SHA = "c" * 40


@pytest.fixture
def temp_db():
    """Provide isolated temporary database file path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    store = AnalysisStore(db_path=db_path)
    store.initialize()
    yield db_path
    try:
        os.remove(db_path)
    except OSError:
        pass


def _make_valid_pr_payload(
    pr_number: int = 42,
    head_sha: str = VALID_HEAD_SHA,
    base_sha: str = VALID_BASE_SHA,
    owner: str = "octocat",
    repo: str = "Hello-World"
):
    """Helper to generate a valid PR webhook payload."""
    return {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "title": "Security harden auth",
            "html_url": f"https://github.com/{owner}/{repo}/pull/{pr_number}",
            "user": {"login": owner},
            "head": {"sha": head_sha, "ref": "feature-branch"},
            "base": {"sha": base_sha, "ref": "main"}
        },
        "repository": {
            "name": repo,
            "owner": {"login": owner}
        }
    }


def _build_test_report(
    analysis_id: str = "ana_test_3d2b",
    review_status: str = "allow",
    head_sha: str = VALID_HEAD_SHA,
    owner: str = "octocat",
    repo: str = "Hello-World",
    pr_number: int = 42
):
    """Helper to generate a valid frozen Step 6O production report."""
    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "repository": {
            "owner": owner,
            "repository": repo,
            "branch": f"pr/{pr_number}",
            "path": ".",
            "pr_number": pr_number,
            "head_sha": head_sha,
            "base_sha": VALID_BASE_SHA,
            "author": owner,
        },
        "review_status": review_status,
        "summary": {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "analyzed_files": 1,
        },
        "findings": [],
        "analysis_version": "1.0.0",
        "owner": owner,
        "repository_id": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "base_sha": VALID_BASE_SHA,
        "author": owner,
        "query": f"repo:{owner}/{repo}",
        "created_at": "2026-10-25T12:00:00+00:00"
    }


# =============================================================================
# 1. COMPLETED PUBLICATION SHORT-CIRCUIT
# =============================================================================

def test_existing_analysis_with_completed_publication_returns_already_analyzed(temp_db, monkeypatch):
    """When analysis exists and reservation is 'completed', return already_analyzed without republishing."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_completed_1")
    store.save_analysis(report)
    store.complete_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA, "ana_completed_1")

    mock_pub = MagicMock()
    mock_comm = MagicMock()
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-comp-1", payload, db_path=temp_db)

    assert result["status"] == "already_analyzed"
    assert result["reason"] == "commit_already_analyzed"
    assert result["analysis_id"] == "ana_completed_1"
    mock_pub.assert_not_called()
    mock_comm.assert_not_called()


# =============================================================================
# 2. INCOMPLETE PUBLICATION REPUBLISH WITHOUT AST RERUN
# =============================================================================

def test_existing_analysis_incomplete_publication_republished_without_ast_rerun(temp_db, monkeypatch):
    """When analysis is persisted but reservation is incomplete, republish without rerunning AST analysis."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_incomplete_1")
    store.save_analysis(report)
    # Reservation is not completed (simulate previous failure release)

    mock_ast = MagicMock()
    mock_pub = MagicMock(return_value={"check_run": {"id": 101}, "commit_status": {"state": "success"}})
    mock_comm = MagicMock(return_value={"status": "created", "comment_id": 202})

    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", mock_ast)
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-retry-1", payload, db_path=temp_db)

    assert result["status"] == "success"
    assert result["analysis_id"] == "ana_incomplete_1"
    # AST analysis must NOT have been rerun
    mock_ast.assert_not_called()
    # Publication must have been called
    mock_pub.assert_called_once()
    mock_comm.assert_called_once()

    # Reservation must now be marked completed
    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is not None
    assert res["status"] == "completed"
    assert res["analysis_id"] == "ana_incomplete_1"


# =============================================================================
# 3. PUBLICATION FAILURE MODES DURING RETRY
# =============================================================================

def test_check_run_failure_during_retry_releases_reservation(temp_db, monkeypatch):
    """When Check Run publication fails during retry, return publication_failed and release reservation."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_fail_cr")
    store.save_analysis(report)

    mock_pub = MagicMock(side_effect=Exception("GitHub Check Run 500"))
    mock_comm = MagicMock(return_value={"status": "created"})

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-cr-fail", payload, db_path=temp_db)

    assert result["status"] == "partial_success"
    assert result["reason"] == "partial_publication_failure"

    # Reservation was released for subsequent retry
    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is None


def test_commit_status_failure_during_retry_releases_reservation(temp_db, monkeypatch):
    """When Commit Status publication fails during retry, release reservation."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_fail_cs")
    store.save_analysis(report)

    # Status publisher failure returns status: failed -> publication_failed
    mock_pub = MagicMock(return_value={"status": "failed", "reason": "status_publishing_error"})
    mock_comm = MagicMock(return_value={"status": "failed"})

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-cs-fail", payload, db_path=temp_db)

    assert result["status"] == "publication_failed"
    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is None


def test_pr_comment_failure_during_retry_releases_reservation(temp_db, monkeypatch):
    """When PR comment publication fails during retry, release reservation."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_fail_comment")
    store.save_analysis(report)

    mock_pub = MagicMock(return_value={"check_run": {"id": 1}, "commit_status": {"state": "success"}})
    mock_comm = MagicMock(side_effect=Exception("Comment API 403"))

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-comm-fail", payload, db_path=temp_db)

    assert result["status"] == "partial_success"
    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is None


# =============================================================================
# 4. PARTIAL SUCCESS AND SUBSEQUENT RETRY
# =============================================================================

def test_partial_success_then_subsequent_retry_completes(temp_db, monkeypatch):
    """Partial success releases lock; subsequent retry completes publication."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_partial_recov")
    store.save_analysis(report)

    # Attempt 1: Comment fails -> partial_success
    mock_pub = MagicMock(return_value={"check_run": {"id": 55}, "commit_status": {"state": "success"}})
    mock_comm_fail = MagicMock(return_value={"status": "failed"})

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm_fail)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    res1 = orchestrate_webhook_event("pull_request", "deliv-part-1", payload, db_path=temp_db)
    assert res1["status"] == "partial_success"

    # Attempt 2: Comment succeeds -> success
    mock_comm_succ = MagicMock(return_value={"status": "created", "comment_id": 99})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm_succ)

    res2 = orchestrate_webhook_event("pull_request", "deliv-part-2", payload, db_path=temp_db)
    assert res2["status"] == "success"

    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is not None
    assert res["status"] == "completed"


# =============================================================================
# 5. CHECK RUN DEDUPLICATION & REUSE
# =============================================================================

def test_find_existing_check_run_id_matches_correct_run():
    """Verify find_existing_check_run_id filters by name and SHA, ignoring unrelated runs."""
    mock_client = MagicMock()
    mock_client.get.return_value = {
        "check_runs": [
            {"id": 1, "name": "CI / Build", "head_sha": VALID_HEAD_SHA},
            {"id": 2, "name": CHECK_RUN_NAME, "head_sha": "other_sha", "created_at": "2026-10-25T10:00:00Z"},
            {"id": 42, "name": CHECK_RUN_NAME, "head_sha": VALID_HEAD_SHA, "created_at": "2026-10-25T11:00:00Z"},
        ]
    }

    found_id = find_existing_check_run_id("octocat", "Hello-World", VALID_HEAD_SHA, client=mock_client)
    assert found_id == 42


def test_find_existing_check_run_id_returns_none_when_no_match():
    """Verify find_existing_check_run_id returns None when no matching check run exists."""
    mock_client = MagicMock()
    mock_client.get.return_value = {
        "check_runs": [
            {"id": 1, "name": "CI / Build", "head_sha": VALID_HEAD_SHA}
        ]
    }
    found_id = find_existing_check_run_id("octocat", "Hello-World", VALID_HEAD_SHA, client=mock_client)
    assert found_id is None


def test_check_run_reuse_passed_to_publisher(temp_db, monkeypatch):
    """Verify orchestrator discovers existing check run and passes check_run_id to publisher."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_reuse_cr")
    store.save_analysis(report)

    monkeypatch.setattr("backend.github.orchestrator.find_existing_check_run_id", lambda *a, **k: 777)
    mock_pub = MagicMock(return_value={"check_run": {"id": 777}, "commit_status": {"state": "success"}})
    mock_comm = MagicMock(return_value={"status": "created"})

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-reuse-1", payload, db_path=temp_db)

    assert result["status"] == "success"
    # publish_step_6o_report_status must have received check_run_id=777
    call_kwargs = mock_pub.call_args[1]
    assert call_kwargs["check_run_id"] == 777


# =============================================================================
# 6. STALE HEAD SHA & CONCURRENCY
# =============================================================================

def test_stale_or_changed_pr_head_sha_rejected(temp_db, monkeypatch):
    """When persisted report head SHA does not match current PR head, reject and release reservation."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_stale_1", head_sha=ALT_HEAD_SHA)
    store.save_analysis(report)

    # Mock store to return the report with ALT_HEAD_SHA when querying VALID_HEAD_SHA
    monkeypatch.setattr(store, "get_pr_analysis_by_commit", lambda *a, **k: report)
    monkeypatch.setattr("backend.github.orchestrator._get_analysis_store", lambda *a, **k: store)

    mock_pub = MagicMock()
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)

    payload = _make_valid_pr_payload(head_sha=VALID_HEAD_SHA)
    result = orchestrate_webhook_event("pull_request", "deliv-stale-1", payload, db_path=temp_db)

    assert result["status"] == "ignored"
    assert result["reason"] == "stale_report_head_sha_mismatch"
    mock_pub.assert_not_called()

    # Reservation was released and not left locked
    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is None


def test_concurrent_republication_reservation(temp_db, monkeypatch):
    """Verify concurrent workers attempting republication observe in-progress lock."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_concurrent")
    store.save_analysis(report)

    # Worker 1 reserves the commit
    res1, reason1, _ = store.reserve_pr_commit_analysis("octocat", "Hello-World", 42, VALID_HEAD_SHA, allow_republish=True)
    assert res1 is True
    assert reason1 == "reserved"

    # Worker 2 attempts orchestration for the same commit
    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-worker-2", payload, db_path=temp_db)

    assert result["status"] == "in_progress"
    assert result["reason"] == "analysis_in_progress"


# =============================================================================
# 7. UNEXPECTED EXCEPTION & SCHEMA INVARIANTS
# =============================================================================

def test_unexpected_exception_during_republish_releases_reservation(temp_db, monkeypatch):
    """When an unexpected exception occurs during republish, release delivery and commit reservation."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_unhandled")
    store.save_analysis(report)

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", MagicMock(return_value={"check_run": {"id": 1}, "commit_status": {"state": "success"}}))
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", MagicMock(return_value={"status": "created"}))
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    # Force unexpected exception during complete_pr_commit_reservation to test outer exception handling
    monkeypatch.setattr(store, "complete_pr_commit_reservation", MagicMock(side_effect=RuntimeError("Database corruption on commit")))
    monkeypatch.setattr("backend.github.orchestrator._get_analysis_store", lambda *a, **k: store)

    payload = _make_valid_pr_payload()
    with pytest.raises(RuntimeError):
        orchestrate_webhook_event("pull_request", "deliv-fatal", payload, db_path=temp_db)

    # Reservation was released and not completed
    res = store.get_pr_commit_reservation("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert res is None or res.get("status") != "completed"


def test_frozen_report_schema_preserved_on_retry(temp_db, monkeypatch):
    """Verify report schema keys are strictly preserved throughout the retry pipeline."""
    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_schema_check")
    store.save_analysis(report)

    published_report = {}

    def mock_publish(owner, repository, head_sha, report, **kwargs):
        nonlocal published_report
        published_report = report
        return {"check_run": {"id": 1}, "commit_status": {"state": "success"}}

    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_publish)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", lambda *a, **k: {"status": "created"})
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-schema", payload, db_path=temp_db)

    assert result["status"] == "success"

    # Frozen production report schema verification
    required_keys = [
        "analysis_id",
        "status",
        "repository",
        "review_status",
        "summary",
        "findings",
        "analysis_version",
    ]
    for key in required_keys:
        assert key in published_report, f"Missing required frozen report key: {key}"
