"""Phase 3D-2A Test Suite: Webhook Delivery Claims and Commit Reservation Lifecycle.

Validates the lifecycle of webhook delivery claims and PR commit reservations:
1. Retryable handled publication failure (publication_failed) releases the delivery claim.
2. Partial publication failure (partial_success) releases the delivery claim.
3. Subsequent attempt with the same delivery ID is eligible to retry (not rejected as duplicate).
4. Successful publication retains the delivery claim (duplicate delivery is suppressed).
5. Successful publication transitions the commit reservation to status='completed'.
6. Commit reservation receives exact normalized owner, repo, pr_number, head_sha, and analysis_id.
7. Handled publication failure (publication_failed) does not mark commit reservation completed and releases in-progress lock.
8. Partial publication failure (partial_success) does not mark commit reservation completed.
9. Unexpected exceptions during orchestration release both delivery claim and commit reservation.
"""

import os
import sys
import tempfile
import pytest
from unittest.mock import MagicMock, patch
import httpx

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage.store import AnalysisStore
from backend.github.orchestrator import orchestrate_webhook_event
from backend.github.webhook import (
    claim_webhook_delivery,
    release_webhook_delivery,
    release_pr_commit_reservation,
)

VALID_HEAD_SHA = "a" * 40
VALID_BASE_SHA = "b" * 40


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
    repo: "Hello-World" = "Hello-World"
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


def _build_mock_report(analysis_id: str = "ana_test_123"):
    """Helper to return a dummy Step 6O report dict."""
    return {
        "status": "completed",
        "review_status": "allow",
        "analysis_id": analysis_id,
        "query": "repo:octocat/Hello-World",
        "created_at": "2026-10-25T12:00:00+00:00",
        "repository": {
            "owner": "octocat",
            "repository": "Hello-World",
            "branch": "pr/42",
            "path": ".",
            "pr_number": 42,
            "head_sha": VALID_HEAD_SHA,
            "base_sha": VALID_BASE_SHA,
            "author": "octocat",
        },
        "owner": "octocat",
        "repository_id": "Hello-World",
        "pr_number": 42,
        "head_sha": VALID_HEAD_SHA,
        "base_sha": VALID_BASE_SHA,
        "author": "octocat",
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
        "analysis_version": "1.0.0"
    }


# =============================================================================
# 1. DELIVERY CLAIM LIFECYCLE TESTS (Defect A)
# =============================================================================

def test_1_publication_failure_releases_delivery_claim(temp_db, monkeypatch):
    """1. Handled publication_failed status releases the delivery claim."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_fail_001"
    payload = _make_valid_pr_payload()

    # Mock acquire and analysis report generation to succeed
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report("ana_fail_1"))

    # Mock publication to fail
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", MagicMock(side_effect=Exception("Status API 500")))
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", MagicMock(side_effect=Exception("Comment API 500")))

    res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res["status"] == "publication_failed"
    assert res["reason"] == "publication_failed"

    # Delivery claim MUST be released
    assert not store.is_delivery_claimed(delivery_id)


def test_2_partial_publication_failure_releases_delivery_claim(temp_db, monkeypatch):
    """2. Handled partial_success status releases the delivery claim."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_partial_002"
    payload = _make_valid_pr_payload()

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report("ana_partial_2"))

    # Status succeeds, but comment fails -> partial_success
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 123}, "commit_status": {}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", MagicMock(side_effect=Exception("Comment API 503")))

    res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res["status"] == "partial_success"
    assert res["reason"] == "partial_publication_failure"

    # Delivery claim MUST be released
    assert not store.is_delivery_claimed(delivery_id)


def test_3_subsequent_attempt_with_same_delivery_id_is_eligible_to_retry(temp_db, monkeypatch):
    """3. After publication failure, the same delivery_id can be reclaimed (not rejected as duplicate)."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_retry_003"
    payload = _make_valid_pr_payload()

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report("ana_retry_3"))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", MagicMock(side_effect=Exception("GitHub 500")))
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", MagicMock(side_effect=Exception("GitHub 500")))

    # First attempt: fails
    res1 = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res1["status"] == "publication_failed"

    # Delivery claim is released, so claim_webhook_delivery for the same ID succeeds
    can_claim = claim_webhook_delivery(delivery_id, "pull_request", db_path=temp_db)
    assert can_claim is True


def test_4_successful_publication_retains_delivery_claim(temp_db, monkeypatch):
    """4. Successful publication retains the delivery claim, and duplicate deliveries are suppressed."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_success_004"
    payload = _make_valid_pr_payload()

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report("ana_success_4"))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 10}, "commit_status": {}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", lambda *a, **k: {"status": "created", "comment_id": 99})

    res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res["status"] == "success"

    # Delivery claim MUST remain active
    assert store.is_delivery_claimed(delivery_id)

    # Redelivery of the same delivery ID MUST return duplicate
    dup_res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert dup_res["status"] == "duplicate"
    assert dup_res["reason"] == "delivery_already_processed"


# =============================================================================
# 2. COMMIT RESERVATION LIFECYCLE TESTS (Defect B)
# =============================================================================

def test_5_successful_processing_completes_commit_reservation(temp_db, monkeypatch):
    """5. Successful webhook processing marks the matching commit reservation status='completed'."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_res_005"
    payload = _make_valid_pr_payload(pr_number=55, head_sha="c" * 40)
    analysis_id = "ana_completed_5"

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report(analysis_id))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 1}, "commit_status": {}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", lambda *a, **k: {"status": "created", "comment_id": 2})

    res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res["status"] == "success"

    # Verify in pr_commit_reservations table
    commit_key = f"octocat/hello-world:55:{'c' * 40}"
    with store._get_connection() as conn:
        row = conn.execute(
            "SELECT status, analysis_id, owner, repository, pr_number, head_sha FROM pr_commit_reservations WHERE commit_key = ?;",
            (commit_key,)
        ).fetchone()

    assert row is not None
    assert row["status"] == "completed"
    assert row["analysis_id"] == analysis_id
    assert row["owner"] == "octocat"
    assert row["repository"] == "Hello-World"
    assert row["pr_number"] == 55
    assert row["head_sha"] == "c" * 40


def test_6_publication_failure_does_not_complete_commit_reservation(temp_db, monkeypatch):
    """6. Publication failure does not mark commit reservation completed and releases in-progress lock."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_res_006"
    payload = _make_valid_pr_payload(pr_number=66, head_sha="d" * 40)

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report("ana_fail_6"))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", MagicMock(side_effect=Exception("API Error")))
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", MagicMock(side_effect=Exception("API Error")))

    res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res["status"] == "publication_failed"

    commit_key = f"octocat/hello-world:66:{'d' * 40}"
    with store._get_connection() as conn:
        row = conn.execute(
            "SELECT status, analysis_id FROM pr_commit_reservations WHERE commit_key = ?;",
            (commit_key,)
        ).fetchone()

    # The in-progress reservation was released, NOT completed
    assert row is None or row["status"] != "completed"


def test_7_partial_publication_does_not_complete_commit_reservation(temp_db, monkeypatch):
    """7. Partial publication does not mark commit reservation completed."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_res_007"
    payload = _make_valid_pr_payload(pr_number=77, head_sha="e" * 40)

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator._generate_pr_analysis_report", lambda *a, **k: _build_mock_report("ana_partial_7"))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 1}, "commit_status": {}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", MagicMock(side_effect=Exception("Comment Fail")))

    res = orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)
    assert res["status"] == "partial_success"

    commit_key = f"octocat/hello-world:77:{'e' * 40}"
    with store._get_connection() as conn:
        row = conn.execute(
            "SELECT status, analysis_id FROM pr_commit_reservations WHERE commit_key = ?;",
            (commit_key,)
        ).fetchone()

    # Must NOT be completed
    assert row is None or row["status"] != "completed"


def test_8_unexpected_exception_releases_delivery_and_commit_reservation(temp_db, monkeypatch):
    """8. Unhandled exceptions trigger the except block to release both delivery and commit reservations."""
    store = AnalysisStore(db_path=temp_db)
    delivery_id = "del_exc_008"
    head_sha = "f" * 40
    payload = _make_valid_pr_payload(pr_number=88, head_sha=head_sha)

    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", MagicMock(side_effect=RuntimeError("Unhandled crash")))

    with pytest.raises(RuntimeError):
        orchestrate_webhook_event("pull_request", delivery_id, payload, db_path=temp_db)

    # Both delivery and commit reservations must be released
    assert not store.is_delivery_claimed(delivery_id)

    commit_key = f"octocat/hello-world:88:{head_sha}"
    with store._get_connection() as conn:
        row = conn.execute(
            "SELECT status FROM pr_commit_reservations WHERE commit_key = ?;",
            (commit_key,)
        ).fetchone()
    assert row is None
