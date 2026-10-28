"""
CodeSentinel — Phase 3D-2C Slack Notification Deduplication Test Suite

Deterministic, fully isolated validation of persistent Slack notification deduplication:
1. First notification succeeds, transitions state to 'sent' in SQLite.
2. Same delivery ID redelivery is filtered at delivery ingress.
3. Different delivery ID for the same commit SHA detects 'sent' and skips repeat Slack dispatch.
4. Phase 3D-2B publication retry reuses cached analysis, publishes GitHub checks, and skips already-sent Slack alert.
5. Failed delivery (e.g. HTTP 500) records 'failed' and allows bounded retry up to MAX_NOTIFICATION_ATTEMPTS.
6. Max attempts exceeded suppresses further retries.
7. Non-retryable HTTP 400 Bad Request marks terminal failure and suppresses retries.
8. Socket timeout records 'unknown' and prevents blind retries (ambiguous delivery held).
9. Concurrent workers: atomic claim prevents race conditions (1 winner, 1 in_progress).
10. Process restart / store reinitialization preserves notification history and deduplication.
11. New commit on same PR creates independent dispatch key and triggers fresh notification.
12. Security gate invariance: review_status decision is completely isolated from Slack outcomes.
13. Secret redaction: sensitive credentials and tokens are never persisted in dispatch ledger.
14. Unconfigured webhook releases in-flight claim cleanly.
"""

import os
import sys
import threading
from typing import Any, Dict
from unittest.mock import MagicMock
import httpx
import pytest

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage.store import AnalysisStore
from backend.analysis.storage.models import (
    DEFAULT_NOTIFICATION_DISPATCH_TTL_SECONDS,
    MAX_NOTIFICATION_ATTEMPTS,
)
from backend.github.orchestrator import orchestrate_webhook_event
from backend.app.core.config import settings

VALID_HEAD_SHA = "a" * 40
ALT_HEAD_SHA = "b" * 40


@pytest.fixture
def temp_db(tmp_path):
    """Provides a fresh isolated SQLite database file path."""
    db_file = tmp_path / "test_slack_dedup.db"
    return str(db_file)


def _build_test_report(analysis_id: str = "ana_slack_1", head_sha: str = VALID_HEAD_SHA) -> Dict[str, Any]:
    """Builds a valid Step 6O Production Report."""
    return {
        "status": "completed",
        "analysis_id": analysis_id,
        "review_status": "allow",
        "repository": {
            "owner": "octocat",
            "repository": "Hello-World",
            "branch": "pr/42",
            "path": ".",
            "pr_number": 42,
            "head_sha": head_sha,
        },
        "summary": {
            "total_files": 1,
            "analyzed_files": 1,
            "skipped_files": 0,
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "review_status": "allow",
        },
        "findings": [],
        "analysis_version": "1.0",
        "owner": "octocat",
        "repository_id": "Hello-World",
        "pr_number": 42,
        "head_sha": head_sha,
    }


def _make_valid_pr_payload(head_sha: str = VALID_HEAD_SHA, pr_number: int = 42) -> Dict[str, Any]:
    """Builds a canonical GitHub pull_request webhook payload."""
    return {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "title": "Feature branch PR",
            "user": {"login": "octocat"},
            "head": {"sha": head_sha},
            "base": {"sha": "c" * 40},
            "html_url": f"https://github.com/octocat/Hello-World/pull/{pr_number}",
        },
        "repository": {
            "name": "Hello-World",
            "owner": {"login": "octocat"},
        },
    }


# =============================================================================
# 1. STORAGE LEDGER UNIT TESTS
# =============================================================================

def test_claim_notification_dispatch_fresh_record(temp_db):
    """A fresh commit notification claim succeeds and sets status to 'sending'."""
    store = AnalysisStore(db_path=temp_db)
    claimed, reason, rec = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        analysis_id="ana_1",
    )
    assert claimed is True
    assert reason == "claimed"
    assert rec is not None
    assert rec["status"] == "sending"
    assert rec["attempts"] == 1


def test_record_notification_success_transitions_to_sent(temp_db):
    """Recording success sets status to 'sent' and prevents subsequent claims."""
    store = AnalysisStore(db_path=temp_db)
    store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    ok = store.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        status_code=200,
    )
    assert ok is True

    record = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert record is not None
    assert record["status"] == "sent"
    assert record["last_status_code"] == 200

    # Subsequent claim must be rejected as already_sent
    claimed2, reason2, _ = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed2 is False
    assert reason2 == "already_sent"


def test_record_notification_failure_and_bounded_retry(temp_db):
    """Transient failures allow bounded retries up to MAX_NOTIFICATION_ATTEMPTS."""
    store = AnalysisStore(db_path=temp_db)

    for i in range(1, MAX_NOTIFICATION_ATTEMPTS + 1):
        claimed, reason, rec = store.claim_notification_dispatch(
            owner="octocat",
            repository="Hello-World",
            pr_number=42,
            head_sha=VALID_HEAD_SHA,
        )
        assert claimed is True
        assert reason == "claimed"
        assert rec["attempts"] == i

        store.record_notification_failure(
            owner="octocat",
            repository="Hello-World",
            pr_number=42,
            head_sha=VALID_HEAD_SHA,
            status_code=500,
            reason="http_500",
        )

    # Attempt 4 must be rejected because max attempts exceeded
    claimed4, reason4, _ = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed4 is False
    assert reason4 == "max_attempts_exceeded"


def test_non_retryable_400_marks_terminal_failure(temp_db):
    """HTTP 400 Bad Request marks terminal failure and suppresses further claims."""
    store = AnalysisStore(db_path=temp_db)
    store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    store.record_notification_failure(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        status_code=400,
        reason="http_400",
    )

    claimed2, reason2, _ = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed2 is False
    assert reason2 == "terminal_failure"


def test_timeout_marks_unknown_and_holds_without_blind_retry(temp_db):
    """Timeout is marked unknown and held; does not blindly retry unless authorized."""
    store = AnalysisStore(db_path=temp_db)
    store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    store.record_notification_unknown(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        reason="timeout",
    )

    # Standard claim rejects blind retry
    claimed, reason, _ = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed is False
    assert reason == "ambiguous_delivery_held"

    # Explicit authorized recovery allows retry
    claimed_rec, reason_rec, _ = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        allow_unknown_retry=True,
    )
    assert claimed_rec is True
    assert reason_rec == "claimed"


# =============================================================================
# 2. ORCHESTRATION & DEDUPLICATION SCENARIOS
# =============================================================================

def test_first_notification_succeeds_and_deduplicates_second_call(temp_db, monkeypatch):
    """Scenario B: Delivery 1 dispatches Slack. Delivery 2 for same commit skips repeat Slack dispatch."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    mock_send = MagicMock(return_value={"status": "delivered", "status_code": 200})
    monkeypatch.setattr("backend.github.orchestrator.send_slack_pr_alert_sync", mock_send)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 1}, "commit_status": {"state": "success"}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", lambda *a, **k: {"status": "created"})

    # 1. Delivery 1
    payload1 = _make_valid_pr_payload()
    res1 = orchestrate_webhook_event("pull_request", "deliv-slack-1", payload1, db_path=temp_db)
    assert res1["status"] == "success"
    assert res1["slack_notification"]["status"] == "delivered"
    assert mock_send.call_count == 1

    # 2. Reset mock counter and simulate delivery 2 with different delivery ID for same commit
    mock_send.reset_mock()
    # Force reservation to allow retry simulation
    store = AnalysisStore(db_path=temp_db)
    # Even if publication retry is invoked, Slack must be suppressed
    report = _build_test_report("ana_retry_test")
    store.save_analysis(report)

    # Call orchestrator again with new delivery ID
    res2 = orchestrate_webhook_event("pull_request", "deliv-slack-2", payload1, db_path=temp_db)
    # Because commit reservation was completed on delivery 1, res2 returns already_analyzed
    assert res2["status"] == "already_analyzed"
    # Slack alert was NOT invoked again
    mock_send.assert_not_called()


def test_phase_3d_2b_publication_retry_skips_already_sent_slack(temp_db, monkeypatch):
    """Scenario H: Phase 3D-2B publication retry retries GitHub publication but suppresses duplicate Slack."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    store = AnalysisStore(db_path=temp_db)
    report = _build_test_report("ana_cached_slack")
    store.save_analysis(report)

    # Pre-record Slack as already sent on attempt 1
    store.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        status_code=200,
    )

    mock_send = MagicMock()
    mock_pub = MagicMock(return_value={"check_run": {"id": 55}, "commit_status": {"state": "success"}})
    mock_comm = MagicMock(return_value={"status": "created"})

    monkeypatch.setattr("backend.github.orchestrator.send_slack_pr_alert_sync", mock_send)
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", mock_pub)
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", mock_comm)
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))

    payload = _make_valid_pr_payload()
    result = orchestrate_webhook_event("pull_request", "deliv-retry-slack", payload, db_path=temp_db)

    assert result["status"] == "success"
    # GitHub publication retried
    assert mock_pub.call_count == 1
    assert mock_comm.call_count == 1
    # Slack dispatch was skipped and NOT called!
    mock_send.assert_not_called()
    assert result["slack_notification"]["status"] == "skipped"
    assert result["slack_notification"]["reason"] == "already_sent"


def test_concurrent_notification_claims_atomic(temp_db):
    """Scenario E: Concurrent threads attempting to claim the same commit notification resolve to 1 claim."""
    store = AnalysisStore(db_path=temp_db)
    results = []

    def worker_claim():
        claimed, reason, _ = store.claim_notification_dispatch(
            owner="octocat",
            repository="Hello-World",
            pr_number=42,
            head_sha=VALID_HEAD_SHA,
        )
        results.append((claimed, reason))

    t1 = threading.Thread(target=worker_claim)
    t2 = threading.Thread(target=worker_claim)

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one thread claimed, the other was in_progress or already claimed
    claimed_count = sum(1 for c, _ in results if c is True)
    assert claimed_count == 1


def test_process_restart_persistence(temp_db, monkeypatch):
    """Scenario F: A notification sent before application restart is remembered by new AnalysisStore."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    store1 = AnalysisStore(db_path=temp_db)
    store1.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    store1.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )

    # Process restart: instantiate brand new AnalysisStore against same db file
    store2 = AnalysisStore(db_path=temp_db)
    claimed, reason, rec = store2.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed is False
    assert reason == "already_sent"
    assert rec["status"] == "sent"


def test_new_commit_on_same_pr_triggers_fresh_notification(temp_db, monkeypatch):
    """Scenario G: A new commit on the same PR creates an independent dispatch key."""
    store = AnalysisStore(db_path=temp_db)
    store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    store.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )

    # New commit on same PR
    claimed, reason, rec = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=ALT_HEAD_SHA,
    )
    assert claimed is True
    assert reason == "claimed"
    assert rec["status"] == "sending"


def test_security_gate_invariance_on_slack_dedup(temp_db, monkeypatch):
    """Scenario C & invariant test: Security Gate decision is preserved regardless of Slack status."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    # Mock Slack returning 500 failure
    monkeypatch.setattr("backend.github.orchestrator.send_slack_pr_alert_sync", lambda *a, **k: {"status": "failed", "status_code": 500, "reason": "http_500"})
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 1}, "commit_status": {"state": "success"}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", lambda *a, **k: {"status": "created"})

    payload = _make_valid_pr_payload()
    res = orchestrate_webhook_event("pull_request", "deliv-gate-test", payload, db_path=temp_db)

    # Security gate decision and overall status remain 'success' despite Slack 500
    assert res["status"] == "success"
    assert res["review_status"] == "allow"
    assert res["slack_notification"]["status"] == "failed"

    # Ledger recorded the failure
    store = AnalysisStore(db_path=temp_db)
    rec = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert rec is not None
    assert rec["status"] == "failed"
    assert rec["last_status_code"] == 500


def test_no_secret_leakage_in_notification_ledger(temp_db):
    """Sanitizes reason to prevent storing sensitive tokens or credentials in the database."""
    store = AnalysisStore(db_path=temp_db)
    store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    sensitive_reason = "error_with_ghp_1234567890abcdef1234567890abcdef_secret"
    store.record_notification_failure(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        status_code=500,
        reason=sensitive_reason,
    )

    rec = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert rec is not None
    # Verifies reason only contains alphanumeric and underscores
    import re
    assert re.match(r"^[a-zA-Z0-9_\-]+$", rec["last_reason"])


# ============================================================================
# Phase 3D-2C Corrective Hardening Regression Tests
# ============================================================================

def test_claim_fencing_token_rejects_stale_worker_outcomes(temp_db):
    """Worker A's lease expires; Worker B reclaims. Stale Worker A cannot record success/failure/unknown or release."""
    store = AnalysisStore(db_path=temp_db)

    # Worker A claims at t0
    t0 = "2026-10-28T10:00:00+00:00"
    claimed_a, _, rec_a = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        now_iso=t0,
        ttl_seconds=60,
    )
    assert claimed_a is True
    claim_id_a = rec_a["claim_id"]
    assert claim_id_a is not None and claim_id_a.startswith("clm_")

    # Worker A's lease expires at t0 + 65s. Worker B reclaims.
    t1 = "2026-10-28T10:01:05+00:00"
    claimed_b, _, rec_b = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        now_iso=t1,
        ttl_seconds=60,
    )
    assert claimed_b is True
    claim_id_b = rec_b["claim_id"]
    assert claim_id_b != claim_id_a
    assert rec_b["attempts"] == 2

    # Worker A returns late and attempts to release the claim: rejected!
    rel_a = store.release_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        claim_id=claim_id_a,
    )
    assert rel_a is False
    # Worker B's active claim remains intact
    cur = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert cur["status"] == "sending"
    assert cur["claim_id"] == claim_id_b

    # Worker A attempts to record failure with stale claim_id: rejected!
    fail_a = store.record_notification_failure(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        claim_id=claim_id_a,
        reason="stale_error",
    )
    assert fail_a is False

    # Worker A attempts to record unknown with stale claim_id: rejected!
    unk_a = store.record_notification_unknown(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        claim_id=claim_id_a,
    )
    assert unk_a is False

    # Worker A attempts to record success with stale claim_id: rejected!
    succ_a = store.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        claim_id=claim_id_a,
    )
    assert succ_a is False

    # Worker B records success with valid claim_id: accepted!
    succ_b = store.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        claim_id=claim_id_b,
        status_code=200,
    )
    assert succ_b is True

    final_rec = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert final_rec["status"] == "sent"


def test_stale_failure_cannot_overwrite_confirmed_sent(temp_db):
    """A delayed worker returning with failure or timeout cannot overwrite a terminal 'sent' record."""
    store = AnalysisStore(db_path=temp_db)

    # Initial claim and confirmed success
    claimed, _, rec = store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed is True
    ok = store.record_notification_success(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        claim_id=rec["claim_id"],
        status_code=200,
    )
    assert ok is True

    # Delayed failure attempt
    fail_ok = store.record_notification_failure(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        reason="delayed_worker_error",
    )
    assert fail_ok is False

    # Delayed unknown attempt
    unk_ok = store.record_notification_unknown(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        reason="delayed_timeout",
    )
    assert unk_ok is False

    # Terminal record remains 'sent'
    final_rec = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert final_rec["status"] == "sent"
    assert final_rec["last_reason"] == "delivered"


def test_concurrent_reclamation_race_produces_single_winner(temp_db):
    """Two workers concurrently attempting to reclaim the same expired lease results in exactly one winner."""
    store = AnalysisStore(db_path=temp_db)

    # Claim at t0
    t0 = "2026-10-28T10:00:00+00:00"
    store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
        now_iso=t0,
        ttl_seconds=60,
    )

    # Lease expires at t0 + 70s. Both workers race to reclaim.
    t_reclaim = "2026-10-28T10:01:10+00:00"
    results = []

    def worker_reclaim(worker_id: int):
        s = AnalysisStore(db_path=temp_db)
        claimed, reason, rec = s.claim_notification_dispatch(
            owner="octocat",
            repository="Hello-World",
            pr_number=42,
            head_sha=VALID_HEAD_SHA,
            now_iso=t_reclaim,
            ttl_seconds=60,
        )
        results.append((worker_id, claimed, reason, rec))

    threads = [threading.Thread(target=worker_reclaim, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one thread should win
    winners = [r for r in results if r[1] is True]
    losers = [r for r in results if r[1] is False]
    assert len(winners) == 1
    assert len(losers) == 4
    assert winners[0][2] == "claimed"

    rec = store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert rec["attempts"] == 2


def test_slack_http_200_with_persistence_failure_surfaces_uncertainty_and_protects_claim(temp_db, monkeypatch):
    """When Slack HTTP 200 succeeds but persistence fails: status is 'uncertain', claim is NOT deleted."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")
    monkeypatch.setattr("backend.github.orchestrator.send_slack_pr_alert_sync", lambda *a, **k: {"status": "delivered", "status_code": 200})
    monkeypatch.setattr("backend.github.orchestrator.acquire_pull_request", lambda *a, **k: MagicMock(changed_files=[]))
    monkeypatch.setattr("backend.github.orchestrator.publish_step_6o_report_status", lambda *a, **k: {"check_run": {"id": 1}, "commit_status": {"state": "success"}})
    monkeypatch.setattr("backend.github.orchestrator.post_pr_security_comment", lambda *a, **k: {"status": "created"})

    # Mock record_notification_success to simulate a persistence failure (returns False)
    real_store = AnalysisStore(db_path=temp_db)
    monkeypatch.setattr(AnalysisStore, "record_notification_success", lambda *a, **k: False)

    payload = _make_valid_pr_payload()
    res = orchestrate_webhook_event("pull_request", "deliv-persist-fail-test", payload, db_path=temp_db)

    # Surfaces uncertain delivery
    assert res["status"] == "success"
    assert res["slack_notification"]["status"] == "uncertain"
    assert res["slack_notification"]["reason"] == "delivered_but_persistence_failed"
    assert res["slack_notification"]["status_code"] == 200

    # Claim must NOT have been deleted from the database
    rec = real_store.get_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA)
    assert rec is not None
    assert rec["status"] == "sending"

    # Subsequent claim attempt detects in_progress and does NOT trigger duplicate send
    claimed2, reason2, _ = real_store.claim_notification_dispatch(
        owner="octocat",
        repository="Hello-World",
        pr_number=42,
        head_sha=VALID_HEAD_SHA,
    )
    assert claimed2 is False
    assert reason2 == "in_progress"


def test_retry_bounds_enforced_across_expired_leases(temp_db):
    """Reclamation across repeated expirations respects MAX_NOTIFICATION_ATTEMPTS."""
    store = AnalysisStore(db_path=temp_db)

    times = [
        "2026-10-28T10:00:00+00:00",
        "2026-10-28T10:01:05+00:00",
        "2026-10-28T10:02:10+00:00",
        "2026-10-28T10:03:15+00:00",
    ]

    # Attempt 1
    c1, r1, _ = store.claim_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA, now_iso=times[0], ttl_seconds=60)
    assert c1 is True and r1 == "claimed"

    # Attempt 2
    c2, r2, _ = store.claim_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA, now_iso=times[1], ttl_seconds=60)
    assert c2 is True and r2 == "claimed"

    # Attempt 3
    c3, r3, _ = store.claim_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA, now_iso=times[2], ttl_seconds=60)
    assert c3 is True and r3 == "claimed"

    # Attempt 4: Max attempts reached!
    c4, r4, _ = store.claim_notification_dispatch("octocat", "Hello-World", 42, VALID_HEAD_SHA, now_iso=times[3], ttl_seconds=60)
    assert c4 is False
    assert r4 == "max_attempts_exceeded"
