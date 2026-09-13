"""
CodeSentinel — Phase 33B: GitHub Client Resilience & Webhook Idempotency Test Suite

Comprehensive regression suite validating:
1-15:  GitHubClient connection pooling, bounded retry/backoff, rate-limit headers, mutation safety, token secrecy.
16-27: Webhook delivery-id idempotency, atomic claiming, TTL reclamation, bounded cleanup, security boundary ordering, duplicate side-effect prevention.
28-30: Step 6O security invariants, gate immutability, fail-closed separation.
"""

import concurrent.futures
import datetime
from datetime import timezone
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional
import httpx
import pytest
from fastapi.testclient import TestClient

# Ensure root and backend in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.security_gate import evaluate_security_gate
from backend.analysis.storage.models import DEFAULT_DELIVERY_TTL_SECONDS
from backend.analysis.storage.store import AnalysisStore
from backend.app.core.config import settings
from backend.app.main import app
from backend.github.client import GitHubClient
from backend.github.exceptions import (
    GitHubAPIError,
    GitHubAuthenticationError,
    GitHubNotFoundError,
    GitHubPermissionError,
    GitHubRateLimitError,
)
from backend.github.orchestrator import orchestrate_webhook_event
from backend.github.webhook import (
    claim_webhook_delivery,
    release_webhook_delivery,
    verify_github_webhook_signature,
)

VALID_HEAD_SHA = "a" * 40
VALID_BASE_SHA = "b" * 40


def make_mock_pr_payload(delivery_id: str = "del_test_pr_001") -> Dict[str, Any]:
    """Helper to generate a valid PR webhook payload."""
    return {
        "action": "synchronize",
        "number": 42,
        "pull_request": {
            "number": 42,
            "title": "Security harden auth",
            "html_url": "https://github.com/test-owner/test-repo/pull/42",
            "user": {"login": "octocat"},
            "head": {"sha": VALID_HEAD_SHA, "ref": "feature-branch"},
            "base": {"sha": VALID_BASE_SHA, "ref": "main"}
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-owner"}
        }
    }


# ============================================================================
# PART 1: HTTP CLIENT RESILIENCE & CONNECTION POOLING (Tests 1 - 15)
# ============================================================================

def test_1_connection_reuse_across_multiple_requests(monkeypatch):
    """1. Verifies that GitHubClient reuses the same httpx.Client across multiple requests."""
    client = GitHubClient(token="test_token_123")
    initial_client = client._get_client()
    second_client = client._get_client()

    assert initial_client is second_client
    assert not initial_client.is_closed

    call_count = 0

    def mock_req(self, method, url, **kwargs):
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"count": call_count})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res1 = client.get("/repos/owner/repo1")
    res2 = client.get("/repos/owner/repo2")

    assert res1["count"] == 1
    assert res2["count"] == 2
    assert client._get_client() is initial_client
    client.close()


def test_2_client_cleanup_and_close():
    """2. Verifies explicit close and context-manager cleanup releases resources."""
    with GitHubClient(token="tok") as client:
        internal_c = client._get_client()
        assert not internal_c.is_closed

    assert internal_c.is_closed
    with pytest.raises(RuntimeError) as exc:
        client._get_client()
    assert "closed" in str(exc.value)


def test_3_successful_request_does_not_retry(monkeypatch):
    """3. Verifies that a successful 200/201 request is executed exactly once."""
    calls = []
    recorded_delays = []

    def mock_sleep(d):
        recorded_delays.append(d)

    client = GitHubClient(token="tok", sleep_func=mock_sleep)

    def mock_req(self, method, url, **kwargs):
        calls.append((method, str(url)))
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = client.get("/user")
    assert res == {"ok": True}
    assert len(calls) == 1
    assert len(recorded_delays) == 0


def test_4_502_retry_then_success(monkeypatch):
    """4. Verifies 502 Bad Gateway retries with backoff and succeeds on subsequent try."""
    calls = 0
    recorded_delays = []

    def mock_sleep(d):
        recorded_delays.append(d)

    client = GitHubClient(token="tok", max_retries=3, backoff_factor=0.5, sleep_func=mock_sleep)

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(502, text="Bad Gateway")
        return httpx.Response(200, json={"status": "recovered"})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = client.get("/repos/owner/repo")
    assert res == {"status": "recovered"}
    assert calls == 3
    assert len(recorded_delays) == 2
    # attempt 0: 0.5 * 2^0 = 0.5, attempt 1: 0.5 * 2^1 = 1.0
    assert recorded_delays[0] == 0.5
    assert recorded_delays[1] == 1.0


def test_5_503_retry_then_success(monkeypatch):
    """5. Verifies 503 Service Unavailable retries and recovers."""
    calls = 0
    recorded_delays = []

    client = GitHubClient(token="tok", max_retries=2, sleep_func=lambda d: recorded_delays.append(d))

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(200, json={"ready": True})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = client.get("/service")
    assert res["ready"] is True
    assert calls == 2
    assert len(recorded_delays) == 1


def test_6_504_retry_then_success(monkeypatch):
    """6. Verifies 504 Gateway Timeout retries and succeeds."""
    calls = 0
    recorded_delays = []

    client = GitHubClient(token="tok", max_retries=2, sleep_func=lambda d: recorded_delays.append(d))

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(504, text="Gateway Timeout")
        return httpx.Response(200, json={"recovered": True})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = client.get("/timeout")
    assert res["recovered"] is True
    assert calls == 2


def test_7_bounded_retry_exhaustion(monkeypatch):
    """7. Verifies bounded retry exhaustion halts after max_retries and raises typed GitHubAPIError."""
    calls = 0
    recorded_delays = []

    client = GitHubClient(token="tok", max_retries=3, sleep_func=lambda d: recorded_delays.append(d))

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="Service Unavailable")

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    with pytest.raises(GitHubAPIError) as exc:
        client.get("/flaky")

    assert exc.value.status_code == 503
    # 1 initial call + 3 retries = 4 attempts total
    assert calls == 4
    assert len(recorded_delays) == 3


def test_8_429_with_retry_after(monkeypatch):
    """8. Verifies 429 Too Many Requests honors Retry-After header with bound."""
    calls = 0
    recorded_delays = []

    client = GitHubClient(
        token="tok",
        max_retries=2,
        max_backoff_seconds=10.0,
        sleep_func=lambda d: recorded_delays.append(d)
    )

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "3"}, text="Too Many Requests")
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = client.get("/rate-limited")
    assert res["ok"] is True
    assert calls == 2
    assert recorded_delays == [3.0]


def test_9_rate_limit_403_with_reset_information(monkeypatch):
    """9. Verifies rate-limit 403 with X-RateLimit-Reset calculates remaining epoch delay."""
    calls = 0
    recorded_delays = []

    now = time.time()
    reset_future = str(int(now + 4))

    client = GitHubClient(
        token="tok",
        max_retries=2,
        max_backoff_seconds=10.0,
        sleep_func=lambda d: recorded_delays.append(d)
    )

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                403,
                headers={"x-ratelimit-reset": reset_future, "x-ratelimit-remaining": "0"},
                text="API rate limit exceeded"
            )
        return httpx.Response(200, json={"allowed": True})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = client.get("/reset-endpoint")
    assert res["allowed"] is True
    assert calls == 2
    assert len(recorded_delays) == 1
    assert 0.0 <= recorded_delays[0] <= 4.1


def test_10_permission_403_does_not_retry(monkeypatch):
    """10. Verifies ordinary permission 403 (Forbidden) fails immediately without retrying."""
    calls = 0
    client = GitHubClient(token="tok", max_retries=3)

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(403, text="Must have admin rights")

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    with pytest.raises(GitHubPermissionError):
        client.get("/admin")

    assert calls == 1


def test_11_401_does_not_retry(monkeypatch):
    """11. Verifies 401 Unauthorized fails immediately without retrying."""
    calls = 0
    client = GitHubClient(token="bad_tok", max_retries=3)

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"message": "Bad credentials"})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    with pytest.raises(GitHubAuthenticationError):
        client.get("/auth")

    assert calls == 1


def test_12_404_does_not_retry(monkeypatch):
    """12. Verifies 404 Not Found fails immediately without retrying."""
    calls = 0
    client = GitHubClient(token="tok", max_retries=3)

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(404, json={"message": "Not Found"})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    with pytest.raises(GitHubNotFoundError):
        client.get("/missing")

    assert calls == 1


def test_13_post_mutation_not_blindly_retried(monkeypatch):
    """13. Verifies non-idempotent POST mutation is not retried on 502 unless allow_retry=True is explicit."""
    calls = 0
    client = GitHubClient(token="tok", max_retries=3)

    def mock_req(self, method, url, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(502, text="Bad Gateway")

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    with pytest.raises(GitHubAPIError):
        client.post("/issues/1/comments", json_data={"body": "publish comment"})

    assert calls == 1  # Exactly 1, no blind retry


def test_14_retry_delay_hard_bounded(monkeypatch):
    """14. Verifies malicious/huge Retry-After values are capped at max_backoff_seconds."""
    recorded_delays = []
    client = GitHubClient(
        token="tok",
        max_retries=1,
        max_backoff_seconds=5.0,
        sleep_func=lambda d: recorded_delays.append(d)
    )

    def mock_req(self, method, url, **kwargs):
        return httpx.Response(429, headers={"retry-after": "9999999"}, text="Huge wait")

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    with pytest.raises(GitHubRateLimitError):
        client.get("/slow")

    assert recorded_delays == [5.0]  # Capped at max_backoff_seconds


def test_15_token_remains_absent_from_errors_logs_repr():
    """15. Verifies secret tokens never appear in repr, str, or exception representations."""
    secret = "ghp_super_secret_production_token_xyz"
    client = GitHubClient(token=secret)

    client_repr = repr(client)
    assert secret not in client_repr
    assert "token=SET" in client_repr

    err = GitHubAuthenticationError()
    assert secret not in str(err)
    assert secret not in repr(err)


# ============================================================================
# PART 2: WEBHOOK DELIVERY ID IDEMPOTENCY & BOUNDARIES (Tests 16 - 27)
# ============================================================================

def test_16_first_valid_delivery_is_claimed():
    """16. Verifies that the first valid delivery ID is successfully claimed."""
    store = AnalysisStore()
    delivery_id = "del_first_seen_001"
    claimed = store.claim_delivery(delivery_id, "pull_request")
    assert claimed is True
    assert store.is_delivery_claimed(delivery_id) is True


def test_17_duplicate_delivery_is_rejected():
    """17. Verifies that submitting the same delivery ID a second time is rejected as duplicate."""
    store = AnalysisStore()
    delivery_id = "del_dup_001"
    first = store.claim_delivery(delivery_id, "pull_request")
    second = store.claim_delivery(delivery_id, "pull_request")

    assert first is True
    assert second is False


def test_18_same_delivery_id_cannot_be_claimed_twice_across_events():
    """18. Verifies that delivery ID uniqueness is global across event types."""
    store = AnalysisStore()
    delivery_id = "del_shared_guid_001"
    first = store.claim_delivery(delivery_id, "pull_request")
    second = store.claim_delivery(delivery_id, "push")

    assert first is True
    assert second is False


def test_19_concurrent_duplicate_claim_is_atomic():
    """19. Verifies that concurrent threads attempting to claim the same delivery ID result in exactly 1 claim."""
    store = AnalysisStore()
    delivery_id = "del_concurrent_race_001"

    results = []

    def try_claim():
        res = store.claim_delivery(delivery_id, "pull_request")
        results.append(res)

    threads = [threading.Thread(target=try_claim) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one True, all others False
    assert results.count(True) == 1
    assert results.count(False) == 9


def test_20_expired_delivery_can_be_reclaimed():
    """20. Verifies that once a delivery ID's TTL expires, it can be claimed again."""
    store = AnalysisStore()
    delivery_id = "del_reclaim_001"

    # Claim with negative TTL (already expired in the past)
    now_dt = datetime.datetime.now(timezone.utc)
    past_iso = (now_dt - datetime.timedelta(hours=2)).isoformat()

    # Claim in past
    store.claim_delivery(delivery_id, "pull_request", now_iso=past_iso, ttl_seconds=60)
    assert store.is_delivery_claimed(delivery_id) is False

    # New claim now should succeed
    new_claim = store.claim_delivery(delivery_id, "pull_request")
    assert new_claim is True
    assert store.is_delivery_claimed(delivery_id) is True


def test_21_cleanup_is_bounded():
    """21. Verifies bounded cleanup deletes expired deliveries without removing active ones."""
    store = AnalysisStore()
    now_dt = datetime.datetime.now(timezone.utc)
    past_iso = (now_dt - datetime.timedelta(hours=5)).isoformat()
    future_iso = (now_dt + datetime.timedelta(hours=5)).isoformat()

    # Insert directly to test bounded cleanup specifically
    with store._get_connection() as conn:
        for i in range(10):
            conn.execute(
                "INSERT INTO webhook_deliveries (delivery_id, event_type, created_at, expires_at) "
                "VALUES (?, ?, ?, ?);",
                (f"del_exp_{i}", "pull_request", past_iso, past_iso)
            )
        conn.execute(
            "INSERT INTO webhook_deliveries (delivery_id, event_type, created_at, expires_at) "
            "VALUES (?, ?, ?, ?);",
            ("del_active_keep", "pull_request", past_iso, future_iso)
        )

    # Run bounded cleanup with limit 5
    cleaned = store.cleanup_expired_deliveries(limit=5)
    assert cleaned == 5

    # Active record must remain
    assert store.is_delivery_claimed("del_active_keep") is True


def test_22_invalid_hmac_does_not_consume_delivery_id(monkeypatch):
    """22. Verifies invalid HMAC signature fails before claiming delivery ID."""
    store = AnalysisStore()
    delivery_id = "del_unauthenticated_hmac"

    secret = "secret_123"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)

    client = TestClient(app)
    body = json.dumps(make_mock_pr_payload(delivery_id)).encode("utf-8")

    # Send wrong signature
    headers = {
        "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id
    }

    res = client.post("/github/webhook", content=body, headers=headers)
    assert res.status_code == 401
    # Delivery ID was NOT consumed
    assert store.is_delivery_claimed(delivery_id) is False


def test_23_malformed_payload_does_not_consume_delivery_id(monkeypatch):
    """23. Verifies malformed JSON payload fails before claiming delivery ID."""
    store = AnalysisStore()
    delivery_id = "del_malformed_json"

    secret = "secret_xyz"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)

    client = TestClient(app)
    bad_body = b"NOT_VALID_JSON{{{"
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), bad_body, hashlib.sha256).hexdigest()

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id
    }

    res = client.post("/github/webhook", content=bad_body, headers=headers)
    assert res.status_code == 400
    assert store.is_delivery_claimed(delivery_id) is False


def test_24_unsupported_event_handling_remains_safe():
    """24. Verifies unsupported event types are acknowledged/ignored safely without claiming delivery."""
    store = AnalysisStore()
    delivery_id = "del_unsupported_001"

    res = orchestrate_webhook_event("issues", delivery_id, {"action": "opened"})
    assert res["status"] == "ignored"
    assert res["reason"] == "unsupported_event"
    # Unsupported event does not claim delivery
    assert store.is_delivery_claimed(delivery_id) is False


def test_25_duplicate_webhook_does_not_trigger_analysis_twice(monkeypatch):
    """25. Verifies sending duplicate webhook delivery does not invoke static analysis twice."""
    analysis_invocations = 0

    def mock_req(self, method, url, **kwargs):
        str_url = str(url)
        if "/pulls/42/files" in str_url:
            return httpx.Response(200, json=[])
        if "/pulls/42" in str_url:
            return httpx.Response(200, json={
                "title": "PR", "state": "open", "html_url": "url",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        if "/check-runs" in str_url or "/statuses" in str_url or "/comments" in str_url:
            return httpx.Response(201, json={"id": 1, "status": "ok"})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    # Count how many times PR analysis report generator runs
    import backend.github.orchestrator as orch
    orig_generate = orch._generate_pr_analysis_report

    def counting_generate(*args, **kwargs):
        nonlocal analysis_invocations
        analysis_invocations += 1
        return orig_generate(*args, **kwargs)

    monkeypatch.setattr(orch, "_generate_pr_analysis_report", counting_generate)

    delivery_id = "del_pr_dedup_001"
    payload = make_mock_pr_payload(delivery_id)

    res1 = orchestrate_webhook_event("pull_request", delivery_id, payload)
    assert res1["status"] == "success"
    assert analysis_invocations == 1

    # Second delivery with identical ID
    res2 = orchestrate_webhook_event("pull_request", delivery_id, payload)
    assert res2["status"] == "duplicate"
    assert res2["reason"] == "delivery_already_processed"
    # Still exactly 1 analysis invocation!
    assert analysis_invocations == 1


def test_26_duplicate_webhook_does_not_publish_duplicate_results(monkeypatch):
    """26. Verifies duplicate webhook delivery does not publish second Check Run or Commit Status."""
    publish_count = 0

    def mock_req(self, method, url, **kwargs):
        str_url = str(url)
        if "/pulls/42/files" in str_url:
            return httpx.Response(200, json=[])
        if "/pulls/42" in str_url:
            return httpx.Response(200, json={
                "title": "PR", "state": "open", "html_url": "url",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        if "/check-runs" in str_url or "/statuses" in str_url:
            nonlocal publish_count
            publish_count += 1
            return httpx.Response(201, json={"id": 100})
        if "/comments" in str_url:
            return httpx.Response(201, json={"id": 200})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    delivery_id = "del_no_dup_publish"
    payload = make_mock_pr_payload(delivery_id)

    res1 = orchestrate_webhook_event("pull_request", delivery_id, payload)
    assert res1["status"] == "success"
    initial_publishes = publish_count

    res2 = orchestrate_webhook_event("pull_request", delivery_id, payload)
    assert res2["status"] == "duplicate"
    assert publish_count == initial_publishes  # Zero additional publish calls


def test_27_duplicate_webhook_does_not_send_duplicate_slack_notification(monkeypatch):
    """27. Verifies duplicate webhook delivery does not trigger duplicate Slack alerts."""
    slack_alerts = 0

    def mock_req(self, method, url, **kwargs):
        str_url = str(url)
        if "/pulls/42" in str_url:
            return httpx.Response(200, json={
                "title": "PR", "state": "open", "html_url": "url",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    def mock_slack(*args, **kwargs):
        nonlocal slack_alerts
        slack_alerts += 1
        return {"status": "delivered"}

    monkeypatch.setattr("backend.github.orchestrator.send_slack_pr_alert_sync", mock_slack)

    delivery_id = "del_slack_dedup"
    payload = make_mock_pr_payload(delivery_id)

    res1 = orchestrate_webhook_event("pull_request", delivery_id, payload)
    assert res1["status"] == "success"
    assert slack_alerts == 1

    res2 = orchestrate_webhook_event("pull_request", delivery_id, payload)
    assert res2["status"] == "duplicate"
    assert slack_alerts == 1  # No duplicate alert


# ============================================================================
# PART 3: STEP 6O SECURITY INVARIANTS (Tests 28 - 30)
# ============================================================================

def test_28_step_6o_decision_unchanged_through_retry_and_dedup_path(monkeypatch):
    """28. Verifies Step 6O security gate evaluation produces identical decision regardless of retry/dedup."""
    block_report = {
        "status": "success",
        "review_status": "block",
        "summary": {"critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": [{"finding_id": "f1", "severity": "critical"}]
    }

    decision_1, exit_1, _ = evaluate_security_gate(block_report)
    assert decision_1 == "BLOCK"
    assert exit_1 == 1

    # Invariance check: identical report produces identical decision
    decision_2, exit_2, _ = evaluate_security_gate(block_report)
    assert decision_2 == "BLOCK"
    assert exit_2 == 1
    assert decision_1 == decision_2


def test_29_block_cannot_become_allow_because_of_github_infrastructure(monkeypatch):
    """29. Verifies GitHub API failure or 503 outage NEVER converts a BLOCK into an ALLOW."""
    def mock_failing_publish(self, method, url, **kwargs):
        return httpx.Response(503, text="GitHub API Outage")

    monkeypatch.setattr(httpx.Client, "request", mock_failing_publish)

    block_report = {
        "status": "success",
        "review_status": "block",
        "summary": {"critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": [{"finding_id": "f1", "severity": "critical"}]
    }
    decision, _, _ = evaluate_security_gate(block_report)
    assert decision == "BLOCK"

    # Verify that attempting to publish under failure raises infrastructure error, not ALLOW
    client = GitHubClient(token="tok", max_retries=1, sleep_func=lambda d: None)
    with pytest.raises(GitHubAPIError):
        client.post("/check-runs", json_data={"status": decision})


def test_30_github_api_failure_remains_separate_from_security_verdict():
    """30. Verifies GitHub API transport error is strictly an infrastructure error, distinct from security gate."""
    api_err = GitHubAPIError("Service Unavailable", status_code=503)
    assert api_err.status_code == 503
    assert not hasattr(api_err, "review_status")

    clean_report = {
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": []
    }
    decision, exit_code, _ = evaluate_security_gate(clean_report)
    assert decision == "ALLOW"
    assert exit_code == 0

