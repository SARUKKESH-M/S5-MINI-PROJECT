"""
CodeSentinel — Step 6Q Slack Notifications Test Suite

Validates isolated Slack alerting functionality:
1. Configuration handling (disabled when URL is None/empty/whitespace).
2. URL validation (requires https://).
3. mrkdwn escaping (&, <, >).
4. Secret sanitization and masking.
5. Payload construction and bounds (PR title, author, summary, findings, top 5 cap, overflow).
6. Block Kit formatting for BLOCK, REVIEW, and ALLOW decisions.
7. HTTP delivery, timeouts, connection errors, and single-retry transient handling.
8. Webhook orchestrator integration and strict security gate invariance.
"""

import asyncio
import os
import sys
from typing import Any, Dict
import pytest
import httpx

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.notifications.slack import (
    escape_slack_mrkdwn,
    validate_slack_webhook_url,
    build_slack_pr_payload,
    send_slack_pr_alert,
    send_slack_pr_alert_sync,
)
from backend.github.orchestrator import orchestrate_webhook_event
from backend.app.core.config import settings

VALID_HEAD_SHA = "a" * 40
VALID_BASE_SHA = "b" * 40


# ---------------------------------------------------------------------------
# Fixtures & Sample Data Helpers
# ---------------------------------------------------------------------------

def make_sample_report(
    review_status: str = "block",
    total_findings: int = 2,
    critical_count: int = 1,
    high_count: int = 1,
    medium_count: int = 0,
    low_count: int = 0,
    num_findings: int = 2,
) -> Dict[str, Any]:
    """Builds a sample Step 6O Production Report dictionary."""
    findings = []
    for i in range(1, num_findings + 1):
        sev = "critical" if i == 1 else ("high" if i == 2 else "medium")
        findings.append(
            {
                "finding_id": f"finding_{i}",
                "title": f"Vulnerability {i}",
                "severity": sev,
                "category": "Security / Injection",
                "cwe_id": f"CWE-{80 + i}",
                "evidence": [
                    {
                        "document_id": f"app/module_{i}.py",
                        "line_start": 10 * i,
                        "line_end": 10 * i + 2,
                        "signal_type": "TEST_SIGNAL",
                    }
                ],
            }
        )

    return {
        "status": "completed",
        "analysis_id": "repo_ana_pr_test1234",
        "review_status": review_status,
        "repository": {
            "owner": "test-org",
            "repository": "test-repo",
            "branch": "pr/42",
            "path": ".",
        },
        "summary": {
            "total_files": 5,
            "analyzed_files": 3,
            "skipped_files": 2,
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "review_status": review_status,
        },
        "findings": findings,
    }


# ===========================================================================
# 1. CONFIGURATION & URL VALIDATION TESTS
# ===========================================================================

def test_slack_disabled_when_webhook_url_none(monkeypatch):
    """1. Verifies notification is cleanly skipped when webhook URL is None."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", None)
    res = asyncio.run(
        send_slack_pr_alert(
            report=make_sample_report(),
            pr_number=1,
            pr_title="Test PR",
            pr_author="dev",
            repo_full_name="org/repo",
            webhook_url=None,
        )
    )
    assert res["status"] == "skipped"
    assert res["reason"] == "webhook_not_configured"


def test_slack_disabled_when_webhook_url_empty(monkeypatch):
    """2. Verifies notification is skipped when webhook URL is empty string."""
    res = asyncio.run(
        send_slack_pr_alert(
            report=make_sample_report(),
            pr_number=1,
            pr_title="Test PR",
            pr_author="dev",
            repo_full_name="org/repo",
            webhook_url="",
        )
    )
    assert res["status"] == "skipped"
    assert res["reason"] == "webhook_not_configured"


def test_slack_disabled_when_webhook_url_whitespace(monkeypatch):
    """3. Verifies notification is skipped when webhook URL is whitespace only."""
    res = asyncio.run(
        send_slack_pr_alert(
            report=make_sample_report(),
            pr_number=1,
            pr_title="Test PR",
            pr_author="dev",
            repo_full_name="org/repo",
            webhook_url="   \t\n  ",
        )
    )
    assert res["status"] == "skipped"
    assert res["reason"] == "webhook_not_configured"


def test_validate_slack_webhook_url_rejects_insecure():
    """4. Verifies non-HTTPS or malformed URLs are rejected."""
    assert not validate_slack_webhook_url("http://hooks.slack.com/services/T/B/X")
    assert not validate_slack_webhook_url("file:///etc/passwd")
    assert not validate_slack_webhook_url("javascript:alert(1)")
    assert not validate_slack_webhook_url("ftp://server/slack")
    assert not validate_slack_webhook_url("https://hooks.slack.com/with space")
    assert not validate_slack_webhook_url(None)
    assert not validate_slack_webhook_url("")


def test_validate_slack_webhook_url_accepts_valid_https():
    """5. Verifies legitimate HTTPS Slack webhooks and proxies are accepted."""
    assert validate_slack_webhook_url("https://hooks.slack.com/services/T00/B00/X00")
    assert validate_slack_webhook_url("https://slack-proxy.internal.corp/webhook")


# ===========================================================================
# 2. SLACK MRKDWN ESCAPING TESTS
# ===========================================================================

def test_escape_slack_mrkdwn_replaces_amp_lt_gt():
    """6. Verifies &, <, and > are replaced with HTML/mrkdwn entity equivalents."""
    raw = "User <admin> & 'developer' > test"
    escaped = escape_slack_mrkdwn(raw)
    assert escaped == "User &lt;admin&gt; &amp; 'developer' &gt; test"


def test_escape_slack_mrkdwn_handles_none_and_empty():
    """7. Verifies None, empty, or non-string values return empty string safely."""
    assert escape_slack_mrkdwn(None) == ""
    assert escape_slack_mrkdwn("") == ""
    assert escape_slack_mrkdwn(123) == ""


# ===========================================================================
# 3. BLOCK KIT DECISION FORMATTING TESTS
# ===========================================================================

def test_build_payload_block_decision_formatting():
    """8. Verifies BLOCK gate results produce 🔴 icon, #E01E5A color, and danger button."""
    report = make_sample_report(review_status="block")
    payload = build_slack_pr_payload(
        report=report,
        pr_number=42,
        pr_title="Add user query",
        pr_author="alice",
        repo_full_name="acme/api",
        pr_url="https://github.com/acme/api/pull/42",
    )
    assert "🔴" in payload["text"]
    assert "BLOCKED" in payload["text"]
    att = payload["attachments"][0]
    assert att["color"] == "#E01E5A"

    # Check button style
    action_block = [b for b in att["blocks"] if b.get("type") == "actions"]
    assert len(action_block) == 1
    btn = action_block[0]["elements"][0]
    assert btn["style"] == "danger"
    assert btn["url"] == "https://github.com/acme/api/pull/42"


def test_build_payload_review_decision_formatting():
    """9. Verifies REVIEW gate results produce 🟡 icon, #ECB22E color."""
    report = make_sample_report(
        review_status="review",
        critical_count=0,
        high_count=0,
        medium_count=2,
    )
    payload = build_slack_pr_payload(
        report=report,
        pr_number=50,
        pr_title="Refactor auth",
        pr_author="bob",
        repo_full_name="acme/api",
    )
    assert "🟡" in payload["text"]
    assert "REVIEW REQUIRED" in payload["text"]
    att = payload["attachments"][0]
    assert att["color"] == "#ECB22E"


def test_build_payload_allow_decision_formatting():
    """10. Verifies ALLOW gate results produce ✅ icon, #2EB67D color, and primary button."""
    report = make_sample_report(
        review_status="allow",
        total_findings=0,
        critical_count=0,
        high_count=0,
        num_findings=0,
    )
    payload = build_slack_pr_payload(
        report=report,
        pr_number=99,
        pr_title="Clean docs",
        pr_author="carol",
        repo_full_name="acme/docs",
        pr_url="https://github.com/acme/docs/pull/99",
    )
    assert "✅" in payload["text"]
    assert "PASSED" in payload["text"]
    att = payload["attachments"][0]
    assert att["color"] == "#2EB67D"

    action_block = [b for b in att["blocks"] if b.get("type") == "actions"]
    assert len(action_block) == 1
    assert action_block[0]["elements"][0]["style"] == "primary"


# ===========================================================================
# 4. BOUNDARIES, SECRET REDACTION & CONTENT SANITIZATION TESTS
# ===========================================================================

def test_build_payload_top_findings_capped_at_five():
    """11. Verifies reports with >5 findings display only the top 5 plus overflow count."""
    report = make_sample_report(num_findings=9, total_findings=9)
    payload = build_slack_pr_payload(
        report=report,
        pr_number=10,
        pr_title="Big PR",
        pr_author="dave",
        repo_full_name="acme/core",
    )
    att = payload["attachments"][0]
    findings_block = [b for b in att["blocks"] if "Findings Summary:" in b.get("text", {}).get("text", "")]
    assert len(findings_block) == 1
    body = findings_block[0]["text"]["text"]

    # Must contain 5 items and an overflow message
    assert "Vulnerability 1" in body
    assert "Vulnerability 5" in body
    assert "Vulnerability 6" not in body
    assert "... and 4 more findings" in body


def test_build_payload_clean_report_no_findings():
    """12. Verifies clean report displays 'No vulnerabilities detected'."""
    report = make_sample_report(num_findings=0, total_findings=0, review_status="allow")
    payload = build_slack_pr_payload(
        report=report,
        pr_number=10,
        pr_title="Clean update",
        pr_author="dave",
        repo_full_name="acme/core",
    )
    att = payload["attachments"][0]
    findings_block = [b for b in att["blocks"] if "Findings Summary:" in b.get("text", {}).get("text", "")]
    assert "✅ No vulnerabilities detected" in findings_block[0]["text"]["text"]


def test_build_payload_bounds_long_pr_title():
    """13. Verifies PR titles longer than 120 characters are truncated cleanly."""
    long_title = "A" * 200
    payload = build_slack_pr_payload(
        report=make_sample_report(),
        pr_number=1,
        pr_title=long_title,
        pr_author="dev",
        repo_full_name="org/repo",
    )
    header_block = payload["attachments"][0]["blocks"][0]["text"]["text"]
    assert "A" * 125 not in header_block
    assert "..." in header_block


def test_build_payload_bounds_long_author():
    """14. Verifies author names longer than 80 characters are truncated."""
    long_author = "User_" + "X" * 100
    payload = build_slack_pr_payload(
        report=make_sample_report(),
        pr_number=1,
        pr_title="PR",
        pr_author=long_author,
        repo_full_name="org/repo",
    )
    header_block = payload["attachments"][0]["blocks"][0]["text"]["text"]
    assert "X" * 85 not in header_block
    assert "..." in header_block


def test_build_payload_masks_sensitive_tokens():
    """15. Verifies secrets (GitHub PATs, Groq keys) in PR title or findings are redacted."""
    sensitive_title = "Fix for leak ghp_12345678901234567890abcdef12345678 in config"
    report = make_sample_report()
    report["findings"][0]["title"] = "Exposed token gsk_abcdef1234567890123456"

    payload = build_slack_pr_payload(
        report=report,
        pr_number=1,
        pr_title=sensitive_title,
        pr_author="dev",
        repo_full_name="org/repo",
    )
    payload_str = str(payload)
    assert "ghp_12345678901234567890abcdef12345678" not in payload_str
    assert "gsk_abcdef1234567890123456" not in payload_str
    assert "[REDACTED_SECRET]" in payload_str


def test_build_payload_source_code_and_diffs_never_present():
    """16. Verifies raw diff headers and code patches never leak into Slack payload."""
    report = make_sample_report()
    payload = build_slack_pr_payload(
        report=report,
        pr_number=1,
        pr_title="Normal PR",
        pr_author="dev",
        repo_full_name="org/repo",
    )
    payload_str = str(payload)
    assert "@@ -" not in payload_str
    assert "diff --git" not in payload_str


def test_build_payload_optional_pr_url_omitted_when_invalid():
    """17. Verifies insecure or missing PR URLs do not produce action buttons."""
    payload = build_slack_pr_payload(
        report=make_sample_report(),
        pr_number=1,
        pr_title="Normal PR",
        pr_author="dev",
        repo_full_name="org/repo",
        pr_url="http://insecure.url/pull/1",
    )
    action_blocks = [b for b in payload["attachments"][0]["blocks"] if b.get("type") == "actions"]
    assert len(action_blocks) == 0


# ===========================================================================
# 5. HTTP DISPATCH, RETRY & FAILURE HANDLING TESTS (MOCKED)
# ===========================================================================

def test_send_slack_pr_alert_successful_delivery_200():
    """18. Verifies successful HTTP 200 delivery returns delivered status."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(mock_handler)
    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await send_slack_pr_alert(
                report=make_sample_report(),
                pr_number=42,
                pr_title="PR 42",
                pr_author="alice",
                repo_full_name="org/repo",
                webhook_url="https://hooks.slack.com/services/T00/B00/X00",
                client=client,
            )

    res = asyncio.run(_run())
    assert res["status"] == "delivered"
    assert res["status_code"] == 200


def test_send_slack_pr_alert_sync_successful_delivery_200():
    """19. Verifies synchronous delivery helper functions properly on HTTP 200."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(mock_handler)
    with httpx.Client(transport=transport) as client:
        res = send_slack_pr_alert_sync(
            report=make_sample_report(),
            pr_number=42,
            pr_title="PR 42",
            pr_author="alice",
            repo_full_name="org/repo",
            webhook_url="https://hooks.slack.com/services/T00/B00/X00",
            client=client,
        )

    assert res["status"] == "delivered"
    assert res["status_code"] == 200


def test_send_slack_pr_alert_http_400_bad_payload():
    """20. Verifies HTTP 400 bad request returns failed status without raising."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="invalid_payload")

    transport = httpx.MockTransport(mock_handler)
    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await send_slack_pr_alert(
                report=make_sample_report(),
                pr_number=42,
                pr_title="PR 42",
                pr_author="alice",
                repo_full_name="org/repo",
                webhook_url="https://hooks.slack.com/services/T00/B00/X00",
                client=client,
            )

    res = asyncio.run(_run())
    assert res["status"] == "failed"
    assert res["status_code"] == 400
    assert res["reason"] == "http_400"


def test_send_slack_pr_alert_http_429_rate_limit_retry():
    """21. Verifies HTTP 429 performs exactly one retry before succeeding."""
    calls = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "0.01"})
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(mock_handler)
    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await send_slack_pr_alert(
                report=make_sample_report(),
                pr_number=42,
                pr_title="PR 42",
                pr_author="alice",
                repo_full_name="org/repo",
                webhook_url="https://hooks.slack.com/services/T00/B00/X00",
                client=client,
            )

    res = asyncio.run(_run())
    assert calls == 2
    assert res["status"] == "delivered"


def test_send_slack_pr_alert_http_500_server_error_retry():
    """22. Verifies transient HTTP 500 performs one retry and succeeds."""
    calls = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(500, text="server_error")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(mock_handler)
    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await send_slack_pr_alert(
                report=make_sample_report(),
                pr_number=42,
                pr_title="PR 42",
                pr_author="alice",
                repo_full_name="org/repo",
                webhook_url="https://hooks.slack.com/services/T00/B00/X00",
                client=client,
            )

    res = asyncio.run(_run())
    assert calls == 2
    assert res["status"] == "delivered"


def test_send_slack_pr_alert_timeout_handling():
    """23. Verifies httpx.TimeoutException is caught and isolated."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Connection timed out", request=request)

    transport = httpx.MockTransport(mock_handler)
    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await send_slack_pr_alert(
                report=make_sample_report(),
                pr_number=42,
                pr_title="PR 42",
                pr_author="alice",
                repo_full_name="org/repo",
                webhook_url="https://hooks.slack.com/services/T00/B00/X00",
                client=client,
            )

    res = asyncio.run(_run())
    assert res["status"] == "failed"
    assert res["reason"] == "timeout"


def test_send_slack_pr_alert_connection_error_handling():
    """24. Verifies httpx.ConnectError is caught and isolated."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Failed to resolve DNS", request=request)

    transport = httpx.MockTransport(mock_handler)
    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await send_slack_pr_alert(
                report=make_sample_report(),
                pr_number=42,
                pr_title="PR 42",
                pr_author="alice",
                repo_full_name="org/repo",
                webhook_url="https://hooks.slack.com/services/T00/B00/X00",
                client=client,
            )

    res = asyncio.run(_run())
    assert res["status"] == "failed"
    assert res["reason"] == "connection_error"


# ===========================================================================
# 6. ORCHESTRATOR INTEGRATION & GATE INVARIANCE TESTS
# ===========================================================================

def test_orchestrator_integrates_slack_when_configured(monkeypatch):
    """25. Verifies orchestrate_webhook_event invokes Slack when configured."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    def mock_request(self, method, url, **kwargs):
        url_str = str(url)
        if "hooks.slack.com" in url_str:
            return httpx.Response(200, text="ok")
        if "/pulls/77/files" in url_str:
            return httpx.Response(200, json=[])
        if "/pulls/77" in url_str:
            return httpx.Response(200, json={
                "title": "Add feature",
                "state": "open",
                "html_url": "https://github.com/test-owner/test-repo/pull/77",
                "head": {"ref": "feature", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA},
            })
        if "/check-runs" in url_str:
            return httpx.Response(201, json={"id": 100})
        if "/statuses" in url_str:
            return httpx.Response(201, json={"id": 101})
        if "/issues/77/comments" in url_str:
            return httpx.Response(201, json={"id": 102})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    payload = {
        "action": "opened",
        "number": 77,
        "pull_request": {
            "number": 77,
            "title": "Add feature",
            "user": {"login": "octocat"},
            "head": {"sha": VALID_HEAD_SHA},
            "html_url": "https://github.com/test-owner/test-repo/pull/77",
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-owner"},
        },
    }

    res = orchestrate_webhook_event("pull_request", "del_slack_test", payload)
    assert res["status"] == "success"
    assert "slack_notification" in res
    assert res["slack_notification"]["status"] == "delivered"


def test_orchestrator_succeeds_even_if_slack_crashes(monkeypatch):
    """26. Verifies that unexpected Slack errors never crash webhook orchestration."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    def mock_failing_slack(*args, **kwargs):
        raise RuntimeError("Unexpected Slack catastrophic explosion")

    monkeypatch.setattr("backend.github.orchestrator.send_slack_pr_alert_sync", mock_failing_slack)

    def mock_request(self, method, url, **kwargs):
        url_str = str(url)
        if "/pulls/78/files" in url_str:
            return httpx.Response(200, json=[])
        if "/pulls/78" in url_str:
            return httpx.Response(200, json={
                "title": "Crash Test PR",
                "state": "open",
                "html_url": "https://github.com/test-owner/test-repo/pull/78",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA},
            })
        if "/check-runs" in url_str:
            return httpx.Response(201, json={"id": 100})
        if "/statuses" in url_str:
            return httpx.Response(201, json={"id": 101})
        if "/issues/78/comments" in url_str:
            return httpx.Response(201, json={"id": 102})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    payload = {
        "action": "opened",
        "number": 78,
        "pull_request": {
            "number": 78,
            "title": "Crash Test PR",
            "user": {"login": "tester"},
            "head": {"sha": VALID_HEAD_SHA},
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-owner"},
        },
    }

    # Must NOT raise
    res = orchestrate_webhook_event("pull_request", "del_crash_test", payload)
    assert res["status"] == "success"
    assert res["slack_notification"]["status"] == "failed"


def test_security_gate_invariance_on_slack_failure(monkeypatch):
    """27. Verifies that Slack failure CANNOT alter the review_status decision."""
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/1/2")

    def mock_failing_post(self, method, url, **kwargs):
        url_str = str(url)
        if "hooks.slack.com" in url_str:
            return httpx.Response(500, text="Slack is down")
        if "/pulls/79/files" in url_str:
            return httpx.Response(200, json=[])
        if "/pulls/79" in url_str:
            return httpx.Response(200, json={
                "title": "Gate Invariance Test",
                "state": "open",
                "html_url": "https://github.com/test-owner/test-repo/pull/79",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA},
            })
        if "/check-runs" in url_str:
            return httpx.Response(201, json={"id": 100})
        if "/statuses" in url_str:
            return httpx.Response(201, json={"id": 101})
        if "/issues/79/comments" in url_str:
            return httpx.Response(201, json={"id": 102})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_failing_post)

    payload = {
        "action": "opened",
        "number": 79,
        "pull_request": {
            "number": 79,
            "title": "Gate Invariance Test",
            "user": {"login": "tester"},
            "head": {"sha": VALID_HEAD_SHA},
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-owner"},
        },
    }

    res = orchestrate_webhook_event("pull_request", "del_invariance_test", payload)
    # The review_status must remain 'allow' for clean PR regardless of Slack 500
    assert res["status"] == "success"
    assert res["review_status"] == "allow"
    assert res["slack_notification"]["status"] == "failed"
