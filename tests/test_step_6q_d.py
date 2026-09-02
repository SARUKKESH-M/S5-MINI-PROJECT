"""
CodeSentinel — Step 6Q-D Unit & Integration Test Suite

Tests PR Security Commenter formatting & posting, duplicate comment updating using COMMENT_MARKER,
End-to-End Webhook Orchestration for pull_request & push events, FastAPI endpoint integration,
Error handling, Security controls, and HMAC signature verification.
"""

import sys
import os
import hmac
import hashlib
import json
import httpx
import pytest
from fastapi.testclient import TestClient

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from backend.github.client import GitHubClient
    from backend.github.commenter import (
        COMMENT_MARKER,
        format_pr_security_comment,
        post_pr_security_comment
    )
    from backend.github.orchestrator import orchestrate_webhook_event
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
    from backend.app.main import app
except ImportError:
    from github.client import GitHubClient
    from github.commenter import (
        COMMENT_MARKER,
        format_pr_security_comment,
        post_pr_security_comment
    )
    from github.orchestrator import orchestrate_webhook_event
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
    from app.main import app


VALID_HEAD_SHA = "8f2a1c9000000000000000000000000000000000"
VALID_BASE_SHA = "1a2b3c4000000000000000000000000000000000"


def mock_step_6o_report(review_status="block"):
    return {
        "status": "success",
        "review_status": review_status,
        "analysis_id": "repo_ana_demo_flask",
        "repository": {
            "owner": "pallets",
            "repository": "flask",
            "branch": "main",
            "path": "."
        },
        "summary": {
            "total_files": 184,
            "analyzed_files": 176,
            "skipped_files": 8,
            "total_findings": 2,
            "critical_count": 1 if review_status == "block" else 0,
            "high_count": 1 if review_status == "block" else 0,
            "medium_count": 1 if review_status == "review" else 0,
            "low_count": 0,
            "info_count": 0
        },
        "findings": [
            {
                "finding_id": "finding_1",
                "title": "Hardcoded Secret Literal",
                "description": "Hardcoded secret string assigned to JWT_SECRET",
                "severity": "critical" if review_status == "block" else "medium",
                "confidence": "high",
                "category": "security",
                "evidence": [
                    {
                        "document_id": "src/flask/config.py",
                        "line_start": 42,
                        "line_end": 42,
                        "signal_type": "AST_SECRET_LITERAL",
                        "signal_name": "jwt_secret_assignment"
                    }
                ]
            }
        ],
        "analysis_version": "1.0"
    }


def mock_pr_payload():
    return {
        "action": "opened",
        "number": 142,
        "pull_request": {
            "number": 142,
            "title": "Fix auth bypass",
            "state": "open",
            "html_url": "https://github.com/pallets/flask/pull/142",
            "head": {"ref": "fix/auth", "sha": VALID_HEAD_SHA},
            "base": {"ref": "main", "sha": VALID_BASE_SHA}
        },
        "repository": {
            "name": "flask",
            "owner": {"login": "pallets"}
        }
    }


def mock_push_payload():
    return {
        "ref": "refs/heads/main",
        "after": VALID_HEAD_SHA,
        "repository": {
            "name": "flask",
            "owner": {"login": "pallets"}
        }
    }


# =====================================================================
# 1. PR COMMENT FORMATTER TESTS
# =====================================================================

def test_comment_formatter_allow():
    """Verifies comment formatting for 'allow' verdict."""
    rep = mock_step_6o_report("allow")
    comment = format_pr_security_comment(rep, owner="pallets", repository="flask", pr_number=142)
    assert COMMENT_MARKER in comment
    assert "PASSED / Safe to Merge" in comment
    assert "CodeSentinel Security Analysis" in comment


def test_comment_formatter_block():
    """Verifies comment formatting for 'block' verdict."""
    rep = mock_step_6o_report("block")
    comment = format_pr_security_comment(rep, owner="pallets", repository="flask", pr_number=142)
    assert COMMENT_MARKER in comment
    assert "BLOCKED / Do Not Merge" in comment
    assert "Critical Severity" in comment


def test_comment_formatter_review():
    """Verifies comment formatting for 'review' verdict."""
    rep = mock_step_6o_report("review")
    comment = format_pr_security_comment(rep, owner="pallets", repository="flask", pr_number=142)
    assert COMMENT_MARKER in comment
    assert "REVIEW NEEDED" in comment


def test_comment_contains_stable_marker():
    """Verifies stable comment marker is present."""
    rep = mock_step_6o_report("allow")
    comment = format_pr_security_comment(rep)
    assert comment.startswith(COMMENT_MARKER)


def test_comment_does_not_contain_token_or_secrets():
    """Verifies secrets or token values are omitted from comment body."""
    rep = mock_step_6o_report("block")
    comment = format_pr_security_comment(rep)
    assert "secret_token" not in comment
    assert "Bearer" not in comment
    assert "Authorization" not in comment


def test_comment_does_not_contain_raw_source_code():
    """Verifies raw source code is omitted from comment body."""
    rep = mock_step_6o_report("block")
    comment = format_pr_security_comment(rep)
    assert "def internal_secret_function():" not in comment


# =====================================================================
# 2. COMMENT POST & UPDATE TESTS (MOCKED)
# =====================================================================

def test_post_pr_security_comment_create_new(monkeypatch):
    """Verifies creating a new comment when no existing CodeSentinel comment is found."""
    sent_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_requests.append({"method": method, "url": url, "json": json})
        if method == "GET":
            # Return list of unrelated comments
            return httpx.Response(200, json=[{"id": 11, "body": "Looks good to me!"}])
        # Return new comment object
        return httpx.Response(201, json={"id": 99, "body": json.get("body") if json else ""})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    rep = mock_step_6o_report("allow")
    res = post_pr_security_comment("pallets", "flask", 142, rep)
    assert res["id"] == 99
    assert len(sent_requests) == 2
    assert sent_requests[0]["method"] == "GET"
    assert sent_requests[1]["method"] == "POST"
    assert f"/issues/142/comments" in sent_requests[1]["url"]


def test_post_pr_security_comment_update_existing(monkeypatch):
    """Verifies updating existing comment when COMMENT_MARKER is present."""
    sent_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_requests.append({"method": method, "url": url, "json": json})
        if method == "GET":
            # Return list containing an existing CodeSentinel comment
            return httpx.Response(200, json=[
                {"id": 55, "body": f"Old comment\n{COMMENT_MARKER}"}
            ])
        # Return updated comment object
        return httpx.Response(200, json={"id": 55, "body": json.get("body") if json else ""})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    rep = mock_step_6o_report("block")
    res = post_pr_security_comment("pallets", "flask", 142, rep)
    assert res["id"] == 55
    assert len(sent_requests) == 2
    assert sent_requests[0]["method"] == "GET"
    assert sent_requests[1]["method"] == "PATCH"
    assert "/issues/comments/55" in sent_requests[1]["url"]


def test_post_pr_security_comment_do_not_update_unrelated(monkeypatch):
    """Verifies unrelated comments are not updated."""
    sent_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_requests.append({"method": method, "url": url, "json": json})
        if method == "GET":
            return httpx.Response(200, json=[{"id": 77, "body": "Unrelated code review comment"}])
        return httpx.Response(201, json={"id": 88, "body": "new"})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    rep = mock_step_6o_report("allow")
    post_pr_security_comment("pallets", "flask", 142, rep)
    assert sent_requests[1]["method"] == "POST"
    assert "/issues/142/comments" in sent_requests[1]["url"]


# =====================================================================
# 3. COMMENTER VALIDATION TESTS
# =====================================================================

def test_commenter_invalid_owner_rejected():
    """Verifies invalid owner raises ValueError."""
    rep = mock_step_6o_report("allow")
    with pytest.raises(ValueError):
        post_pr_security_comment("../pallets", "flask", 142, rep)


def test_commenter_invalid_repository_rejected():
    """Verifies invalid repository raises ValueError."""
    rep = mock_step_6o_report("allow")
    with pytest.raises(ValueError):
        post_pr_security_comment("pallets", "flask; rm -rf /", 142, rep)


def test_commenter_invalid_pr_number_rejected():
    """Verifies invalid PR number raises ValueError."""
    rep = mock_step_6o_report("allow")
    with pytest.raises(ValueError):
        post_pr_security_comment("pallets", "flask", -142, rep)


# =====================================================================
# 4. WEBHOOK ORCHESTRATION TESTS (MOCKED)
# =====================================================================

def test_orchestration_pull_request_event(monkeypatch):
    """Verifies end-to-end webhook orchestration for pull_request event."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if "/pulls/142/files" in url:
            return httpx.Response(200, json=[{"filename": "src/app.py", "status": "modified", "additions": 1, "deletions": 1, "changes": 2}])
        if "/pulls/142" in url:
            return httpx.Response(200, json={
                "title": "Fix auth", "state": "open", "html_url": "url",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        if "/check-runs" in url:
            return httpx.Response(201, json={"id": 100, "conclusion": json.get("conclusion")})
        if "/statuses" in url:
            return httpx.Response(201, json={"state": json.get("state")})
        if "/issues/142/comments" in url:
            if method == "GET":
                return httpx.Response(200, json=[])
            return httpx.Response(201, json={"id": 200, "body": json.get("body")})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = orchestrate_webhook_event("pull_request", "del_123", mock_pr_payload())
    assert res["status"] == "success"
    assert res["event"] == "pull_request"
    assert res["owner"] == "pallets"
    assert res["repository"] == "flask"
    assert res["pr_number"] == 142
    assert res["head_sha"] == VALID_HEAD_SHA
    assert "check_run" in res
    assert "commit_status" in res
    assert "comment" in res


def test_orchestration_push_event():
    """Verifies push webhook event receives safe acknowledgement without PR comments."""
    res = orchestrate_webhook_event("push", "del_456", mock_push_payload())
    assert res["status"] == "acknowledged"
    assert res["event"] == "push"
    assert res["commit_sha"] == VALID_HEAD_SHA


def test_orchestration_unsupported_event():
    """Verifies unsupported event is safely acknowledged."""
    res = orchestrate_webhook_event("release", "del_789", {"action": "published"})
    assert res["status"] in ("ignored", "acknowledged")
    assert res["event"] == "release"
    assert res["reason"] == "unsupported_event"


# =====================================================================
# 5. ERROR HANDLING TESTS
# =====================================================================

def test_orchestration_github_auth_error_propagated(monkeypatch):
    """Verifies GitHub authentication error propagation."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(401, text="Unauthorized")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubAuthenticationError):
        orchestrate_webhook_event("pull_request", "del_err", mock_pr_payload())


def test_orchestration_github_permission_error_propagated(monkeypatch):
    """Verifies GitHub permission error propagation."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(403, text="Forbidden")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubPermissionError):
        orchestrate_webhook_event("pull_request", "del_err", mock_pr_payload())


def test_orchestration_github_rate_limit_error_propagated(monkeypatch):
    """Verifies GitHub rate-limit error propagation."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(429, text="Rate Limit Exceeded")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubRateLimitError):
        orchestrate_webhook_event("pull_request", "del_err", mock_pr_payload())


# =====================================================================
# 6. FASTAPI ENDPOINT INTEGRATION & HMAC TESTS
# =====================================================================

def test_fastapi_webhook_endpoint_hmac_and_orchestration(monkeypatch):
    """Verifies FastAPI endpoint performs HMAC signature verification before orchestrating PR event."""
    original_request = httpx.Client.request

    def mock_request(self_client, method, url, **kwargs):
        str_url = str(url)
        if "testserver" in str_url or "/github/webhook" in str_url:
            return original_request(self_client, method, url, **kwargs)

        if "/pulls/142/files" in str_url:
            return httpx.Response(200, json=[])
        if "/pulls/142" in str_url:
            return httpx.Response(200, json={
                "title": "Fix auth", "state": "open", "html_url": "url",
                "head": {"ref": "fix", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        if "/check-runs" in str_url:
            return httpx.Response(201, json={"id": 100, "conclusion": "success"})
        if "/statuses" in str_url:
            return httpx.Response(201, json={"state": "success"})
        if "/issues/142/comments" in str_url:
            if method == "GET":
                return httpx.Response(200, json=[])
            return httpx.Response(201, json={"id": 200, "body": kwargs.get("json", {}).get("body", "")})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    secret = "test_webhook_secret_xyz"
    monkeypatch.setattr("backend.app.core.config.settings.GITHUB_WEBHOOK_SECRET", secret)

    client = TestClient(app)
    body_bytes = json.dumps(mock_pr_payload()).encode("utf-8")
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "del_fastapi_001"
    }

    res = client.post("/github/webhook", content=body_bytes, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["event"] == "pull_request"
