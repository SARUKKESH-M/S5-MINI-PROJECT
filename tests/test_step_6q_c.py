"""
CodeSentinel — Step 6Q-C Unit & Integration Test Suite

Tests Check Run Creation & Update, Commit Status Creation, Step 6O Report Payload Formatting,
Decision Mapping ('allow' -> success, 'block' -> failure, 'review' -> action_required/pending),
Input Validation, Error Handling, and Security Boundaries.
"""

import sys
import os
import httpx
import pytest

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from backend.github.client import GitHubClient
    from backend.github.publisher import (
        CHECK_RUN_NAME,
        COMMIT_STATUS_CONTEXT,
        map_review_decision_to_check_conclusion,
        map_review_decision_to_commit_state,
        format_check_run_payload_from_report,
        format_commit_status_from_report,
        create_check_run,
        update_check_run,
        create_commit_status,
        publish_step_6o_report_status
    )
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
except ImportError:
    from github.client import GitHubClient
    from github.publisher import (
        CHECK_RUN_NAME,
        COMMIT_STATUS_CONTEXT,
        map_review_decision_to_check_conclusion,
        map_review_decision_to_commit_state,
        format_check_run_payload_from_report,
        format_commit_status_from_report,
        create_check_run,
        update_check_run,
        create_commit_status,
        publish_step_6o_report_status
    )
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )


VALID_HEAD_SHA = "8f2a1c9000000000000000000000000000000000"


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
                "title": "Hardcoded Secret Assignment",
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


# =====================================================================
# 1. DECISION MAPPING TESTS
# =====================================================================

def test_decision_mapping_check_conclusion():
    """Verifies mapping from Step 6O review_status to Check Run conclusion."""
    assert map_review_decision_to_check_conclusion("allow") == "success"
    assert map_review_decision_to_check_conclusion("block") == "failure"
    assert map_review_decision_to_check_conclusion("review") == "action_required"
    with pytest.raises(ValueError):
        map_review_decision_to_check_conclusion("invalid_status")


def test_decision_mapping_commit_state():
    """Verifies mapping from Step 6O review_status to Commit Status state."""
    assert map_review_decision_to_commit_state("allow") == "success"
    assert map_review_decision_to_commit_state("block") == "failure"
    assert map_review_decision_to_commit_state("review") == "pending"
    with pytest.raises(ValueError):
        map_review_decision_to_commit_state("invalid_status")


# =====================================================================
# 2. CHECK RUN PAYLOAD FORMATTER TESTS
# =====================================================================

def test_format_check_run_payload_queued():
    """Verifies check run payload for queued status."""
    rep = mock_step_6o_report("allow")
    payload = format_check_run_payload_from_report(rep, status="queued")
    assert payload["name"] == CHECK_RUN_NAME
    assert payload["status"] == "queued"
    assert "conclusion" not in payload
    assert "output" in payload


def test_format_check_run_payload_in_progress():
    """Verifies check run payload for in_progress status."""
    rep = mock_step_6o_report("allow")
    payload = format_check_run_payload_from_report(rep, status="in_progress")
    assert payload["status"] == "in_progress"
    assert "conclusion" not in payload


def test_format_check_run_payload_completed_block():
    """Verifies completed check run payload for blocked decision."""
    rep = mock_step_6o_report("block")
    payload = format_check_run_payload_from_report(rep, status="completed")
    assert payload["status"] == "completed"
    assert payload["conclusion"] == "failure"
    assert "BLOCK" in payload["output"]["title"]
    assert "Critical" in payload["output"]["summary"]


def test_format_check_run_payload_completed_allow():
    """Verifies completed check run payload for allowed decision."""
    rep = mock_step_6o_report("allow")
    payload = format_check_run_payload_from_report(rep, status="completed")
    assert payload["conclusion"] == "success"
    assert "ALLOW" in payload["output"]["title"]


def test_format_check_run_payload_completed_review():
    """Verifies completed check run payload for review-needed decision."""
    rep = mock_step_6o_report("review")
    payload = format_check_run_payload_from_report(rep, status="completed")
    assert payload["conclusion"] == "action_required"
    assert "REVIEW" in payload["output"]["title"]


# =====================================================================
# 3. COMMIT STATUS PAYLOAD FORMATTER TESTS
# =====================================================================

def test_format_commit_status_payload():
    """Verifies commit status payload formatting."""
    rep_block = mock_step_6o_report("block")
    status_block = format_commit_status_from_report(rep_block)
    assert status_block["state"] == "failure"
    assert status_block["context"] == COMMIT_STATUS_CONTEXT
    assert "BLOCK" in status_block["description"]

    rep_allow = mock_step_6o_report("allow")
    status_allow = format_commit_status_from_report(rep_allow)
    assert status_allow["state"] == "success"

    rep_review = mock_step_6o_report("review")
    status_review = format_commit_status_from_report(rep_review)
    assert status_review["state"] == "pending"


# =====================================================================
# 4. PUBLISHER API REQUEST TESTS (MOCKED)
# =====================================================================

def test_create_check_run_api(monkeypatch):
    """Verifies create_check_run sends correct HTTP POST payload."""
    sent_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_requests.append({"method": method, "url": url, "json": json})
        return httpx.Response(201, json={"id": 98765, "status": json.get("status")})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = create_check_run(
        owner="pallets",
        repository="flask",
        head_sha=VALID_HEAD_SHA,
        name=CHECK_RUN_NAME,
        status="completed",
        conclusion="failure",
        output={"title": "Audit Verdict", "summary": "Failed"}
    )
    assert res["id"] == 98765
    assert len(sent_requests) == 1
    assert sent_requests[0]["url"] == f"https://api.github.com/repos/pallets/flask/check-runs"
    assert sent_requests[0]["json"]["head_sha"] == VALID_HEAD_SHA
    assert sent_requests[0]["json"]["conclusion"] == "failure"


def test_update_check_run_api(monkeypatch):
    """Verifies update_check_run sends correct HTTP PATCH payload."""
    sent_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_requests.append({"method": method, "url": url, "json": json})
        return httpx.Response(200, json={"id": 98765, "status": json.get("status")})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = update_check_run(
        owner="pallets",
        repository="flask",
        check_run_id=98765,
        status="completed",
        conclusion="success"
    )
    assert res["id"] == 98765
    assert sent_requests[0]["method"] == "PATCH"
    assert sent_requests[0]["url"] == f"https://api.github.com/repos/pallets/flask/check-runs/98765"


def test_create_commit_status_api(monkeypatch):
    """Verifies create_commit_status sends correct HTTP POST payload."""
    sent_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_requests.append({"method": method, "url": url, "json": json})
        return httpx.Response(201, json={"state": json.get("state")})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = create_commit_status(
        owner="pallets",
        repository="flask",
        head_sha=VALID_HEAD_SHA,
        state="failure",
        description="CodeSentinel: BLOCKED"
    )
    assert res["state"] == "failure"
    assert sent_requests[0]["url"] == f"https://api.github.com/repos/pallets/flask/statuses/{VALID_HEAD_SHA}"
    assert sent_requests[0]["json"]["context"] == COMMIT_STATUS_CONTEXT


def test_publish_step_6o_report_status_combined(monkeypatch):
    """Verifies publish_step_6o_report_status publishes both Check Run and Commit Status."""
    sent_urls = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        sent_urls.append(url)
        if "/check-runs" in url:
            return httpx.Response(201, json={"id": 111, "conclusion": json.get("conclusion")})
        return httpx.Response(201, json={"state": json.get("state")})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    rep = mock_step_6o_report("block")
    pub_res = publish_step_6o_report_status(
        owner="pallets",
        repository="flask",
        head_sha=VALID_HEAD_SHA,
        report=rep
    )
    assert "check_run" in pub_res
    assert "commit_status" in pub_res
    assert len(sent_urls) == 2


# =====================================================================
# 5. INPUT VALIDATION TESTS
# =====================================================================

def test_invalid_inputs_rejected():
    """Verifies malformed SHAs, owners, repos, and status values are rejected."""
    # Malformed SHA
    with pytest.raises(ValueError):
        create_check_run("pallets", "flask", "short_sha", status="completed", conclusion="success")

    # Non-hex SHA
    with pytest.raises(ValueError):
        create_commit_status("pallets", "flask", "8f2a1c900000000000000000000000000000000Z", state="success")

    # Empty owner
    with pytest.raises(ValueError):
        create_check_run("", "flask", VALID_HEAD_SHA)

    # Invalid repo
    with pytest.raises(ValueError):
        create_commit_status("pallets", "flask; rm -rf /", VALID_HEAD_SHA, state="success")

    # Invalid check status
    with pytest.raises(ValueError):
        create_check_run("pallets", "flask", VALID_HEAD_SHA, status="invalid_status")

    # Invalid commit state
    with pytest.raises(ValueError):
        create_commit_status("pallets", "flask", VALID_HEAD_SHA, state="invalid_state")


# =====================================================================
# 6. GITHUB ERROR PROPAGATION TESTS
# =====================================================================

def test_github_errors_propagated(monkeypatch):
    """Verifies HTTP status errors (401, 403, 404, 429, 500) propagate existing GitHub exception classes."""
    def mock_401(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(401, text="Unauthorized")

    monkeypatch.setattr(httpx.Client, "request", mock_401)
    with pytest.raises(GitHubAuthenticationError):
        create_check_run("pallets", "flask", VALID_HEAD_SHA)

    def mock_403(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(403, text="Forbidden")

    monkeypatch.setattr(httpx.Client, "request", mock_403)
    with pytest.raises(GitHubPermissionError):
        create_commit_status("pallets", "flask", VALID_HEAD_SHA, state="success")

    def mock_404(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(404, text="Not Found")

    monkeypatch.setattr(httpx.Client, "request", mock_404)
    with pytest.raises(GitHubNotFoundError):
        update_check_run("pallets", "flask", 12345)

    def mock_429(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(429, text="Rate Limit Exceeded")

    monkeypatch.setattr(httpx.Client, "request", mock_429)
    with pytest.raises(GitHubRateLimitError):
        create_check_run("pallets", "flask", VALID_HEAD_SHA)

    def mock_500(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(500, text="Internal Server Error")

    monkeypatch.setattr(httpx.Client, "request", mock_500)
    with pytest.raises(GitHubAPIError):
        create_commit_status("pallets", "flask", VALID_HEAD_SHA, state="success")


# =====================================================================
# 7. SECURITY & STEP 6O COMPATIBILITY TESTS
# =====================================================================

def test_security_report_text_shell_syntax_inert():
    """Verifies report title/description with shell syntax is formatted safely without execution."""
    rep = mock_step_6o_report("block")
    rep["findings"][0]["title"] = "Injected Finding Title; rm -rf /"
    payload = format_check_run_payload_from_report(rep, status="completed")
    assert "Injected Finding Title; rm -rf /" in payload["output"]["text"]


def test_token_secrecy_in_publisher_exceptions(monkeypatch):
    """Verifies token values are masked in client representations used by publisher."""
    client = GitHubClient(token="secret_token_val_999")
    assert "secret_token_val_999" not in repr(client)
    assert "token=SET" in repr(client)
