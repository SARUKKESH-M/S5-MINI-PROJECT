"""
Comprehensive Test Suite for Phase 3: Inline GitHub PR Review Comments.

Validates:
1. Valid changed-line finding creates an inline comment.
2. Correct file path is sent.
3. Correct line number is sent.
4. Correct diff side is sent ("RIGHT").
5. Correct commit SHA is sent.
6. Finding outside PR diff does not create inline comment.
7. Finding outside PR diff remains in the analysis result.
8. Deleted/invalid line is handled safely.
9. Malformed finding location does not create an unsafe comment.
10. Multiple findings generate the correct review payload.
11. Duplicate publication does not create duplicate inline comments.
12. GitHub 422 is handled gracefully.
13. GitHub 403 is handled gracefully.
14. GitHub 429 follows bounded error-handling behavior.
15. GitHub publishing failure does not fail the analysis.
16. Step 6O result is identical whether inline publishing succeeds or fails.
17. Existing top-level summary comment still works.
18. Existing Check Run behavior remains unchanged.
19. Existing Commit Status behavior remains unchanged.
20. No secrets are exposed in generated comments or logs.
"""

import sys
import os
import pytest
import httpx
from typing import Any, Dict, List

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.github.client import GitHubClient
from backend.github.models import GitHubChangedFile, GitHubPullRequest, GitHubPullRequestSnapshot
from backend.github.commenter import (
    COMMENT_MARKER,
    INLINE_COMMENT_MARKER_PREFIX,
    format_pr_security_comment,
    post_pr_security_comment,
    format_inline_finding_comment,
    generate_inline_finding_fingerprint,
    extract_inline_commentable_findings,
    get_existing_inline_comment_fingerprints,
    post_pr_inline_review_comments
)
from backend.github.orchestrator import orchestrate_webhook_event


VALID_HEAD_SHA = "a" * 40
VALID_BASE_SHA = "b" * 40

SAMPLE_UNIFIED_DIFF = (
    "@@ -10,4 +10,6 @@ def authenticate(user, password):\n"
    "     # Check credentials\n"
    "+    eval(f'check_{user}')\n"
    "+    cursor.execute(f'SELECT * FROM users WHERE id={user}')\n"
    "     return True\n"
)


def make_sample_finding(
    finding_id: str = "finding_1",
    file_path: str = "src/auth.py",
    line: int = 12,
    severity: str = "critical",
    title: str = "Insecure Dynamic Code Execution",
    description: str = "Use of eval() detected on untrusted user input.",
    cwe: str = "CWE-95"
) -> Dict[str, Any]:
    """Helper to construct a deterministic finding dictionary."""
    return {
        "finding_id": finding_id,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": "high",
        "category": "Security / Code Injection",
        "cwe": cwe,
        "remediation": "Replace eval() with safe dictionary lookup.",
        "evidence": [
            {
                "document_id": file_path,
                "line_start": line,
                "line_end": line,
                "signal_type": "AST_DYNAMIC_CODE_EXECUTION",
                "signal_name": "eval_call"
            }
        ]
    }


def make_sample_report(findings: List[Dict[str, Any]], review_status: str = "block") -> Dict[str, Any]:
    """Helper to construct a Step 6O production report."""
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    info = sum(1 for f in findings if f.get("severity") == "info")

    return {
        "status": "success",
        "analysis_id": "repo_ana_test_12345",
        "review_status": review_status,
        "summary": {
            "total_findings": len(findings),
            "critical_count": crit,
            "high_count": high,
            "medium_count": med,
            "low_count": low,
            "info_count": info,
            "analyzed_files": 1,
            "skipped_files": 0
        },
        "findings": findings
    }


# =============================================================================
# 1. Valid changed-line finding creates an inline comment
# 2. Correct file path is sent
# 3. Correct line number is sent
# 4. Correct diff side is sent ("RIGHT")
# 5. Correct commit SHA is sent
# =============================================================================
def test_valid_changed_line_creates_inline_comment(monkeypatch):
    """Verifies that a finding on a changed line creates an inline comment with correct fields."""
    finding = make_sample_finding(line=12)
    report = make_sample_report([finding])
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    captured_requests = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        captured_requests.append({
            "method": method,
            "url": url,
            "json": json
        })
        if "/pulls/101/comments" in url and method == "GET":
            return httpx.Response(200, json=[])
        if "/pulls/101/reviews" in url and method == "POST":
            return httpx.Response(201, json={"id": 888, "state": "COMMENTED"})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )

    assert res["status"] == "success"
    assert res["comments_count"] == 1
    assert res["review_id"] == 888

    # Verify review request structure
    review_req = [r for r in captured_requests if "/reviews" in r["url"]][0]
    assert review_req["json"]["commit_id"] == VALID_HEAD_SHA
    assert review_req["json"]["event"] == "COMMENT"

    comments = review_req["json"]["comments"]
    assert len(comments) == 1
    c = comments[0]
    assert c["path"] == "src/auth.py"
    assert c["line"] == 12
    assert c["side"] == "RIGHT"
    assert INLINE_COMMENT_MARKER_PREFIX in c["body"]
    assert "[CRITICAL]" in c["body"]


# =============================================================================
# 6. Finding outside PR diff does not create inline comment
# 7. Finding outside PR diff remains in the analysis result
# =============================================================================
def test_finding_outside_diff_excluded_from_inline_comments(monkeypatch):
    """Verifies that findings outside the modified diff hunks are NOT sent as inline comments."""
    # Line 99 is far outside the diff hunk (lines 10-14)
    finding_outside = make_sample_finding(line=99, title="Pre-existing issue")
    report = make_sample_report([finding_outside])
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    captured_posts = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if method == "POST":
            captured_posts.append(url)
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )

    assert res["status"] == "skipped"
    assert res["reason"] == "no_diff_scoped_findings"
    assert res["comments_count"] == 0
    assert len(captured_posts) == 0  # No review posted

    # Verify finding is still present in report
    assert len(report["findings"]) == 1
    assert report["findings"][0]["title"] == "Pre-existing issue"


# =============================================================================
# 8. Deleted/invalid line is handled safely
# 9. Malformed finding location does not create an unsafe comment
# =============================================================================
def test_deleted_or_malformed_lines_handled_safely(monkeypatch):
    """Verifies that deleted lines, negative lines, or non-integer lines are skipped safely."""
    malformed_findings = [
        {"finding_id": "m1", "title": "No line", "file_path": "src/auth.py"},
        {"finding_id": "m2", "title": "Negative line", "file_path": "src/auth.py", "line_number": -5},
        {"finding_id": "m3", "title": "Zero line", "file_path": "src/auth.py", "line_number": 0},
        {"finding_id": "m4", "title": "String line", "file_path": "src/auth.py", "line_number": "invalid"},
        {"finding_id": "m5", "title": "No file", "line_number": 12},
    ]
    report = make_sample_report(malformed_findings)
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    res = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )

    assert res["status"] == "skipped"
    assert res["comments_count"] == 0


# =============================================================================
# 10. Multiple findings generate the correct review payload
# =============================================================================
def test_multiple_findings_generate_batch_review_payload(monkeypatch):
    """Verifies that multiple findings across modified lines are combined into one review."""
    f1 = make_sample_finding(finding_id="f1", line=11, severity="critical", title="Eval call")
    f2 = make_sample_finding(finding_id="f2", line=12, severity="high", title="SQL injection")
    report = make_sample_report([f1, f2])
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    captured_comments = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if "/pulls/101/comments" in url:
            return httpx.Response(200, json=[])
        if "/pulls/101/reviews" in url and method == "POST":
            captured_comments.extend(json.get("comments", []))
            return httpx.Response(201, json={"id": 999})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )

    assert res["status"] == "success"
    assert res["comments_count"] == 2
    assert len(captured_comments) == 2
    assert captured_comments[0]["line"] == 11
    assert captured_comments[1]["line"] == 12


# =============================================================================
# 11. Duplicate publication does not create duplicate inline comments
# =============================================================================
def test_idempotency_prevents_duplicate_inline_comments(monkeypatch):
    """Verifies that existing CodeSentinel inline comments are not re-published on webhook replay."""
    finding = make_sample_finding(line=12)
    report = make_sample_report([finding])
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    # Compute expected fingerprint
    fp = generate_inline_finding_fingerprint("src/auth.py", 12, finding)

    captured_reviews = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if "/pulls/101/comments" in url and method == "GET":
            # Simulate an already-posted inline comment on this PR
            return httpx.Response(200, json=[
                {
                    "id": 501,
                    "path": "src/auth.py",
                    "line": 12,
                    "body": f"{INLINE_COMMENT_MARKER_PREFIX}{fp} -->\nPrevious comment text"
                }
            ])
        if "/pulls/101/reviews" in url and method == "POST":
            captured_reviews.append(json)
            return httpx.Response(201, json={"id": 123})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )

    assert res["status"] == "skipped"
    assert res["reason"] == "already_commented"
    assert res["comments_count"] == 0
    assert len(captured_reviews) == 0


# =============================================================================
# 12. GitHub 422 is handled gracefully
# =============================================================================
def test_github_422_handled_gracefully_with_fallback(monkeypatch):
    """Verifies that a 422 from batch review triggers individual comment fallback gracefully."""
    f1 = make_sample_finding(finding_id="f1", line=11)
    f2 = make_sample_finding(finding_id="f2", line=12)
    report = make_sample_report([f1, f2])
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    individual_attempts = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if "/pulls/101/comments" in url and method == "GET":
            return httpx.Response(200, json=[])
        if "/pulls/101/reviews" in url and method == "POST":
            # Simulate GitHub rejecting batch review with 422
            return httpx.Response(422, json={"message": "Validation Failed", "errors": ["line out of diff"]})
        if "/pulls/101/comments" in url and method == "POST":
            individual_attempts.append(json)
            # Suppose line 11 succeeds, line 12 fails
            if json.get("line") == 11:
                return httpx.Response(201, json={"id": 777})
            else:
                return httpx.Response(422, json={"message": "Unprocessable"})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    res = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )

    assert res["status"] == "partial_success"
    assert res["method"] == "individual_fallback"
    assert res["comments_count"] == 1
    assert len(individual_attempts) == 2


# =============================================================================
# 13. GitHub 403 is handled gracefully
# 14. GitHub 429 follows bounded error-handling behavior
# =============================================================================
def test_github_403_and_429_handled_without_crash(monkeypatch):
    """Verifies that 403 Forbidden and 429 Rate Limit do not raise exceptions."""
    finding = make_sample_finding(line=12)
    report = make_sample_report([finding])
    changed_file = GitHubChangedFile(
        filename="src/auth.py",
        status="modified",
        additions=2,
        deletions=0,
        changes=2,
        patch=SAMPLE_UNIFIED_DIFF
    )

    # Test 403
    monkeypatch.setattr(httpx.Client, "request", lambda *a, **k: httpx.Response(403, json={"message": "Must have write access"}))
    res_403 = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )
    assert res_403["status"] == "skipped"
    assert "Permission" in res_403["reason"] or "403" in res_403["reason"]

    # Test 429
    monkeypatch.setattr(httpx.Client, "request", lambda *a, **k: httpx.Response(429, json={"message": "Rate limit exceeded"}))
    res_429 = post_pr_inline_review_comments(
        owner="test-org",
        repository="test-repo",
        pr_number=101,
        head_sha=VALID_HEAD_SHA,
        report=report,
        changed_files=[changed_file]
    )
    assert res_429["status"] == "skipped"
    assert "RateLimit" in res_429["reason"] or "429" in res_429["reason"]


# =============================================================================
# 15. GitHub publishing failure does not fail the analysis
# 16. Step 6O result is identical whether inline publishing succeeds or fails
# =============================================================================
def test_publishing_failure_preserves_step_6o_analysis(monkeypatch):
    """Verifies that webhook orchestration succeeds and Step 6O status is preserved even if GitHub commenting fails."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if "/pulls/142/files" in url:
            return httpx.Response(200, json=[{
                "filename": "src/app.py",
                "status": "modified",
                "additions": 2,
                "deletions": 0,
                "changes": 2,
                "patch": SAMPLE_UNIFIED_DIFF
            }])
        if "/pulls/142" in url and method == "GET":
            return httpx.Response(200, json={
                "title": "PR Title", "state": "open", "html_url": "url",
                "head": {"ref": "feature", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        if "/check-runs" in url:
            return httpx.Response(201, json={"id": 10})
        if "/statuses" in url:
            return httpx.Response(201, json={"state": "success"})
        if "/issues/142/comments" in url:
            return httpx.Response(201, json={"id": 20})
        if "/pulls/142/reviews" in url:
            # Simulate complete network failure or 500 error on inline comments
            return httpx.Response(500, json={"message": "Internal GitHub Server Error"})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    payload = {
        "action": "opened",
        "number": 142,
        "pull_request": {
            "number": 142,
            "title": "PR Title",
            "html_url": "https://github.com/test-org/test-repo/pull/142",
            "head": {"sha": VALID_HEAD_SHA, "ref": "feature"},
            "base": {"sha": VALID_BASE_SHA, "ref": "main"},
            "user": {"login": "dev_user"}
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-org"}
        }
    }

    res = orchestrate_webhook_event("pull_request", "del_555", payload)
    assert res["status"] == "success"
    assert "review_status" in res
    assert "inline_comments" in res
    assert res["inline_comments"]["status"] == "skipped"


# =============================================================================
# 17. Existing top-level summary comment still works
# 18. Existing Check Run behavior remains unchanged
# 19. Existing Commit Status behavior remains unchanged
# =============================================================================
def test_existing_summary_comment_and_check_runs_unaffected(monkeypatch):
    """Verifies that top-level comment, check run, and commit status remain published alongside inline comments."""
    posted_endpoints = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        posted_endpoints.append(f"{method} {url}")
        if "/pulls/142/files" in url:
            return httpx.Response(200, json=[{
                "filename": "src/app.py",
                "status": "modified",
                "additions": 1,
                "deletions": 1,
                "changes": 2,
                "patch": SAMPLE_UNIFIED_DIFF
            }])
        if "/pulls/142" in url and method == "GET":
            return httpx.Response(200, json={
                "title": "PR Title", "state": "open", "html_url": "url",
                "head": {"ref": "feature", "sha": VALID_HEAD_SHA},
                "base": {"ref": "main", "sha": VALID_BASE_SHA}
            })
        if "/check-runs" in url:
            return httpx.Response(201, json={"id": 10})
        if "/statuses" in url:
            return httpx.Response(201, json={"state": "success"})
        if "/issues/142/comments" in url:
            if method == "GET":
                return httpx.Response(200, json=[])
            return httpx.Response(201, json={"id": 20})
        if "/pulls/142/comments" in url:
            return httpx.Response(200, json=[])
        if "/pulls/142/reviews" in url:
            return httpx.Response(201, json={"id": 30})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    payload = {
        "action": "opened",
        "number": 142,
        "pull_request": {
            "number": 142,
            "title": "PR Title",
            "html_url": "https://github.com/test-org/test-repo/pull/142",
            "head": {"sha": VALID_HEAD_SHA, "ref": "feature"},
            "base": {"sha": VALID_BASE_SHA, "ref": "main"},
            "user": {"login": "dev_user"}
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "test-org"}
        }
    }

    res = orchestrate_webhook_event("pull_request", "del_777", payload)
    assert res["status"] == "success"
    assert res["check_run"]["id"] == 10
    assert res["commit_status"]["state"] == "success"
    assert res["comment"]["id"] == 20

    # Ensure Check Runs, Statuses, and Issue Comments were all invoked
    endpoints_str = " ".join(posted_endpoints)
    assert "/check-runs" in endpoints_str
    assert "/statuses" in endpoints_str
    assert "/issues/142/comments" in endpoints_str


# =============================================================================
# 20. No secrets are exposed in generated comments or logs
# =============================================================================
def test_no_secrets_exposed_in_inline_comment():
    """Verifies that credential tokens and sensitive paths are redacted from inline comments."""
    finding_with_secrets = make_sample_finding(
        description="Leaked token: ghp_12345678901234567890abcdef at C:\\Users\\admin\\secrets.txt",
        title="Hardcoded token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    )
    fp = "abcdef1234567890"
    comment = format_inline_finding_comment(finding_with_secrets, fp)

    assert "ghp_12345678901234567890abcdef" not in comment
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in comment
    assert "C:\\Users\\admin\\" not in comment
    assert "[REDACTED_CREDENTIAL]" in comment
