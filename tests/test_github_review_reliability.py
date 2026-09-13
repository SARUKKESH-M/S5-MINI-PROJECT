"""
CodeSentinel — Phase 33D Test Suite: GitHub PR Review & Comment Reliability V2

Covers all 39 requirements:
- Pagination (inline comments and summary comments)
- Fingerprint stability across line shifts and collision resistance
- Comment & review deduplication
- Review events mapping and enforce mode
- Safe non-downgrade of Step 6O verdicts
- Error preservation & security boundaries
"""

import hashlib
import os
import sys
import pytest
import httpx
from typing import Any, Dict, List

# Ensure backend and workspace root directory are in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.github.client import GitHubClient
from backend.github.models import GitHubChangedFile, GitHubPullRequest, GitHubPullRequestSnapshot
from backend.github.commenter import (
    COMMENT_MARKER,
    INLINE_COMMENT_MARKER_PREFIX,
    INLINE_COMMENT_MARKER_SUFFIX,
    REVIEW_MARKER_PREFIX,
    REVIEW_MARKER_SUFFIX,
    format_pr_security_comment,
    post_pr_security_comment,
    format_inline_finding_comment,
    generate_inline_finding_fingerprint,
    extract_inline_commentable_findings,
    get_existing_inline_comment_fingerprints,
    get_existing_reviews,
    generate_review_marker,
    map_review_status_to_review_event,
    get_effective_review_mode,
    post_pr_inline_review_comments
)
from backend.github.publisher import (
    map_review_decision_to_check_conclusion,
    map_review_decision_to_commit_state,
    format_check_run_payload_from_report,
    format_commit_status_from_report,
    publish_step_6o_report_status
)
from backend.github.orchestrator import orchestrate_webhook_event
from backend.github.exceptions import (
    GitHubAPIError,
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubNotFoundError,
    GitHubRateLimitError
)

VALID_HEAD_SHA = "a" * 40
VALID_BASE_SHA = "b" * 40

SAMPLE_DIFF = (
    "@@ -10,4 +10,6 @@ def authenticate(user, password):\n"
    "     # Check credentials\n"
    "+    eval(f'check_{user}')\n"
    "+    cursor.execute(f'SELECT * FROM users WHERE id={user}')\n"
    "     return True\n"
)


def make_finding(
    finding_id: str = "finding_1",
    file_path: str = "src/auth.py",
    line: int = 12,
    severity: str = "critical",
    title: str = "Insecure Dynamic Code Execution",
    description: str = "Use of eval() detected on untrusted user input.",
    cwe: str = "CWE-95",
    scope: str = "authenticate",
    sink_name: str = "eval",
    occurrence_index: Any = None
) -> Dict[str, Any]:
    f = {
        "finding_id": finding_id,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": "high",
        "category": "Security / Code Injection",
        "cwe": cwe,
        "scope": scope,
        "remediation": "Replace eval() with safe dictionary lookup.",
        "evidence": [
            {
                "document_id": file_path,
                "line_start": line,
                "line_end": line,
                "signal_type": "AST_DYNAMIC_CODE_EXECUTION",
                "signal_name": sink_name,
                "scope": scope
            }
        ]
    }
    if occurrence_index is not None:
        f["occurrence_index"] = occurrence_index
        f["evidence"][0]["occurrence_index"] = occurrence_index
    return f


def make_report(findings: List[Dict[str, Any]], review_status: str = "block") -> Dict[str, Any]:
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    info = sum(1 for f in findings if f.get("severity") == "info")

    return {
        "status": "success",
        "analysis_id": "repo_ana_rel_123",
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
# PAGINATION TESTS (1-6)
# =============================================================================

def test_01_inline_comment_page1_and_page2_discovery(monkeypatch):
    """1. Verifies pagination across page 1 and page 2 for inline comment discovery."""
    requested_pages = []

    def mock_req(self, method, url, params=None, **kwargs):
        if "/pulls/42/comments" in str(url) and method == "GET":
            p = params.get("page", 1) if params else 1
            requested_pages.append(p)
            if p == 1:
                return httpx.Response(200, json=[
                    {"id": 1, "body": f"{INLINE_COMMENT_MARKER_PREFIX}fp_page1{INLINE_COMMENT_MARKER_SUFFIX}"}
                ] * 100)  # full page
            elif p == 2:
                return httpx.Response(200, json=[
                    {"id": 101, "body": f"{INLINE_COMMENT_MARKER_PREFIX}fp_page2{INLINE_COMMENT_MARKER_SUFFIX}"}
                ])  # partial page -> stop
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    fps = get_existing_inline_comment_fingerprints("org", "repo", 42, per_page=100)
    assert "fp_page1" in fps
    assert "fp_page2" in fps
    assert requested_pages == [1, 2]


def test_02_existing_fingerprint_found_beyond_first_page(monkeypatch):
    """2. Verifies existing fingerprint on page 3 is discovered."""
    def mock_req(self, method, url, params=None, **kwargs):
        if "/pulls/42/comments" in str(url) and method == "GET":
            p = params.get("page", 1) if params else 1
            if p in (1, 2):
                return httpx.Response(200, json=[{"id": p * 100, "body": "unrelated"}] * 100)
            elif p == 3:
                return httpx.Response(200, json=[
                    {"id": 300, "body": f"{INLINE_COMMENT_MARKER_PREFIX}deep_fp_3{INLINE_COMMENT_MARKER_SUFFIX}"}
                ])
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    fps = get_existing_inline_comment_fingerprints("org", "repo", 42, per_page=100)
    assert "deep_fp_3" in fps


def test_03_pagination_stops_at_empty_page(monkeypatch):
    """3. Verifies pagination immediately halts when an empty list is returned."""
    requested_pages = []

    def mock_req(self, method, url, params=None, **kwargs):
        if "/pulls/42/comments" in str(url) and method == "GET":
            p = params.get("page", 1) if params else 1
            requested_pages.append(p)
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    fps = get_existing_inline_comment_fingerprints("org", "repo", 42)
    assert len(fps) == 0
    assert requested_pages == [1]


def test_04_pagination_is_bounded(monkeypatch):
    """4. Verifies pagination does not exceed max_pages bound."""
    page_count = 0

    def mock_req(self, method, url, params=None, **kwargs):
        nonlocal page_count
        if "/pulls/42/comments" in str(url) and method == "GET":
            page_count += 1
            return httpx.Response(200, json=[{"id": page_count, "body": "some comment"}] * 100)
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    fps = get_existing_inline_comment_fingerprints("org", "repo", 42, max_pages=3, per_page=100)
    assert page_count == 3


def test_05_malformed_comment_marker_is_ignored(monkeypatch):
    """5. Verifies malformed marker prefixes/suffixes do not crash extraction."""
    def mock_req(self, method, url, params=None, **kwargs):
        return httpx.Response(200, json=[
            {"id": 1, "body": "<!-- codesentinel-inline-finding: missing suffix"},
            {"id": 2, "body": "normal text without marker"},
            {"id": 3, "body": None},
            {"id": 4, "body": f"{INLINE_COMMENT_MARKER_PREFIX}valid_marker{INLINE_COMMENT_MARKER_SUFFIX}"},
            "not a dict"
        ])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    fps = get_existing_inline_comment_fingerprints("org", "repo", 42)
    assert fps == {"valid_marker"}


def test_06_foreign_comment_is_ignored(monkeypatch):
    """6. Verifies human or third-party bot comments without markers are safely ignored."""
    def mock_req(self, method, url, params=None, **kwargs):
        return httpx.Response(200, json=[
            {"id": 1, "body": "LGTM! Looks good to merge.", "user": {"login": "human"}},
            {"id": 2, "body": "SonarCloud analysis passed", "user": {"login": "sonarcloud[bot]"}}
        ])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    fps = get_existing_inline_comment_fingerprints("org", "repo", 42)
    assert len(fps) == 0


# =============================================================================
# FINGERPRINT STABILITY TESTS (7-12)
# =============================================================================

def test_07_same_logical_finding_after_line_shift_maps_to_same_fingerprint():
    """7. Verifies that when a finding moves from line 12 to line 15, its fingerprint is identical."""
    f_orig = make_finding(finding_id="f1", line=12)
    f_shifted = make_finding(finding_id="f1", line=15)

    fp1 = generate_inline_finding_fingerprint("src/auth.py", 12, f_orig)
    fp2 = generate_inline_finding_fingerprint("src/auth.py", 15, f_shifted)

    assert fp1 == fp2, "Fingerprint must be invariant to line shifts"


def test_08_two_separate_findings_in_same_file_do_not_collide():
    """8. Verifies that two distinct findings in the same file generate distinct fingerprints."""
    f1 = make_finding(finding_id="f1", line=12, sink_name="eval", title="Eval call")
    f2 = make_finding(finding_id="f2", line=20, sink_name="cursor.execute", title="SQL injection")

    fp1 = generate_inline_finding_fingerprint("src/auth.py", 12, f1)
    fp2 = generate_inline_finding_fingerprint("src/auth.py", 20, f2)

    assert fp1 != fp2, "Separate findings in the same file must not collide"


def test_09_different_files_do_not_collide():
    """9. Verifies that the same finding in different files generates distinct fingerprints."""
    f1 = make_finding(finding_id="f1", file_path="src/auth.py")
    f2 = make_finding(finding_id="f1", file_path="src/api.py")

    fp1 = generate_inline_finding_fingerprint("src/auth.py", 12, f1)
    fp2 = generate_inline_finding_fingerprint("src/api.py", 12, f2)

    assert fp1 != fp2, "Findings in different files must not collide"


def test_10_different_rules_do_not_collide():
    """10. Verifies that different security rules on the same line generate distinct fingerprints."""
    f1 = make_finding(finding_id="f1", title="Eval injection", cwe="CWE-95")
    f2 = make_finding(finding_id="f2", title="Path traversal", cwe="CWE-22")
    f2["evidence"][0]["signal_type"] = "AST_PATH_TRAVERSAL"

    fp1 = generate_inline_finding_fingerprint("src/auth.py", 12, f1)
    fp2 = generate_inline_finding_fingerprint("src/auth.py", 12, f2)

    assert fp1 != fp2, "Different rules must produce distinct fingerprints"


def test_11_fingerprint_does_not_contain_secrets_or_raw_source():
    """11. Verifies fingerprint is fixed-length hex digest and never exposes secrets or code."""
    secret_payload = "ghp_12345678901234567890abcdef"
    f = make_finding(finding_id="f1", title=f"Secret {secret_payload}")

    fp = generate_inline_finding_fingerprint("src/auth.py", 12, f)
    assert len(fp) == 16
    assert secret_payload not in fp
    assert all(c in "0123456789abcdef" for c in fp)


def test_12_deterministic_fingerprint_across_repeated_runs():
    """12. Verifies that fingerprint generation is 100% deterministic across repeated invocations."""
    f = make_finding(finding_id="f1", line=12)
    fp1 = generate_inline_finding_fingerprint("src/auth.py", 12, f)
    fp2 = generate_inline_finding_fingerprint("src/auth.py", 12, f)
    fp3 = generate_inline_finding_fingerprint("src/auth.py", 12, f)

    assert fp1 == fp2 == fp3


# =============================================================================
# DEDUPLICATION TESTS (13-17)
# =============================================================================

def test_13_existing_fingerprint_prevents_duplicate_inline_comment(monkeypatch):
    """13. Verifies that an existing fingerprint prevents duplicate inline comment creation."""
    finding = make_finding(finding_id="f1", line=12)
    report = make_report([finding])
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    fp = generate_inline_finding_fingerprint("src/auth.py", 12, finding)
    posted_reviews = []

    def mock_req(self, method, url, **kwargs):
        if "/pulls/101/comments" in str(url) and method == "GET":
            return httpx.Response(200, json=[
                {"id": 501, "body": f"{INLINE_COMMENT_MARKER_PREFIX}{fp}{INLINE_COMMENT_MARKER_SUFFIX}"}
            ])
        if "/pulls/101/reviews" in str(url) and method == "POST":
            posted_reviews.append(kwargs.get("json"))
            return httpx.Response(201, json={"id": 10})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_inline_review_comments("org", "repo", 101, VALID_HEAD_SHA, report, [changed_file])
    assert res["status"] == "skipped"
    assert res["reason"] == "already_commented"
    assert len(posted_reviews) == 0


def test_14_missing_fingerprint_publishes_new_comment(monkeypatch):
    """14. Verifies that a finding without existing fingerprint is published."""
    finding = make_finding(finding_id="f1", line=12)
    report = make_report([finding])
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    posted_reviews = []

    def mock_req(self, method, url, **kwargs):
        if "/pulls/101/comments" in str(url) and method == "GET":
            return httpx.Response(200, json=[])  # no existing comments
        if "/pulls/101/reviews" in str(url) and method == "POST":
            posted_reviews.append(kwargs.get("json"))
            return httpx.Response(201, json={"id": 888})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_inline_review_comments("org", "repo", 101, VALID_HEAD_SHA, report, [changed_file])
    assert res["status"] == "success"
    assert res["comments_count"] == 1
    assert len(posted_reviews) == 1


def test_15_only_added_right_side_lines_are_published():
    """15. Verifies that only added lines on the RIGHT side are eligible for inline comments."""
    finding_added = make_finding(line=11)
    finding_context = make_finding(line=10)  # context line in SAMPLE_DIFF

    report = make_report([finding_added, finding_context])
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    candidates = extract_inline_commentable_findings(report, [changed_file])
    assert len(candidates) == 1
    assert candidates[0]["line"] == 11
    assert candidates[0]["side"] == "RIGHT"


def test_16_422_fallback_to_individual_comments(monkeypatch):
    """16. Verifies that batch review 422 triggers individual comment fallback."""
    f1 = make_finding(finding_id="f1", line=11)
    f2 = make_finding(finding_id="f2", line=12)
    report = make_report([f1, f2])
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    individual_posts = []

    def mock_req(self, method, url, **kwargs):
        if "/pulls/101/comments" in str(url) and method == "GET":
            return httpx.Response(200, json=[])
        if "/pulls/101/reviews" in str(url) and method == "POST":
            return httpx.Response(422, json={"message": "Unprocessable Entity"})
        if "/pulls/101/comments" in str(url) and method == "POST":
            individual_posts.append(kwargs.get("json"))
            return httpx.Response(201, json={"id": 111})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_inline_review_comments("org", "repo", 101, VALID_HEAD_SHA, report, [changed_file])
    assert res["status"] == "partial_success"
    assert res["method"] == "individual_fallback"
    assert res["comments_count"] == 2
    assert len(individual_posts) == 2


def test_17_duplicate_review_is_skipped(monkeypatch):
    """17. Verifies that a review with an identical marker on the same commit SHA is skipped."""
    finding = make_finding(finding_id="f1", line=12)
    report = make_report([finding], review_status="block")
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    fp = generate_inline_finding_fingerprint("src/auth.py", 12, finding)
    marker = generate_review_marker(VALID_HEAD_SHA, "block", "REQUEST_CHANGES", [fp])

    review_posts = []

    def mock_req(self, method, url, **kwargs):
        if "/pulls/101/reviews" in str(url) and method == "GET":
            return httpx.Response(200, json=[
                {"id": 99, "commit_id": VALID_HEAD_SHA, "body": f"Header\n{marker}\nDetails"}
            ])
        if "/pulls/101/reviews" in str(url) and method == "POST":
            review_posts.append(kwargs.get("json"))
            return httpx.Response(201, json={"id": 100})
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_inline_review_comments(
        "org", "repo", 101, VALID_HEAD_SHA, report, [changed_file], review_mode="enforce"
    )
    assert res["status"] == "skipped"
    assert res["reason"] == "review_already_submitted"
    assert len(review_posts) == 0


# =============================================================================
# REVIEW EVENT MAPPING TESTS (18-24)
# =============================================================================

def test_18_default_mode_remains_comment():
    """18. Verifies default mode always uses COMMENT event regardless of verdict."""
    assert map_review_status_to_review_event("allow", review_mode="comment") == "COMMENT"
    assert map_review_status_to_review_event("block", review_mode="comment") == "COMMENT"
    assert map_review_status_to_review_event("review", review_mode="comment") == "COMMENT"
    assert map_review_status_to_review_event("invalid", review_mode="comment") == "COMMENT"


def test_19_enforce_mode_block_maps_to_request_changes():
    """19. Verifies enforce mode maps BLOCK to REQUEST_CHANGES."""
    assert map_review_status_to_review_event("block", review_mode="enforce") == "REQUEST_CHANGES"


def test_20_enforce_mode_allow_maps_to_approve():
    """20. Verifies enforce mode maps ALLOW to APPROVE."""
    assert map_review_status_to_review_event("allow", review_mode="enforce") == "APPROVE"


def test_21_enforce_mode_review_maps_to_comment():
    """21. Verifies enforce mode maps REVIEW to COMMENT."""
    assert map_review_status_to_review_event("review", review_mode="enforce") == "COMMENT"


def test_22_enforce_mode_invalid_safe_non_approve_behavior():
    """22. Verifies enforce mode never maps INVALID, UNKNOWN, or None to APPROVE."""
    assert map_review_status_to_review_event("invalid", review_mode="enforce") == "COMMENT"
    assert map_review_status_to_review_event("unknown", review_mode="enforce") == "COMMENT"
    assert map_review_status_to_review_event(None, review_mode="enforce") == "COMMENT"


def test_23_permission_failure_does_not_alter_step_6o(monkeypatch):
    """23. Verifies that a 403 Permission error on review submission does not alter Step 6O verdict."""
    finding = make_finding(finding_id="f1", line=12)
    report = make_report([finding], review_status="block")
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    def mock_req(self, method, url, **kwargs):
        if "/pulls/101/comments" in str(url):
            return httpx.Response(200, json=[])
        if "/pulls/101/reviews" in str(url) and method == "POST":
            return httpx.Response(403, json={"message": "Resource not accessible by integration"})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_inline_review_comments(
        "org", "repo", 101, VALID_HEAD_SHA, report, [changed_file], review_mode="enforce"
    )
    assert res["status"] == "skipped"
    assert "Permission" in res["reason"]
    # Step 6O report verdict remains strictly BLOCK
    assert report["review_status"] == "block"


def test_24_publishing_failure_does_not_alter_step_6o(monkeypatch):
    """24. Verifies 500 error from GitHub does not alter Step 6O verdict."""
    finding = make_finding(finding_id="f1", line=12)
    report = make_report([finding], review_status="block")
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)

    def mock_req(self, method, url, **kwargs):
        if "/pulls/101/comments" in str(url):
            return httpx.Response(200, json=[])
        if "/pulls/101/reviews" in str(url) and method == "POST":
            return httpx.Response(500, json={"message": "Internal Server Error"})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_inline_review_comments("org", "repo", 101, VALID_HEAD_SHA, report, [changed_file])
    assert res["status"] == "skipped"
    assert report["review_status"] == "block"


# =============================================================================
# SUMMARY COMMENT TESTS (25-28)
# =============================================================================

def test_25_existing_summary_comment_is_updated(monkeypatch):
    """25. Verifies existing summary comment is updated via PATCH rather than duplicated."""
    patch_called = []
    post_called = []

    def mock_req(self, method, url, **kwargs):
        if "/issues/101/comments" in str(url) and method == "GET":
            return httpx.Response(200, json=[
                {"id": 404, "body": f"Intro\n{COMMENT_MARKER}\nOld summary"}
            ])
        if "/issues/comments/404" in str(url) and method == "PATCH":
            patch_called.append(url)
            return httpx.Response(200, json={"id": 404, "status": "updated"})
        if method == "POST":
            post_called.append(url)
            return httpx.Response(201, json={"id": 505})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_security_comment("org", "repo", 101, make_report([]))
    assert len(patch_called) == 1
    assert len(post_called) == 0


def test_26_summary_search_paginates_safely(monkeypatch):
    """26. Verifies summary comment lookup paginates to page 2 if needed."""
    requested_pages = []

    def mock_req(self, method, url, params=None, **kwargs):
        if "/issues/101/comments" in str(url) and method == "GET":
            p = params.get("page", 1) if params else 1
            requested_pages.append(p)
            if p == 1:
                return httpx.Response(200, json=[{"id": 1, "body": "unrelated"}] * 100)
            elif p == 2:
                return httpx.Response(200, json=[
                    {"id": 202, "body": f"Header\n{COMMENT_MARKER}\nSummary"}
                ])
        if "/issues/comments/202" in str(url) and method == "PATCH":
            return httpx.Response(200, json={"id": 202})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    res = post_pr_security_comment("org", "repo", 101, make_report([]), per_page=100)
    assert requested_pages == [1, 2]


def test_27_unrelated_comments_are_untouched(monkeypatch):
    """27. Verifies comments without COMMENT_MARKER are never modified."""
    modified_comments = []

    def mock_req(self, method, url, **kwargs):
        if "/issues/101/comments" in str(url) and method == "GET":
            return httpx.Response(200, json=[
                {"id": 1, "body": "Hello world from dev"},
                {"id": 2, "body": "Another user comment"}
            ])
        if method == "PATCH":
            modified_comments.append(url)
            return httpx.Response(200, json={})
        if "/issues/101/comments" in str(url) and method == "POST":
            return httpx.Response(201, json={"id": 999})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    post_pr_security_comment("org", "repo", 101, make_report([]))
    assert len(modified_comments) == 0, "Unrelated user comments must never be modified"


def test_28_repeated_execution_does_not_create_duplicate_summary_comments(monkeypatch):
    """28. Verifies running summary commenter twice updates rather than posts twice."""
    comments_store = []

    def mock_req(self, method, url, **kwargs):
        if "/issues/101/comments" in str(url) and method == "GET":
            return httpx.Response(200, json=list(comments_store))
        if "/issues/101/comments" in str(url) and method == "POST":
            new_c = {"id": 100 + len(comments_store), "body": kwargs.get("json", {}).get("body", "")}
            comments_store.append(new_c)
            return httpx.Response(201, json=new_c)
        if "/issues/comments/" in str(url) and method == "PATCH":
            cid = int(str(url).rsplit("/", 1)[-1])
            for c in comments_store:
                if c["id"] == cid:
                    c["body"] = kwargs.get("json", {}).get("body", "")
            return httpx.Response(200, json={"id": cid})
        return httpx.Response(200, json={})

    monkeypatch.setattr(httpx.Client, "request", mock_req)

    # First run: posts
    post_pr_security_comment("org", "repo", 101, make_report([]))
    assert len(comments_store) == 1

    # Second run: patches
    post_pr_security_comment("org", "repo", 101, make_report([]))
    assert len(comments_store) == 1, "Must not create duplicate summary comments"


# =============================================================================
# SECURITY & INVARIANT TESTS (29-34)
# =============================================================================

def test_29_block_remains_block_after_comment_failure(monkeypatch):
    """29. Verifies BLOCK verdict remains unchanged if comment posting throws error."""
    report = make_report([make_finding(severity="critical")], review_status="block")
    monkeypatch.setattr(GitHubClient, "request", lambda *a, **k: (_ for _ in ()).throw(GitHubAPIError("Server error", 500)))

    try:
        post_pr_security_comment("org", "repo", 101, report)
    except Exception:
        pass

    assert report["review_status"] == "block"


def test_30_block_remains_block_after_review_failure(monkeypatch):
    """30. Verifies BLOCK verdict remains unchanged if review submission fails."""
    report = make_report([make_finding(severity="critical")], review_status="block")
    changed_file = GitHubChangedFile("src/auth.py", "modified", 2, 0, 2, patch=SAMPLE_DIFF)
    monkeypatch.setattr(GitHubClient, "request", lambda *a, **k: (_ for _ in ()).throw(GitHubAPIError("Forbidden", 403)))

    res = post_pr_inline_review_comments("org", "repo", 101, VALID_HEAD_SHA, report, [changed_file])
    assert res["status"] == "skipped"
    assert report["review_status"] == "block"


def test_31_allow_remains_allow_after_publishing_failure(monkeypatch):
    """31. Verifies ALLOW verdict remains unchanged if publisher throws exception."""
    report = make_report([], review_status="allow")
    monkeypatch.setattr(GitHubClient, "request", lambda *a, **k: (_ for _ in ()).throw(GitHubAPIError("Timeout", 504)))

    try:
        publish_step_6o_report_status("org", "repo", VALID_HEAD_SHA, report)
    except Exception:
        pass

    assert report["review_status"] == "allow"


def test_32_invalid_remains_fail_closed():
    """32. Verifies INVALID review_status maps to failure in Check Runs and Commit Statuses."""
    check_conclusion = map_review_decision_to_check_conclusion("invalid")
    commit_state = map_review_decision_to_commit_state("invalid")
    review_event = map_review_status_to_review_event("invalid", review_mode="enforce")

    assert check_conclusion == "failure"
    assert commit_state == "failure"
    assert review_event == "COMMENT"  # never APPROVE!


def test_33_no_secret_leakage_in_review_marker_or_comment():
    """33. Verifies sensitive tokens and credentials are masked from review comments and markers."""
    secret_token = "ghp_12345678901234567890abcdef"
    secret_jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    f = make_finding(
        title=f"Leaked {secret_token}",
        description=f"Auth header: {secret_jwt}"
    )
    fp = generate_inline_finding_fingerprint("src/auth.py", 12, f)
    comment = format_inline_finding_comment(f, fp)
    marker = generate_review_marker(VALID_HEAD_SHA, "block", "COMMENT", [fp])

    assert secret_token not in comment
    assert secret_jwt not in comment
    assert secret_token not in marker
    assert secret_jwt not in marker


def test_34_no_workstation_source_path_leakage():
    """34. Verifies absolute workstation paths are masked to workspace/."""
    f = make_finding(description="Found in C:\\Users\\admin\\repo\\secret.txt and /home/runner/work/code")
    fp = generate_inline_finding_fingerprint("src/auth.py", 12, f)
    comment = format_inline_finding_comment(f, fp)

    assert "C:\\Users\\admin\\" not in comment
    assert "/home/runner/" not in comment
    assert "workspace/" in comment


# =============================================================================
# REGRESSION TESTS (35-39)
# =============================================================================

def test_35_phase_33b_resilience_contracts_preserved():
    """35. Verifies Phase 33B bounded backoff retry delay calculation remains intact."""
    client = GitHubClient(timeout=5.0, max_retries=3, max_backoff_seconds=8.0)
    delay = client._calculate_retry_delay(None, attempt=2)
    assert 0.0 <= delay <= 8.0
    client.close()


def test_36_phase_33c_commit_idempotency_contracts_preserved():
    """36. Verifies Phase 33C commit reservation and lookup functions remain callable."""
    from backend.analysis.storage.store import AnalysisStore, _validate_pr_identity
    owner, repo, pr, sha = _validate_pr_identity("octocat", "Hello-World", 42, "a" * 40)
    assert owner == "octocat"
    assert repo == "Hello-World"
    assert pr == 42
    assert sha == "a" * 40


def test_37_phase_32_analytics_contracts_preserved():
    """37. Verifies Phase 32 time window parsing contracts remain intact."""
    from backend.analysis.storage.models import parse_time_window
    window, cutoff = parse_time_window("30d")
    assert window == "30d"
    assert cutoff is not None


def test_38_existing_step_6q_github_check_run_payload_intact():
    """38. Verifies Step 6Q check run and commit status payload formatting remain intact."""
    report = make_report([], review_status="allow")
    payload = format_check_run_payload_from_report(report, status="completed")
    assert payload["conclusion"] == "success"
    status_payload = format_commit_status_from_report(report)
    assert status_payload["state"] == "success"


def test_39_existing_inline_review_comment_structure_intact():
    """39. Verifies inline finding comment format preserves badges and markers."""
    f = make_finding(severity="critical", cwe="CWE-89")
    comment = format_inline_finding_comment(f, "abcdef1234567890")
    assert INLINE_COMMENT_MARKER_PREFIX in comment
    assert "[CRITICAL]" in comment
    assert "`CWE-89`" in comment
