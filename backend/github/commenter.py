"""
CodeSentinel — Step 6Q-D: GitHub PR Security Commenter

Formats and posts/updates deterministic Markdown security analysis comments on GitHub Pull Requests.
Prevents duplicate comments by identifying the stable marker `<!-- codesentinel-security-analysis -->`.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Set

try:
    from backend.app.core.config import settings
    from backend.github.client import GitHubClient
    from backend.github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
    from backend.analysis.diff_scope import parse_unified_diff
except ImportError:
    try:
        from app.core.config import settings
    except ImportError:
        settings = None
    from github.client import GitHubClient
    from github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
    from analysis.diff_scope import parse_unified_diff

REVIEW_MARKER_PREFIX = "<!-- codesentinel-review:"
REVIEW_MARKER_SUFFIX = " -->"

VALID_REVIEW_MODES = {"comment", "enforce"}
VALID_REVIEW_EVENTS = {"COMMENT", "APPROVE", "REQUEST_CHANGES"}

DEFAULT_MAX_PAGINATION_PAGES = 10
DEFAULT_PAGINATION_PER_PAGE = 100



COMMENT_MARKER = "<!-- codesentinel-security-analysis -->"

DECISION_TO_COMMENT_LABEL = {
    "allow": "PASSED / Safe to Merge",
    "block": "BLOCKED / Do Not Merge",
    "review": "REVIEW NEEDED / Manual Review Required"
}

DECISION_TO_NEXT_ACTION = {
    "allow": "No blocking security vulnerabilities detected. Code is safe to merge.",
    "block": "High or critical severity security vulnerabilities were detected. Remediate findings before merging.",
    "review": "Security findings require manual review by a security reviewer before proceeding."
}


def format_pr_security_comment(
    report: Dict[str, Any],
    owner: str = "",
    repository: str = "",
    pr_number: Optional[int] = None
) -> str:
    """
    Transforms a Step 6O Production Report into a deterministic Markdown PR security comment.

    Args:
        report: Valid Step 6O Production Report dictionary.
        owner: Optional repository owner name.
        repository: Optional repository name.
        pr_number: Optional PR number.

    Returns:
        Formatted Markdown string containing the COMMENT_MARKER.
    """
    if not isinstance(report, dict):
        raise ValueError("Step 6O report must be a non-empty dictionary")

    review_status = str(report.get("review_status", "allow")).lower()
    decision_label = DECISION_TO_COMMENT_LABEL.get(review_status, "PASSED / Safe to Merge")
    next_action = DECISION_TO_NEXT_ACTION.get(review_status, "Review security findings before merging.")

    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    crit_count = int(summary.get("critical_count", 0))
    high_count = int(summary.get("high_count", 0))
    med_count = int(summary.get("medium_count", 0))
    low_count = int(summary.get("low_count", 0))
    info_count = int(summary.get("info_count", 0))
    total_findings = int(summary.get("total_findings", len(report.get("findings", []))))
    analyzed_files = int(summary.get("analyzed_files", 0))

    repo_info = ""
    if owner and repository:
        repo_info = f" for **{owner}/{repository}**"
        if pr_number:
            repo_info += f" (PR #{pr_number})"

    markdown = (
        f"{COMMENT_MARKER}\n"
        f"## CodeSentinel Security Analysis{repo_info}\n\n"
        f"**Security Gate Verdict**: `{decision_label}`\n\n"
        f"### Summary Telemetry\n"
        f"- **Analyzed Files**: {analyzed_files}\n"
        f"- **Total Security Findings**: {total_findings}\n"
        f"- **Critical Severity**: `{crit_count}`\n"
        f"- **High Severity**: `{high_count}`\n"
        f"- **Medium Severity**: `{med_count}`\n"
        f"- **Low Severity**: `{low_count}`\n"
        f"- **Info**: `{info_count}`\n\n"
    )

    findings = report.get("findings", [])
    if findings and isinstance(findings, list):
        markdown += "### Key Findings\n\n"
        for idx, f in enumerate(findings[:10], start=1):
            if isinstance(f, dict):
                f_id = f.get("finding_id", f"finding_{idx}")
                f_title = str(f.get("title", "Security Finding")).strip()
                f_sev = str(f.get("severity", "unknown")).upper()
                markdown += f"{idx}. **[{f_sev}]** `{f_id}` — {f_title}\n"
        if len(findings) > 10:
            markdown += f"\n*...and {len(findings) - 10} additional findings.*"
        markdown += "\n\n"

    markdown += (
        f"### Recommended Next Action\n"
        f"{next_action}\n\n"
        f"---  \n"
        f"*Automated DevSecOps Security Audit generated by CodeSentinel Security OS.*"
    )

    return markdown


def post_pr_security_comment(
    owner: str,
    repository: str,
    pr_number: int,
    report: Dict[str, Any],
    client: Optional[GitHubClient] = None,
    max_pages: int = DEFAULT_MAX_PAGINATION_PAGES,
    per_page: int = DEFAULT_PAGINATION_PER_PAGE
) -> Dict[str, Any]:
    """
    Posts or updates a GitHub Pull Request security comment.
    Searches for an existing comment with `COMMENT_MARKER` using bounded pagination and updates it if present.

    Args:
        owner: Repository owner.
        repository: Repository name.
        pr_number: PR number.
        report: Step 6O Production Report dictionary.
        client: Optional GitHubClient instance.
        max_pages: Maximum comment pages to inspect.
        per_page: Items per page.

    Returns:
        GitHub API response dictionary for comment creation/update.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_pr_num = validate_pr_number(pr_number)

    api_client = client or GitHubClient()
    comment_body = format_pr_security_comment(report, owner=clean_owner, repository=clean_repo, pr_number=clean_pr_num)

    # 1. Search for existing comments on the PR/issue with bounded pagination
    list_endpoint = f"/repos/{clean_owner}/{clean_repo}/issues/{clean_pr_num}/comments"
    existing_comment_id = None
    page = 1

    while page <= max_pages:
        try:
            comments_res = api_client.get(list_endpoint, params={"page": page, "per_page": per_page})
        except Exception:
            comments_res = []

        if not isinstance(comments_res, list) or not comments_res:
            break

        for c in comments_res:
            if isinstance(c, dict) and COMMENT_MARKER in str(c.get("body", "")):
                existing_comment_id = c.get("id")
                break

        if existing_comment_id is not None or len(comments_res) < per_page:
            break

        page += 1

    # 2. Update existing comment or post new comment
    if existing_comment_id is not None:
        update_endpoint = f"/repos/{clean_owner}/{clean_repo}/issues/comments/{existing_comment_id}"
        return api_client.request("PATCH", update_endpoint, json_data={"body": comment_body})
    else:
        post_endpoint = f"/repos/{clean_owner}/{clean_repo}/issues/{clean_pr_num}/comments"
        return api_client.request("POST", post_endpoint, json_data={"body": comment_body})



# =============================================================================
# INLINE GITHUB PR REVIEW COMMENTS
# =============================================================================

INLINE_COMMENT_MARKER_PREFIX = "<!-- codesentinel-inline-finding:"
INLINE_COMMENT_MARKER_SUFFIX = " -->"

SEVERITY_BADGES = {
    "critical": "🔴 **[CRITICAL]**",
    "high": "🟠 **[HIGH]**",
    "medium": "🟡 **[MEDIUM]**",
    "low": "🔵 **[LOW]**",
    "info": "⚪ **[INFO]**"
}


def _scrub_sensitive_text(text: str) -> str:
    """Removes tokens, passwords, or internal paths from comment text to prevent leakage."""
    if not text or not isinstance(text, str):
        return ""
    # Mask common credential patterns (ghp_, github_pat_, Bearer, secret keys)
    scrubbed = re.sub(
        r"(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|Bearer\s+[A-Za-z0-9\-_.]+)",
        "[REDACTED_CREDENTIAL]",
        text
    )
    scrubbed = re.sub(
        r"(sk-[A-Za-z0-9]{20,}|(?:secret|password|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"])",
        "[REDACTED_CREDENTIAL]",
        scrubbed,
        flags=re.IGNORECASE
    )
    # Mask local user home directories (e.g. C:\Users\admin\... or /home/runner/...)
    scrubbed = re.sub(r"[A-Za-z]:\\[Uu]sers\\[^\\]+\\", "workspace/", scrubbed)
    scrubbed = re.sub(r"/home/[^/]+/", "workspace/", scrubbed)
    return scrubbed


def generate_inline_finding_fingerprint(
    file_path: str,
    line: Optional[int],
    finding: Dict[str, Any]
) -> str:
    """
    Generates a deterministic 16-hex fingerprint for an inline finding on a file.
    Follows Phase 31 structural fingerprinting:
    - Independent of line shifts (omits raw line number).
    - Distinguishes separate occurrences using scope, sink name, rule, and structural occurrence index.
    - Zero secrets or raw source code included.
    """
    norm_path = _normalize_repo_relative_path(file_path).lower()

    evidence = finding.get("evidence", [])
    ev = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) else {}

    raw_rule = ev.get("signal_type") or finding.get("rule_id") or finding.get("category") or "unknown"
    norm_rule = str(raw_rule).strip().lower()

    raw_cwe = finding.get("cwe") or finding.get("cwe_id") or ""
    norm_cwe = str(raw_cwe).strip().lower()

    raw_scope = (
        finding.get("scope")
        or finding.get("function_name")
        or ev.get("scope")
        or ev.get("function_name")
        or "<module>"
    )
    norm_scope = str(raw_scope).strip() or "<module>"

    raw_sink = (
        ev.get("signal_name")
        or ev.get("sink_name")
        or ev.get("call_name")
        or finding.get("sink_name")
        or finding.get("call_name")
        or ""
    )
    norm_sink = str(raw_sink).strip()

    raw_title = str(finding.get("title") or "").strip().lower()

    occ = finding.get("occurrence_index")
    if occ is None:
        occ = ev.get("occurrence_index")

    if occ is not None:
        discriminator = str(occ)
    else:
        discriminator = str(finding.get("finding_id") or "0")

    canonical = f"{norm_path}:{norm_rule}:{norm_cwe}:{norm_scope}:{norm_sink}:{raw_title}:{discriminator}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def format_inline_finding_comment(
    finding: Dict[str, Any],
    fingerprint: str
) -> str:
    """
    Formats a concise, developer-friendly Markdown inline PR review comment for a deterministic finding.
    Ensures stable marker inclusion and zero secret leakage.
    """
    if not isinstance(finding, dict):
        raise ValueError("Finding must be a dictionary")

    marker = f"{INLINE_COMMENT_MARKER_PREFIX}{fingerprint}{INLINE_COMMENT_MARKER_SUFFIX}"
    sev_raw = str(finding.get("severity") or "medium").strip().lower()
    badge = SEVERITY_BADGES.get(sev_raw, "🟡 **[MEDIUM]**")

    cwe_id = finding.get("cwe") or finding.get("cwe_id")
    cwe_label = f"`{cwe_id}` — " if cwe_id else ""

    title = _scrub_sensitive_text(str(finding.get("title") or "Security Finding").strip())
    desc = _scrub_sensitive_text(str(finding.get("description") or "Security vulnerability detected on this modified line.").strip())

    remediation = finding.get("remediation") or finding.get("suggestion")
    if not remediation:
        remediation = "Remediate this finding or implement appropriate input validation/sanitization."
    remediation_text = _scrub_sensitive_text(str(remediation).strip())

    comment = (
        f"{marker}\n"
        f"### {badge} {cwe_label}{title}\n\n"
        f"**Issue:** {desc}\n\n"
        f"**Remediation:** {remediation_text}\n\n"
        f"---\n"
        f"*CodeSentinel Automated DevSecOps Gate*"
    )
    return comment


def _normalize_repo_relative_path(path: str) -> str:
    """Normalizes relative file path for cross-platform comparison."""
    if not path or not isinstance(path, str):
        return ""
    clean = path.strip().replace("\\", "/").lstrip("./")
    while "//" in clean:
        clean = clean.replace("//", "/")
    return clean


def extract_inline_commentable_findings(
    report: Dict[str, Any],
    changed_files: List[Any]
) -> List[Dict[str, Any]]:
    """
    Extracts findings from a Step 6O report that map confidently to added/modified lines in the PR diff.
    Findings outside diff hunks, on unmappable lines, or in unchanged files are strictly omitted.

    Args:
        report: Step 6O Production Report dictionary containing findings.
        changed_files: List of GitHubChangedFile objects or dicts from PR snapshot.

    Returns:
        List of dictionaries with keys: 'path', 'line', 'side', 'finding', 'fingerprint'.
    """
    if not isinstance(report, dict) or not changed_files:
        return []

    # 1. Build map of changed files -> set of added/modified lines in new file (side RIGHT)
    changed_file_diff_map: Dict[str, Set[int]] = {}

    for f_item in changed_files:
        fname = getattr(f_item, "filename", None) or (f_item.get("filename") if isinstance(f_item, dict) else "")
        patch = getattr(f_item, "patch", None) or (f_item.get("patch") if isinstance(f_item, dict) else None)
        status = getattr(f_item, "status", None) or (f_item.get("status") if isinstance(f_item, dict) else "")

        if not fname or status == "removed" or not patch:
            continue

        norm_name = _normalize_repo_relative_path(fname)
        try:
            diff_info = parse_unified_diff(patch)
            if diff_info and diff_info.added_lines:
                changed_file_diff_map[norm_name] = set(diff_info.added_lines)
        except Exception:
            continue

    if not changed_file_diff_map:
        return []

    # 2. Iterate through report findings and map to modified diff lines
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return []

    commentable: List[Dict[str, Any]] = []
    scope_occurrence_counts: Dict[Tuple[str, str, str], int] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        # Extract file path
        f_path = finding.get("file_path") or finding.get("file")
        if not f_path:
            ev_list = finding.get("evidence", [])
            if isinstance(ev_list, list) and ev_list and isinstance(ev_list[0], dict):
                f_path = ev_list[0].get("document_id")

        if not f_path or not isinstance(f_path, str):
            continue

        norm_f_path = _normalize_repo_relative_path(f_path)

        # Match to a changed file in PR
        matched_target_path = None
        matched_diff_lines = None

        if norm_f_path in changed_file_diff_map:
            matched_target_path = norm_f_path
            matched_diff_lines = changed_file_diff_map[norm_f_path]
        else:
            for cf_name, diff_lines in changed_file_diff_map.items():
                if norm_f_path.endswith(cf_name) or cf_name.endswith(norm_f_path):
                    matched_target_path = cf_name
                    matched_diff_lines = diff_lines
                    break

        if not matched_target_path or matched_diff_lines is None:
            # Finding is in an unchanged file or file without patch -> skip inline comment
            continue

        # Extract line number
        f_line = finding.get("line_number")
        if f_line is None:
            f_line = finding.get("line")
        if f_line is None:
            ev_list = finding.get("evidence", [])
            if isinstance(ev_list, list) and ev_list and isinstance(ev_list[0], dict):
                f_line = ev_list[0].get("line_start")

        if f_line is None:
            continue

        try:
            line_num = int(f_line)
        except (ValueError, TypeError):
            continue

        if line_num <= 0:
            continue

        # Strict check: finding line MUST be in added/modified diff lines of the PR!
        if line_num not in matched_diff_lines:
            # Line is outside the PR diff hunk -> do NOT create inline comment
            continue

        ev_list = finding.get("evidence", [])
        ev0 = ev_list[0] if isinstance(ev_list, list) and ev_list and isinstance(ev_list[0], dict) else {}
        rule_key = str(ev0.get("signal_type") or finding.get("rule_id") or finding.get("category") or "unknown").lower()
        scope_key = str(finding.get("scope") or ev0.get("scope") or "<module>")
        occ_key = (matched_target_path, rule_key, scope_key)

        finding_dict = dict(finding)
        if "occurrence_index" not in finding_dict and "occurrence_index" not in ev0 and not finding_dict.get("finding_id"):
            current_occ = scope_occurrence_counts.get(occ_key, 0)
            scope_occurrence_counts[occ_key] = current_occ + 1
            finding_dict["occurrence_index"] = current_occ

        fp = generate_inline_finding_fingerprint(matched_target_path, line_num, finding_dict)
        commentable.append({
            "path": matched_target_path,
            "line": line_num,
            "side": "RIGHT",
            "finding": finding_dict,
            "fingerprint": fp
        })


    return commentable



def get_effective_review_mode(review_mode: Optional[str] = None) -> str:
    """Resolves effective GitHub review mode ('comment' or 'enforce')."""
    if review_mode and str(review_mode).strip().lower() in VALID_REVIEW_MODES:
        return str(review_mode).strip().lower()
    if settings is not None:
        configured = getattr(settings, "CODESENTINEL_GITHUB_REVIEW_MODE", None) or getattr(settings, "GITHUB_REVIEW_MODE", "comment")
        val = str(configured or "comment").strip().lower()
        if val in VALID_REVIEW_MODES:
            return val
    return "comment"


def map_review_status_to_review_event(
    review_status: Optional[str],
    review_mode: str = "comment"
) -> str:
    """
    Maps canonical Step 6O review_status ('allow', 'block', 'review', 'invalid') to GitHub review event.
    Enforce mode mapping:
      - allow -> APPROVE
      - block -> REQUEST_CHANGES
      - review -> COMMENT
      - invalid / unknown / None -> COMMENT (fail-closed: never APPROVE)
    Default ('comment') mode always maps to COMMENT.
    """
    clean_mode = str(review_mode or "comment").strip().lower()
    if clean_mode != "enforce":
        return "COMMENT"

    clean_status = str(review_status or "").strip().lower()
    if clean_status == "allow":
        return "APPROVE"
    elif clean_status == "block":
        return "REQUEST_CHANGES"
    elif clean_status == "review":
        return "COMMENT"
    else:
        # INVALID, UNKNOWN, or missing -> fail-closed: COMMENT, never APPROVE
        return "COMMENT"


def generate_review_marker(
    head_sha: str,
    review_status: str,
    review_event: str,
    finding_fingerprints: Optional[List[str]] = None
) -> str:
    """
    Generates a deterministic hidden review marker for submission deduplication.
    Never exposes secrets or source code.
    """
    fps = sorted(list(set(finding_fingerprints or [])))
    fps_hash = hashlib.sha256(",".join(fps).encode("utf-8")).hexdigest()[:16]
    clean_sha = str(head_sha or "").strip().lower()
    clean_status = str(review_status or "allow").strip().lower()
    clean_event = str(review_event or "COMMENT").strip().upper()
    return f"{REVIEW_MARKER_PREFIX}{clean_sha}:{clean_status}:{clean_event}:{fps_hash}{REVIEW_MARKER_SUFFIX}"


def get_existing_reviews(
    owner: str,
    repository: str,
    pr_number: int,
    client: Optional[GitHubClient] = None,
    max_pages: int = DEFAULT_MAX_PAGINATION_PAGES,
    per_page: int = DEFAULT_PAGINATION_PER_PAGE
) -> List[Dict[str, Any]]:
    """
    Fetches existing PR reviews with bounded pagination to inspect CodeSentinel review markers.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_pr_num = validate_pr_number(pr_number)

    api_client = client or GitHubClient()
    endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}/reviews"
    reviews: List[Dict[str, Any]] = []
    page = 1

    try:
        while page <= max_pages:
            res = api_client.get(endpoint, params={"page": page, "per_page": per_page})
            if not isinstance(res, list) or not res:
                break
            for r in res:
                if isinstance(r, dict):
                    reviews.append(r)
            if len(res) < per_page:
                break
            page += 1
    except Exception:
        pass

    return reviews


def get_existing_inline_comment_fingerprints(
    owner: str,
    repository: str,
    pr_number: int,
    client: Optional[GitHubClient] = None,
    max_pages: int = DEFAULT_MAX_PAGINATION_PAGES,
    per_page: int = DEFAULT_PAGINATION_PER_PAGE
) -> Set[str]:
    """
    Fetches existing PR review comments and extracts published CodeSentinel finding fingerprints.
    Uses bounded pagination to handle large PRs reliably.
    Prevents duplicate inline comments on repeated webhook delivery.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_pr_num = validate_pr_number(pr_number)

    api_client = client or GitHubClient()
    existing_fps: Set[str] = set()
    endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}/comments"
    page = 1
    total_comments = 0
    max_comments = max_pages * per_page

    try:
        while page <= max_pages and total_comments < max_comments:
            comments_res = api_client.get(endpoint, params={"page": page, "per_page": per_page})
            if not isinstance(comments_res, list) or not comments_res:
                break
            for comment in comments_res:
                total_comments += 1
                if isinstance(comment, dict):
                    body = str(comment.get("body") or "")
                    if INLINE_COMMENT_MARKER_PREFIX in body:
                        parts = body.split(INLINE_COMMENT_MARKER_PREFIX)
                        for part in parts[1:]:
                            if INLINE_COMMENT_MARKER_SUFFIX in part:
                                fp = part.split(INLINE_COMMENT_MARKER_SUFFIX)[0].strip()
                                if fp:
                                    existing_fps.add(fp)
            if len(comments_res) < per_page:
                break
            page += 1
    except Exception:
        # Non-blocking: if comment inspection fails, return collected set safely
        pass

    return existing_fps


def post_pr_inline_review_comments(
    owner: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    report: Dict[str, Any],
    changed_files: List[Any],
    client: Optional[GitHubClient] = None,
    review_mode: Optional[str] = None
) -> Dict[str, Any]:
    """
    Publishes inline Pull Request review comments on modified code lines for valid findings.
    Enforces idempotency, diff-line bounds checking, review submission deduplication,
    and non-blocking error handling.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_pr_num = validate_pr_number(pr_number)
    clean_head_sha = validate_commit_sha(head_sha)

    eff_mode = get_effective_review_mode(review_mode)
    review_status = str(report.get("review_status", "allow")).strip().lower()
    review_event = map_review_status_to_review_event(review_status, review_mode=eff_mode)

    api_client = client or GitHubClient()

    # 1. Extract findings that map confidently to changed diff lines
    candidate_comments = extract_inline_commentable_findings(report, changed_files)
    all_candidate_fps = [c["fingerprint"] for c in candidate_comments]
    review_marker = generate_review_marker(clean_head_sha, review_status, review_event, all_candidate_fps)

    # 2. Check for duplicate review submission on this exact commit SHA and verdict/findings
    should_check_reviews = (eff_mode == "enforce")
    if should_check_reviews:

        try:
            existing_reviews = get_existing_reviews(clean_owner, clean_repo, clean_pr_num, client=api_client)
            for rev in existing_reviews:
                rev_body = str(rev.get("body") or "")
                if review_marker in rev_body:
                    return {
                        "status": "skipped",
                        "reason": "review_already_submitted",
                        "comments_count": 0,
                        "posted_findings": []
                    }
        except Exception:
            pass


    # 3. Handle cases where no diff-scoped findings exist
    if not candidate_comments:
        # In enforce mode, submit review (APPROVE or REQUEST_CHANGES) if verdict demands it
        if eff_mode == "enforce" and review_event in ("APPROVE", "REQUEST_CHANGES"):
            review_endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}/reviews"
            if review_event == "APPROVE":
                body_msg = "No blocking security vulnerabilities detected. Pull request approved by CodeSentinel."
            else:
                body_msg = "High or critical security vulnerabilities detected. Remediate findings before merging."
            review_body = f"{review_marker}\n## CodeSentinel Security Audit — {review_event}\n\n{body_msg}"
            batch_payload = {
                "commit_id": clean_head_sha,
                "event": review_event,
                "body": review_body,
                "comments": []
            }
            try:
                res = api_client.request("POST", review_endpoint, json_data=batch_payload)
                review_id = res.get("id") if isinstance(res, dict) else None
                return {
                    "status": "success",
                    "method": "batch_review",
                    "comments_count": 0,
                    "review_id": review_id,
                    "review_event": review_event,
                    "posted_findings": []
                }
            except (GitHubAuthenticationError, GitHubPermissionError, GitHubNotFoundError, GitHubRateLimitError) as gh_err:
                return {
                    "status": "skipped",
                    "reason": type(gh_err).__name__,
                    "comments_count": 0,
                    "posted_findings": []
                }
            except Exception as exc:
                return {
                    "status": "skipped",
                    "reason": f"review_submission_error_{type(exc).__name__}",
                    "comments_count": 0,
                    "posted_findings": []
                }

        return {
            "status": "skipped",
            "reason": "no_diff_scoped_findings",
            "comments_count": 0,
            "posted_findings": []
        }

    # 4. Query existing comments to prevent duplicates
    existing_fps = get_existing_inline_comment_fingerprints(
        owner=clean_owner,
        repository=clean_repo,
        pr_number=clean_pr_num,
        client=api_client
    )

    to_post = [c for c in candidate_comments if c["fingerprint"] not in existing_fps]
    if not to_post:
        return {
            "status": "skipped",
            "reason": "already_commented",
            "comments_count": 0,
            "posted_findings": []
        }

    # Deduplicate within to_post itself if multiple identical findings on same line
    unique_to_post: List[Dict[str, Any]] = []
    seen_fps: Set[str] = set()
    for c in to_post:
        if c["fingerprint"] not in seen_fps:
            seen_fps.add(c["fingerprint"])
            unique_to_post.append(c)

    # 5. Format review comments payload
    comments_payload = []
    for item in unique_to_post:
        comments_payload.append({
            "path": item["path"],
            "line": item["line"],
            "side": item["side"],
            "body": format_inline_finding_comment(item["finding"], item["fingerprint"])
        })

    # 6. Attempt batch review submission via Pull Request Reviews API
    review_endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}/reviews"
    review_body = (
        f"{review_marker}\n"
        "## CodeSentinel Security Audit — Inline Review Findings\n\n"
        "Security findings were identified on lines modified in this pull request. "
        "Please review the inline recommendations below."
    )
    batch_payload = {
        "commit_id": clean_head_sha,
        "event": review_event,
        "body": review_body,
        "comments": comments_payload
    }

    try:
        res = api_client.request("POST", review_endpoint, json_data=batch_payload)
        review_id = res.get("id") if isinstance(res, dict) else None
        return {
            "status": "success",
            "method": "batch_review",
            "comments_count": len(comments_payload),
            "review_id": review_id,
            "review_event": review_event,
            "posted_findings": [c["fingerprint"] for c in unique_to_post]
        }
    except (GitHubAuthenticationError, GitHubPermissionError, GitHubNotFoundError, GitHubRateLimitError) as gh_err:
        return {
            "status": "skipped",
            "reason": type(gh_err).__name__,
            "comments_count": 0,
            "posted_findings": []
        }
    except GitHubAPIError as api_err:
        # If batch review fails with 422 (e.g. line outside diff in GitHub's view),
        # attempt individual comment posting so valid lines still receive comments
        if api_err.status_code == 422:
            posted_count = 0
            posted_fps = []
            individual_endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}/comments"
            for item in unique_to_post:
                indiv_payload = {
                    "commit_id": clean_head_sha,
                    "path": item["path"],
                    "line": item["line"],
                    "side": item["side"],
                    "body": format_inline_finding_comment(item["finding"], item["fingerprint"])
                }
                try:
                    api_client.request("POST", individual_endpoint, json_data=indiv_payload)
                    posted_count += 1
                    posted_fps.append(item["fingerprint"])
                except Exception:
                    continue
            return {
                "status": "partial_success" if posted_count > 0 else "skipped",
                "method": "individual_fallback",
                "comments_count": posted_count,
                "posted_findings": posted_fps,
                "reason": "batch_422_individual_fallback"
            }
        else:
            return {
                "status": "skipped",
                "reason": f"github_api_error_{api_err.status_code}",
                "comments_count": 0,
                "posted_findings": []
            }
    except Exception as exc:
        return {
            "status": "skipped",
            "reason": f"unexpected_transport_error_{type(exc).__name__}",
            "comments_count": 0,
            "posted_findings": []
        }
