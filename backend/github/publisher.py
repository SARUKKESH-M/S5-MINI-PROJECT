"""
CodeSentinel — Step 6Q-C: GitHub Check Run & Commit Status Publisher

Publishes CodeSentinel Step 6O security decisions and finding summaries to GitHub
via GitHub Check Runs API and Commit Status API. Strictly preserves token secrecy
and enforces input validation.
"""

from typing import Any, Dict, Optional

try:
    from backend.github.client import GitHubClient
    from backend.github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_commit_sha,
        validate_pr_number
    )
except ImportError:
    from github.client import GitHubClient
    from github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_commit_sha,
        validate_pr_number
    )


CHECK_RUN_NAME = "CodeSentinel Security Analysis"
COMMIT_STATUS_CONTEXT = "codesentinel/security"

VALID_CHECK_STATUSES = {"queued", "in_progress", "completed"}
VALID_CHECK_CONCLUSIONS = {
    "action_required", "cancelled", "failure", "neutral",
    "success", "skipped", "stale", "timed_out"
}
VALID_COMMIT_STATES = {"error", "failure", "pending", "success"}

# CodeSentinel Step 6O Review Decision Mappings
DECISION_TO_CHECK_CONCLUSION = {
    "allow": "success",
    "block": "failure",
    "review": "action_required"
}

DECISION_TO_COMMIT_STATE = {
    "allow": "success",
    "block": "failure",
    "review": "pending"
}


def map_review_decision_to_check_conclusion(review_status: str) -> str:
    """Maps Step 6O review_status ('allow', 'block', 'review') to GitHub Check Run conclusion."""
    clean_status = str(review_status or "allow").strip().lower()
    if clean_status not in DECISION_TO_CHECK_CONCLUSION:
        raise ValueError(f"Invalid review_status decision: {review_status}")
    return DECISION_TO_CHECK_CONCLUSION[clean_status]


def map_review_decision_to_commit_state(review_status: str) -> str:
    """Maps Step 6O review_status ('allow', 'block', 'review') to GitHub Commit Status state."""
    clean_status = str(review_status or "allow").strip().lower()
    if clean_status not in DECISION_TO_COMMIT_STATE:
        raise ValueError(f"Invalid review_status decision: {review_status}")
    return DECISION_TO_COMMIT_STATE[clean_status]


def format_check_run_payload_from_report(
    report: Dict[str, Any],
    status: str = "completed"
) -> Dict[str, Any]:
    """
    Transforms a Step 6O Production Repository Report into a GitHub Check Run payload.

    Args:
        report: Valid Step 6O Production Report dictionary.
        status: Check Run status ('queued', 'in_progress', 'completed').

    Returns:
        Structured Check Run payload dictionary.
    """
    if not isinstance(report, dict):
        raise ValueError("Step 6O report must be a non-empty dictionary")

    clean_status = str(status or "completed").strip().lower()
    if clean_status not in VALID_CHECK_STATUSES:
        raise ValueError(f"Invalid Check Run status: {status}")

    review_status = str(report.get("review_status", "allow")).lower()
    conclusion = map_review_decision_to_check_conclusion(review_status) if clean_status == "completed" else None

    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    crit_count = int(summary.get("critical_count", 0))
    high_count = int(summary.get("high_count", 0))
    med_count = int(summary.get("medium_count", 0))
    low_count = int(summary.get("low_count", 0))
    info_count = int(summary.get("info_count", 0))
    total_findings = int(summary.get("total_findings", len(report.get("findings", []))))
    analyzed_files = int(summary.get("analyzed_files", 0))

    title_verdict = review_status.upper()
    title_text = f"CodeSentinel Security Audit: {title_verdict}"

    summary_text = (
        f"**Review Verdict**: `{review_status.upper()}`\n\n"
        f"**Telemetry Summary**:\n"
        f"- Analyzed Files: {analyzed_files}\n"
        f"- Total Findings: {total_findings}\n"
        f"- Critical: {crit_count}\n"
        f"- High: {high_count}\n"
        f"- Medium: {med_count}\n"
        f"- Low: {low_count}\n"
        f"- Info: {info_count}\n"
    )

    findings = report.get("findings", [])
    text_details = ""
    if findings and isinstance(findings, list):
        text_details = "### Finding Summary\n\n"
        for idx, f in enumerate(findings[:10], start=1):
            if isinstance(f, dict):
                f_id = f.get("finding_id", f"finding_{idx}")
                f_title = f.get("title", "Security Finding")
                f_sev = str(f.get("severity", "unknown")).upper()
                text_details += f"- **[{f_sev}]** `{f_id}`: {f_title}\n"
        if len(findings) > 10:
            text_details += f"\n*...and {len(findings) - 10} additional findings.*"

    payload = {
        "name": CHECK_RUN_NAME,
        "status": clean_status,
        "output": {
            "title": title_text,
            "summary": summary_text,
            "text": text_details
        }
    }

    if clean_status == "completed" and conclusion:
        payload["conclusion"] = conclusion

    return payload


def format_commit_status_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms a Step 6O Production Repository Report into a GitHub Commit Status payload.

    Args:
        report: Valid Step 6O Production Report dictionary.

    Returns:
        Structured Commit Status payload dictionary.
    """
    if not isinstance(report, dict):
        raise ValueError("Step 6O report must be a non-empty dictionary")

    review_status = str(report.get("review_status", "allow")).lower()
    state = map_review_decision_to_commit_state(review_status)

    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    crit_count = int(summary.get("critical_count", 0))
    high_count = int(summary.get("high_count", 0))
    med_count = int(summary.get("medium_count", 0))

    description = f"CodeSentinel: {review_status.upper()} ({crit_count} Critical, {high_count} High, {med_count} Medium)"
    if len(description) > 140:
        description = description[:137] + "..."

    return {
        "state": state,
        "context": COMMIT_STATUS_CONTEXT,
        "description": description
    }


def create_check_run(
    owner: str,
    repository: str,
    head_sha: str,
    name: str = CHECK_RUN_NAME,
    status: str = "queued",
    conclusion: Optional[str] = None,
    output: Optional[Dict[str, Any]] = None,
    client: Optional[GitHubClient] = None
) -> Dict[str, Any]:
    """
    Creates a new GitHub Check Run via REST API.

    Args:
        owner: Repository owner.
        repository: Repository name.
        head_sha: Head commit SHA (40-char hex).
        name: Check run display title.
        status: 'queued', 'in_progress', 'completed'.
        conclusion: 'success', 'failure', 'action_required', etc. (required if status == 'completed').
        output: Optional dict containing title, summary, text.
        client: Optional GitHubClient instance.

    Returns:
        GitHub API response dictionary.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_sha = validate_commit_sha(head_sha)

    clean_status = str(status or "queued").strip().lower()
    if clean_status not in VALID_CHECK_STATUSES:
        raise ValueError(f"Invalid Check Run status: {status}")

    payload: Dict[str, Any] = {
        "name": name or CHECK_RUN_NAME,
        "head_sha": clean_sha,
        "status": clean_status
    }

    if clean_status == "completed":
        if not conclusion:
            conclusion = "neutral"
        clean_conclusion = str(conclusion).strip().lower()
        if clean_conclusion not in VALID_CHECK_CONCLUSIONS:
            raise ValueError(f"Invalid Check Run conclusion: {conclusion}")
        payload["conclusion"] = clean_conclusion

    if output and isinstance(output, dict):
        payload["output"] = output

    api_client = client or GitHubClient()
    endpoint = f"/repos/{clean_owner}/{clean_repo}/check-runs"
    return api_client.request("POST", endpoint, json_data=payload)


def update_check_run(
    owner: str,
    repository: str,
    check_run_id: int,
    status: str = "completed",
    conclusion: Optional[str] = None,
    output: Optional[Dict[str, Any]] = None,
    client: Optional[GitHubClient] = None
) -> Dict[str, Any]:
    """
    Updates an existing GitHub Check Run via REST API.

    Args:
        owner: Repository owner.
        repository: Repository name.
        check_run_id: Positive integer Check Run ID.
        status: 'queued', 'in_progress', 'completed'.
        conclusion: 'success', 'failure', 'action_required', etc.
        output: Optional dict containing title, summary, text.
        client: Optional GitHubClient instance.

    Returns:
        GitHub API response dictionary.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_check_id = validate_pr_number(check_run_id)  # Reuses positive integer validator

    clean_status = str(status or "completed").strip().lower()
    if clean_status not in VALID_CHECK_STATUSES:
        raise ValueError(f"Invalid Check Run status: {status}")

    payload: Dict[str, Any] = {
        "status": clean_status
    }

    if clean_status == "completed":
        if not conclusion:
            conclusion = "neutral"
        clean_conclusion = str(conclusion).strip().lower()
        if clean_conclusion not in VALID_CHECK_CONCLUSIONS:
            raise ValueError(f"Invalid Check Run conclusion: {conclusion}")
        payload["conclusion"] = clean_conclusion

    if output and isinstance(output, dict):
        payload["output"] = output

    api_client = client or GitHubClient()
    endpoint = f"/repos/{clean_owner}/{clean_repo}/check-runs/{clean_check_id}"
    return api_client.request("PATCH", endpoint, json_data=payload)


def create_commit_status(
    owner: str,
    repository: str,
    head_sha: str,
    state: str,
    context: str = COMMIT_STATUS_CONTEXT,
    description: Optional[str] = None,
    target_url: Optional[str] = None,
    client: Optional[GitHubClient] = None
) -> Dict[str, Any]:
    """
    Creates a GitHub Commit Status entry via REST API.

    Args:
        owner: Repository owner.
        repository: Repository name.
        head_sha: Head commit SHA (40-char hex).
        state: 'error', 'failure', 'pending', 'success'.
        context: Status context name string (e.g. 'codesentinel/security').
        description: Concise summary message (max 140 chars).
        target_url: Optional details link.
        client: Optional GitHubClient instance.

    Returns:
        GitHub API response dictionary.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_sha = validate_commit_sha(head_sha)

    clean_state = str(state or "pending").strip().lower()
    if clean_state not in VALID_COMMIT_STATES:
        raise ValueError(f"Invalid Commit Status state: {state}")

    payload: Dict[str, Any] = {
        "state": clean_state,
        "context": context or COMMIT_STATUS_CONTEXT
    }

    if description:
        clean_desc = str(description).strip()
        if len(clean_desc) > 140:
            clean_desc = clean_desc[:137] + "..."
        payload["description"] = clean_desc

    if target_url and isinstance(target_url, str):
        payload["target_url"] = target_url.strip()

    api_client = client or GitHubClient()
    endpoint = f"/repos/{clean_owner}/{clean_repo}/statuses/{clean_sha}"
    return api_client.request("POST", endpoint, json_data=payload)


def publish_step_6o_report_status(
    owner: str,
    repository: str,
    head_sha: str,
    report: Dict[str, Any],
    check_run_id: Optional[int] = None,
    client: Optional[GitHubClient] = None
) -> Dict[str, Any]:
    """
    Publishes a Step 6O Production Report security decision to GitHub as both a Check Run and a Commit Status.

    Args:
        owner: Repository owner.
        repository: Repository name.
        head_sha: Head commit SHA (40-char hex).
        report: Step 6O Production Report dictionary.
        check_run_id: Optional existing Check Run ID to update instead of creating a new one.
        client: Optional GitHubClient instance.

    Returns:
        Dictionary containing published 'check_run' and 'commit_status' response data.
    """
    api_client = client or GitHubClient()

    check_payload = format_check_run_payload_from_report(report, status="completed")
    status_payload = format_commit_status_from_report(report)

    if check_run_id:
        check_res = update_check_run(
            owner=owner,
            repository=repository,
            check_run_id=check_run_id,
            status=check_payload["status"],
            conclusion=check_payload.get("conclusion"),
            output=check_payload.get("output"),
            client=api_client
        )
    else:
        check_res = create_check_run(
            owner=owner,
            repository=repository,
            head_sha=head_sha,
            name=check_payload["name"],
            status=check_payload["status"],
            conclusion=check_payload.get("conclusion"),
            output=check_payload.get("output"),
            client=api_client
        )

    commit_res = create_commit_status(
        owner=owner,
        repository=repository,
        head_sha=head_sha,
        state=status_payload["state"],
        context=status_payload["context"],
        description=status_payload["description"],
        client=api_client
    )

    return {
        "check_run": check_res,
        "commit_status": commit_res
    }
