"""
CodeSentinel — Step 6Q Slack Notification Client & Payload Builder

Provides a secure, minimal, and fully isolated Slack Incoming Webhook adapter.
Strictly decoupled from deterministic security analysis, findings generation,
and security gate decisions.
"""

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional
import httpx

try:
    from backend.app.core.config import settings
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    try:
        from app.core.config import settings
    except ImportError:
        settings = None  # type: ignore

    try:
        from app.core.security import sanitize_sensitive_text
    except ImportError:
        TOKEN_LITERAL_REGEX = re.compile(
            r"(ghp_[a-zA-Z0-9_]{16,255}|gho_[a-zA-Z0-9_]{16,255}|github_pat_[a-zA-Z0-9_]{16,255}|gsk_[a-zA-Z0-9_]{16,255}|bearer\s+[a-zA-Z0-9._\-]+|secret_[a-zA-Z0-9_]{4,})",
            re.IGNORECASE,
        )

        def sanitize_sensitive_text(text: str) -> str:
            if not text or not isinstance(text, str):
                return ""
            return TOKEN_LITERAL_REGEX.sub("[REDACTED_SECRET]", text)


logger = logging.getLogger("codesentinel.notifications.slack")

# Slack text block length boundaries
MAX_PR_TITLE_LENGTH = 120
MAX_SUMMARY_LENGTH = 500
MAX_FINDINGS_TEXT_LENGTH = 1000
MAX_FINDING_TITLE_LENGTH = 100
MAX_FILE_PATH_LENGTH = 100
MAX_AUTHOR_LENGTH = 80
MAX_TOP_FINDINGS_COUNT = 5

# Canonical Step 6O Security Gate Visuals
GATE_VISUAL_MAP = {
    "block": {
        "icon": "🔴",
        "color": "#E01E5A",
        "label": "BLOCKED",
        "button_style": "danger",
        "action_text": "High or critical severity security vulnerabilities detected.",
    },
    "review": {
        "icon": "🟡",
        "color": "#ECB22E",
        "label": "REVIEW REQUIRED",
        "button_style": "default",
        "action_text": "Manual security review required before merging.",
    },
    "allow": {
        "icon": "✅",
        "color": "#2EB67D",
        "label": "PASSED",
        "button_style": "primary",
        "action_text": "No blocking security vulnerabilities detected.",
    },
}

DEFAULT_GATE_VISUAL = {
    "icon": "⚪",
    "color": "#808080",
    "label": "UNKNOWN",
    "button_style": "default",
    "action_text": "Security analysis completed.",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}


def escape_slack_mrkdwn(text: str) -> str:
    """
    Escapes Slack-sensitive characters (&, <, >) in dynamic text fields
    to prevent syntax collisions, broken blocks, or injection in Slack mrkdwn.
    """
    if not text or not isinstance(text, str):
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _truncate_clean(text: str, max_length: int) -> str:
    """Truncates text safely and appends an ellipsis if exceeded."""
    if not text or len(text) <= max_length:
        return text or ""
    return text[: max_length - 3] + "..."


def validate_slack_webhook_url(url: Optional[str]) -> bool:
    """
    Validates that the provided webhook URL uses https:// and is non-empty.
    Rejects insecure schemes, whitespace, and arbitrary protocols.
    """
    if not url or not isinstance(url, str):
        return False
    clean = url.strip()
    if not clean:
        return False
    if not clean.lower().startswith("https://"):
        return False
    if any(c in clean for c in ["\r", "\n", " ", "\t"]):
        return False
    return True


def build_slack_pr_payload(
    report: Dict[str, Any],
    pr_number: int,
    pr_title: str,
    pr_author: str,
    repo_full_name: str,
    pr_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Builds a bounded, sanitized Slack Block Kit payload from a Step 6O Production Report.
    Ensures secrets are redacted, dynamic characters escaped, and sizes bounded.
    """
    if not isinstance(report, dict):
        report = {}

    review_status = str(report.get("review_status", "allow")).strip().lower()
    vis = GATE_VISUAL_MAP.get(review_status, DEFAULT_GATE_VISUAL)

    # Sanitize and escape dynamic PR metadata
    clean_title = escape_slack_mrkdwn(
        sanitize_sensitive_text(_truncate_clean(pr_title, MAX_PR_TITLE_LENGTH))
    )
    clean_author = escape_slack_mrkdwn(
        sanitize_sensitive_text(_truncate_clean(pr_author, MAX_AUTHOR_LENGTH))
    )
    clean_repo = escape_slack_mrkdwn(
        sanitize_sensitive_text(_truncate_clean(repo_full_name, 100))
    )
    clean_action = escape_slack_mrkdwn(vis["action_text"])

    # Extract summary metrics
    raw_summary = report.get("summary", {})
    if not isinstance(raw_summary, dict):
        raw_summary = {}

    total_findings = int(raw_summary.get("total_findings", 0))
    crit_count = int(raw_summary.get("critical_count", 0))
    high_count = int(raw_summary.get("high_count", 0))
    med_count = int(raw_summary.get("medium_count", 0))
    low_count = int(raw_summary.get("low_count", 0))

    # Format top findings (up to MAX_TOP_FINDINGS_COUNT)
    raw_findings = report.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []

    finding_lines: List[str] = []
    for f in raw_findings[:MAX_TOP_FINDINGS_COUNT]:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "low")).strip().lower()
        f_icon = SEVERITY_ICONS.get(sev, "⚪")
        raw_title = str(f.get("title") or f.get("type") or "Security Finding")
        f_title = escape_slack_mrkdwn(
            sanitize_sensitive_text(_truncate_clean(raw_title, MAX_FINDING_TITLE_LENGTH))
        )

        # Extract file location from evidence if available
        evidence = f.get("evidence", [])
        loc_str = "workspace"
        if isinstance(evidence, list) and len(evidence) > 0 and isinstance(evidence[0], dict):
            doc_id = str(evidence[0].get("document_id", ""))
            line_s = evidence[0].get("line_start", "?")
            if doc_id:
                clean_doc = escape_slack_mrkdwn(
                    sanitize_sensitive_text(_truncate_clean(doc_id, MAX_FILE_PATH_LENGTH))
                )
                loc_str = f"{clean_doc}:{line_s}"

        cwe = str(f.get("cwe_id", "")).strip()
        cwe_part = f" (`{escape_slack_mrkdwn(cwe)}`)" if cwe else ""

        finding_lines.append(f"• {f_icon} *{f_title}*{cwe_part} — `{loc_str}`")

    if len(raw_findings) > MAX_TOP_FINDINGS_COUNT:
        overflow_count = len(raw_findings) - MAX_TOP_FINDINGS_COUNT
        finding_lines.append(f"• ... and {overflow_count} more findings")

    findings_text = "\n".join(finding_lines) if finding_lines else "✅ No vulnerabilities detected"
    if len(findings_text) > MAX_FINDINGS_TEXT_LENGTH:
        findings_text = findings_text[: MAX_FINDINGS_TEXT_LENGTH - 15] + "\n• ... [truncated]"

    # Fallback text
    fallback_text = (
        f"{vis['icon']} CodeSentinel Security Gate: {vis['label']} — PR #{pr_number} ({clean_repo})"
    )

    # Construct Block Kit blocks
    blocks: List[Dict[str, Any]] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*CodeSentinel Security Gate: {vis['label']}* {vis['icon']}\n"
                    f"*Repository:* `{clean_repo}`\n"
                    f"*PR #{pr_number}:* {clean_title}\n"
                    f"*Author:* {clean_author}\n"
                    f"*Decision:* {clean_action}"
                ),
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Findings:*\n{total_findings}",
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Severities:*\n"
                        f"🔴 {crit_count} Crit  🟠 {high_count} High  🟡 {med_count} Med  🟢 {low_count} Low"
                    ),
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Findings Summary:*\n{findings_text}",
            },
        },
    ]

    # Provenance context block
    analysis_id = str(report.get("analysis_id", ""))
    if analysis_id:
        clean_aid = escape_slack_mrkdwn(sanitize_sensitive_text(analysis_id))
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🛡️ Analysis ID: `{clean_aid}` | Engine: Deterministic AST",
                    }
                ],
            }
        )

    # Optional Action Button (only if valid https:// PR URL is provided)
    if pr_url and isinstance(pr_url, str) and pr_url.strip().lower().startswith("https://"):
        clean_url = pr_url.strip()
        btn_element: Dict[str, Any] = {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "View Pull Request",
                "emoji": True,
            },
            "url": clean_url,
        }
        if vis["button_style"] != "default":
            btn_element["style"] = vis["button_style"]

        blocks.append(
            {
                "type": "actions",
                "elements": [btn_element],
            }
        )

    return {
        "text": fallback_text,
        "attachments": [
            {
                "color": vis["color"],
                "blocks": blocks,
            }
        ],
    }


async def send_slack_pr_alert(
    report: Dict[str, Any],
    pr_number: int,
    pr_title: str,
    pr_author: str,
    repo_full_name: str,
    pr_url: Optional[str] = None,
    webhook_url: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    Asynchronously sends an automated, sanitized Slack notification for a PR security report.
    Guarantees isolation: never raises exceptions into the caller pipeline.
    """
    target_url = webhook_url
    if target_url is None and settings is not None:
        target_url = getattr(settings, "SLACK_WEBHOOK_URL", None)

    if not target_url or not isinstance(target_url, str) or not target_url.strip():
        return {
            "status": "skipped",
            "reason": "webhook_not_configured",
        }

    target_url = target_url.strip()

    if not validate_slack_webhook_url(target_url):
        logger.warning("Slack notification skipped: invalid webhook URL configuration.")
        return {
            "status": "failed",
            "reason": "invalid_webhook_url",
        }

    try:
        payload = build_slack_pr_payload(
            report=report,
            pr_number=pr_number,
            pr_title=pr_title,
            pr_author=pr_author,
            repo_full_name=repo_full_name,
            pr_url=pr_url,
        )
    except Exception as build_err:
        logger.error("Failed to build Slack payload: %s", str(build_err))
        return {
            "status": "failed",
            "reason": "payload_construction_error",
        }

    async def _post_payload(http_client: httpx.AsyncClient) -> Dict[str, Any]:
        retries_remaining = 1
        while True:
            try:
                res = await http_client.post(
                    target_url,
                    json=payload,
                    timeout=timeout,
                )
                if res.status_code == 200:
                    return {
                        "status": "delivered",
                        "status_code": 200,
                    }

                if res.status_code == 429 and retries_remaining > 0:
                    retries_remaining -= 1
                    retry_after = 0.5
                    raw_after = res.headers.get("Retry-After")
                    if raw_after:
                        try:
                            retry_after = min(float(raw_after), 2.0)
                        except (ValueError, TypeError):
                            retry_after = 0.5
                    await asyncio.sleep(retry_after)
                    continue

                if res.status_code in (500, 502, 503, 504) and retries_remaining > 0:
                    retries_remaining -= 1
                    await asyncio.sleep(0.5)
                    continue

                logger.warning("Slack notification rejected with HTTP %d", res.status_code)
                return {
                    "status": "failed",
                    "status_code": res.status_code,
                    "reason": f"http_{res.status_code}",
                }

            except httpx.TimeoutException:
                logger.warning("Slack notification timed out after %.1fs", timeout)
                return {
                    "status": "failed",
                    "reason": "timeout",
                }
            except httpx.ConnectError:
                logger.warning("Slack notification connection failed")
                return {
                    "status": "failed",
                    "reason": "connection_error",
                }
            except httpx.RequestError as req_err:
                logger.warning("Slack notification request error: %s", type(req_err).__name__)
                return {
                    "status": "failed",
                    "reason": "request_error",
                }
            except Exception as e:
                logger.error("Unexpected error delivering Slack alert: %s", type(e).__name__)
                return {
                    "status": "failed",
                    "reason": "unexpected_error",
                }

    try:
        if client is not None:
            return await _post_payload(client)
        else:
            async with httpx.AsyncClient() as new_client:
                return await _post_payload(new_client)
    except Exception as outer_err:
        logger.error("Slack client execution error: %s", type(outer_err).__name__)
        return {
            "status": "failed",
            "reason": "client_error",
        }


def send_slack_pr_alert_sync(
    report: Dict[str, Any],
    pr_number: int,
    pr_title: str,
    pr_author: str,
    repo_full_name: str,
    pr_url: Optional[str] = None,
    webhook_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    Synchronous version of send_slack_pr_alert for synchronous webhook orchestration.
    Guarantees isolation: never raises exceptions into the caller pipeline.
    """
    target_url = webhook_url
    if target_url is None and settings is not None:
        target_url = getattr(settings, "SLACK_WEBHOOK_URL", None)

    if not target_url or not isinstance(target_url, str) or not target_url.strip():
        return {
            "status": "skipped",
            "reason": "webhook_not_configured",
        }

    target_url = target_url.strip()

    if not validate_slack_webhook_url(target_url):
        logger.warning("Slack notification skipped: invalid webhook URL configuration.")
        return {
            "status": "failed",
            "reason": "invalid_webhook_url",
        }

    try:
        payload = build_slack_pr_payload(
            report=report,
            pr_number=pr_number,
            pr_title=pr_title,
            pr_author=pr_author,
            repo_full_name=repo_full_name,
            pr_url=pr_url,
        )
    except Exception as build_err:
        logger.error("Failed to build Slack payload: %s", str(build_err))
        return {
            "status": "failed",
            "reason": "payload_construction_error",
        }

    def _post_payload_sync(http_client: httpx.Client) -> Dict[str, Any]:
        retries_remaining = 1
        while True:
            try:
                res = http_client.post(
                    target_url,
                    json=payload,
                    timeout=timeout,
                )
                if res.status_code == 200:
                    return {
                        "status": "delivered",
                        "status_code": 200,
                    }

                if res.status_code == 429 and retries_remaining > 0:
                    retries_remaining -= 1
                    retry_after = 0.5
                    raw_after = res.headers.get("Retry-After")
                    if raw_after:
                        try:
                            retry_after = min(float(raw_after), 2.0)
                        except (ValueError, TypeError):
                            retry_after = 0.5
                    time.sleep(retry_after)
                    continue

                if res.status_code in (500, 502, 503, 504) and retries_remaining > 0:
                    retries_remaining -= 1
                    time.sleep(0.5)
                    continue

                logger.warning("Slack notification rejected with HTTP %d", res.status_code)
                return {
                    "status": "failed",
                    "status_code": res.status_code,
                    "reason": f"http_{res.status_code}",
                }

            except httpx.TimeoutException:
                logger.warning("Slack notification timed out after %.1fs", timeout)
                return {
                    "status": "failed",
                    "reason": "timeout",
                }
            except httpx.ConnectError:
                logger.warning("Slack notification connection failed")
                return {
                    "status": "failed",
                    "reason": "connection_error",
                }
            except httpx.RequestError as req_err:
                logger.warning("Slack notification request error: %s", type(req_err).__name__)
                return {
                    "status": "failed",
                    "reason": "request_error",
                }
            except Exception as e:
                logger.error("Unexpected error delivering Slack alert: %s", type(e).__name__)
                return {
                    "status": "failed",
                    "reason": "unexpected_error",
                }

    try:
        if client is not None:
            return _post_payload_sync(client)
        else:
            with httpx.Client() as new_client:
                return _post_payload_sync(new_client)
    except Exception as outer_err:
        logger.error("Slack client execution error: %s", type(outer_err).__name__)
        return {
            "status": "failed",
            "reason": "client_error",
        }
