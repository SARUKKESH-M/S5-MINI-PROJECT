"""
CodeSentinel — Step 6Q Notifications Package

Provides external alerting adapters (e.g., Slack Incoming Webhooks)
strictly decoupled from deterministic security analysis and security gate decisions.
"""

try:
    from backend.notifications.slack import (
        escape_slack_mrkdwn,
        validate_slack_webhook_url,
        build_slack_pr_payload,
        send_slack_pr_alert,
        send_slack_pr_alert_sync,
    )
except ImportError:
    from notifications.slack import (
        escape_slack_mrkdwn,
        validate_slack_webhook_url,
        build_slack_pr_payload,
        send_slack_pr_alert,
        send_slack_pr_alert_sync,
    )

__all__ = [
    "escape_slack_mrkdwn",
    "validate_slack_webhook_url",
    "build_slack_pr_payload",
    "send_slack_pr_alert",
    "send_slack_pr_alert_sync",
]
