"""
CodeSentinel — CLI Output Formatter

Provides clean human-friendly terminal formatting, secret redaction,
and JSON/Markdown output formatting for the CodeSentinel CLI.
"""

import json
from typing import Any, Dict, Optional

try:
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    def sanitize_sensitive_text(val: str) -> str:
        return val


def format_terminal_header(title: str) -> str:
    """Formats a clean terminal header box."""
    line = "-" * min(60, max(30, len(title) + 10))
    return f"\n{title}\n{line}"


def format_security_report_terminal(report: Dict[str, Any]) -> str:
    """Formats a Step 6O report dictionary into human-friendly terminal text."""
    if not isinstance(report, dict):
        return "Invalid report format."

    status = report.get("status", "unknown").upper()
    rev_status = str(report.get("review_status", "allow")).upper()

    repo = report.get("repository", {})
    repo_name = repo.get("repository", "Target Repository") if isinstance(repo, dict) else "Target Repository"

    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    crit = summary.get("critical_count", 0)
    high = summary.get("high_count", 0)
    med = summary.get("medium_count", 0)
    low = summary.get("low_count", 0)
    info = summary.get("info_count", 0)
    total = summary.get("total_findings", 0)

    lines = [
        format_terminal_header(f"CodeSentinel Security Analysis — {repo_name}"),
        f"Status:          {status}",
        f"Security Gate:   {rev_status}",
        "",
        "Severity Summary:",
        f"  Critical:  {crit}",
        f"  High:      {high}",
        f"  Medium:    {med}",
        f"  Low:       {low}",
        f"  Info:      {info}",
        f"  Total:     {total}",
    ]

    findings = report.get("findings", [])
    if isinstance(findings, list) and findings:
        lines.append("\nTop Findings:")
        for idx, f in enumerate(findings[:5], 1):
            if isinstance(f, dict):
                sev = str(f.get("severity", "INFO")).upper()
                rule = f.get("rule_id", "rule")
                msg = f.get("message", f.get("description", ""))
                lines.append(f"  {idx}. [{sev}] {rule}: {msg}")

    result_text = "\n".join(lines)
    return sanitize_sensitive_text(result_text)


def format_json_output(data: Any, indent: int = 2) -> str:
    """Formats data as indented JSON with secret redaction."""
    try:
        raw_json = json.dumps(data, indent=indent, default=str)
        return sanitize_sensitive_text(raw_json)
    except Exception as e:
        return json.dumps({"error": f"Failed to format JSON: {e}"})
