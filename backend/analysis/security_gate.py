"""
CodeSentinel — Step 6R-C: CI Security Gate / Automated Decision Enforcement

Validates Step 6O Production Security Reports, evaluates severity metrics against
deterministic security policies ('allow', 'review', 'block'), and enforces fail-closed
CI pipeline results.
"""

import json
import os
import sys
from typing import Any, Dict, Tuple


def validate_security_report(report: Any) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validates the structure, types, and constraints of a Step 6O Production Security Report.

    Returns:
        Tuple of (is_valid: bool, error_message: str, validated_summary: dict)
    """
    if not isinstance(report, dict):
        return False, "Report is not a valid JSON dictionary object", {}

    status = report.get("status")
    if status not in ("success", "completed"):
        return False, f"Report status is invalid or failed: {status}", {}

    review_status = report.get("review_status")
    if review_status not in ("allow", "review", "block"):
        return False, f"Report review_status is invalid: {review_status}", {}

    summary = report.get("summary")
    if not isinstance(summary, dict):
        return False, "Report missing valid summary dictionary", {}

    severity_keys = ["critical_count", "high_count", "medium_count", "low_count", "info_count"]
    clean_summary = {}

    for k in severity_keys:
        val = summary.get(k)
        if val is None:
            return False, f"Missing required severity count: {k}", {}
        if isinstance(val, bool) or not isinstance(val, int):
            return False, f"Severity count '{k}' must be an integer, got {type(val).__name__}", {}
        if val < 0:
            return False, f"Severity count '{k}' cannot be negative: {val}", {}
        clean_summary[k] = val

    return True, "", clean_summary


def evaluate_security_gate(report: Dict[str, Any]) -> Tuple[str, int, str]:
    """
    Evaluates a security report against CodeSentinel security gate policies.

    Rules:
    - Malformed report -> ("INVALID", 1, "Security gate error: Malformed report")
    - CRITICAL > 0 or HIGH > 0 -> ("BLOCK", 1, "Security gate failed: Critical/High vulnerabilities detected")
    - MEDIUM > 0 (and CRITICAL=0, HIGH=0) -> ("REVIEW", 2, "Security gate requires review: Medium severity findings detected")
    - No CRITICAL/HIGH/MEDIUM -> ("ALLOW", 0, "Security gate passed: No critical, high, or medium findings")

    Returns:
        Tuple of (decision: str, exit_code: int, message: str)
    """
    is_valid, err_msg, summary = validate_security_report(report)
    if not is_valid:
        return "INVALID", 1, f"SECURITY GATE FAILED (MALFORMED REPORT): {err_msg}"

    critical = summary["critical_count"]
    high = summary["high_count"]
    medium = summary["medium_count"]

    reported_review_status = report.get("review_status")

    if critical > 0 or high > 0:
        decision = "BLOCK"
        exit_code = 1
        msg = f"SECURITY GATE FAILED (BLOCK): {critical} critical, {high} high severity findings detected."
    elif medium > 0:
        decision = "REVIEW"
        exit_code = 2
        msg = f"SECURITY GATE REQUIRES REVIEW (REVIEW): {medium} medium severity findings detected."
    else:
        decision = "ALLOW"
        exit_code = 0
        msg = "SECURITY GATE PASSED (ALLOW): No critical, high, or medium security findings."

    # Fail closed if declared review_status contradicts severity counts
    if reported_review_status != decision.lower():
        return "INVALID", 1, f"SECURITY GATE FAILED: Declared review_status '{reported_review_status}' contradicts computed decision '{decision.lower()}'"

    return decision, exit_code, msg


def run_security_gate(report_path: str) -> int:
    """
    Loads report from report_path, evaluates the gate, prints human-readable status, and returns process exit code.
    """
    if not report_path or not isinstance(report_path, str):
        print("SECURITY GATE FAILED: Invalid report file path", file=sys.stderr)
        return 1

    if not os.path.exists(report_path):
        print(f"SECURITY GATE FAILED: Report file not found at path: {report_path}", file=sys.stderr)
        return 1

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        print(f"SECURITY GATE FAILED: Unparseable report JSON: {e}", file=sys.stderr)
        return 1

    decision, exit_code, msg = evaluate_security_gate(report)

    summary = report.get("summary", {}) if isinstance(report, dict) and isinstance(report.get("summary"), dict) else {}

    print("\nCodeSentinel Security Gate")
    print("--------------------------")
    print(f"Decision: {decision}")
    print(f"Critical: {summary.get('critical_count', 'N/A')}")
    print(f"High:     {summary.get('high_count', 'N/A')}")
    print(f"Medium:   {summary.get('medium_count', 'N/A')}")
    print(f"Low:      {summary.get('low_count', 'N/A')}")
    print(f"Info:     {summary.get('info_count', 'N/A')}")
    print("--------------------------")
    print(msg)
    print()

    return exit_code


def main() -> int:
    """CLI entry point for running security gate evaluation."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeSentinel Security Gate Evaluator")
    parser.add_argument(
        "--report",
        default="security-report.json",
        help="Path to Step 6O security report JSON file (default: security-report.json)"
    )

    args = parser.parse_args()
    return run_security_gate(args.report)


if __name__ == "__main__":
    sys.exit(main())
