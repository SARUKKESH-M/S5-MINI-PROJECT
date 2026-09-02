"""
CodeSentinel — Step 6R-B: Automated Security Scan Entry Point

Invokes CodeSentinel's static security analysis pipeline on a target repository workspace
using Step 6L repository acquisition, Step 6M multi-file repository analysis, and
Step 6O production report formatting without executing target repository code.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from backend.repository.acquirer import acquire_repository
    from backend.analysis.repository_orchestrator import analyze_repository
    from backend.analysis.report_service import build_repository_report
except ImportError:
    from repository.acquirer import acquire_repository
    from analysis.repository_orchestrator import analyze_repository
    from analysis.report_service import build_repository_report


def run_security_scan(
    target_dir: str,
    output_path: Optional[str] = None,
    repository_url: str = "https://github.com/codesentinel/repo",
    branch: str = "main"
) -> Dict[str, Any]:
    """
    Executes a static security scan on target_dir using existing CodeSentinel pipeline.

    Args:
        target_dir: Path to target repository directory.
        output_path: Optional file path to save machine-readable report JSON.
        repository_url: Repository URL metadata (must be valid GitHub URL format).
        branch: Branch name metadata.

    Returns:
        Step 6O Production Security Report dictionary.

    Raises:
        ValueError: If target_dir does not exist or is invalid.
    """
    if not target_dir or not isinstance(target_dir, str):
        raise ValueError("Target repository directory path must be a non-empty string")

    target_path = Path(target_dir).resolve()
    if not target_path.exists() or not target_path.is_dir():
        raise ValueError(f"Target repository directory does not exist or is not a directory: {target_dir}")

    # 1. Acquire repository locally into isolated workspace
    acq_meta = acquire_repository(
        repository_url=repository_url,
        branch=branch,
        local_path=str(target_path)
    )

    acq_info = acq_meta.get("acquisition", {})
    acquisition_id = acq_meta.get("acquisition_id") or acq_info.get("acquisition_id")
    if not acquisition_id:
        raise ValueError("Failed to obtain acquisition_id from workspace acquisition metadata")

    # 2. Run repository security analysis orchestrator
    report = analyze_repository(
        acquisition_id=acquisition_id,
        query="security analysis"
    )

    # 3. Ensure report complies with Step 6O contract
    report = build_repository_report(report)

    # 4. Save to output file if requested
    if output_path:
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report


def main() -> int:
    """CLI entry point for running security scan."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeSentinel Static Security Scan")
    parser.add_argument(
        "--target-dir",
        default=".",
        help="Path to repository directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--output",
        default="security-report.json",
        help="Path to output report JSON file (default: security-report.json)"
    )

    args = parser.parse_args()

    try:
        report = run_security_scan(
            target_dir=args.target_dir,
            output_path=args.output
        )
        review_status = report.get("review_status", "allow")
        summary = report.get("summary", {})
        print(f"CodeSentinel Security Scan Complete.")
        print(f"Status: {report.get('status')}")
        print(f"Review Decision: {review_status}")
        print(
            f"Findings: Total={summary.get('total_findings', 0)}, "
            f"Critical={summary.get('critical_count', 0)}, "
            f"High={summary.get('high_count', 0)}, "
            f"Medium={summary.get('medium_count', 0)}, "
            f"Low={summary.get('low_count', 0)}"
        )
        print(f"Report saved to: {args.output}")
        return 0
    except Exception as e:
        print(f"Security Scan Failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
