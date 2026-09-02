"""
CodeSentinel — Step 6R-B Unit & Integration Test Suite

Tests Automated Security Scan Entrypoint, Step 6O Report Contract Adherence,
Decision Mapping (allow, review, block), Secret Safety, Malformed Output Handling,
Path Traversal Defense, and Static Non-Execution Boundary.
"""

import json
import os
import sys
import tempfile
import pytest
from pathlib import Path

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.security_scan import run_security_scan, main
from backend.analysis.report_service import compute_review_status, build_repository_report


def test_security_scan_entry_point_with_clean_repo(tmp_path):
    """Verifies that run_security_scan successfully executes on a clean local directory."""
    target_dir = tmp_path / "test_repo"
    target_dir.mkdir()
    sample_file = target_dir / "app.py"
    sample_file.write_text("def hello(): return 'world'\n", encoding="utf-8")

    output_report_file = tmp_path / "output_report.json"

    report = run_security_scan(
        target_dir=str(target_dir),
        output_path=str(output_report_file)
    )

    assert isinstance(report, dict)
    assert report.get("status") in ("success", "completed")
    assert "review_status" in report
    assert report["review_status"] in ("allow", "review", "block")
    assert "summary" in report
    assert "findings" in report
    assert "analysis_id" in report
    assert output_report_file.exists()

    with open(output_report_file, "r", encoding="utf-8") as f:
        saved_report = json.load(f)
    assert saved_report["analysis_id"] == report["analysis_id"]


def test_review_status_decision_mapping():
    """Verifies automated decision rules for allow, review, and block."""
    # Allow cases
    assert compute_review_status({"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 5}) == "allow"
    assert compute_review_status({"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0}) == "allow"

    # Review case
    assert compute_review_status({"critical_count": 0, "high_count": 0, "medium_count": 2, "low_count": 1}) == "review"

    # Block cases
    assert compute_review_status({"critical_count": 1, "high_count": 0, "medium_count": 0}) == "block"
    assert compute_review_status({"critical_count": 0, "high_count": 3, "medium_count": 1}) == "block"
    assert compute_review_status({"critical_count": 2, "high_count": 1, "medium_count": 5}) == "block"


def test_report_contract_secret_exclusion_and_forbidden_fields():
    """Verifies that secrets and forbidden fields are stripped from the scan report."""
    raw_record = {
        "status": "success",
        "analysis_id": "test_ana_123",
        "repository": {"owner": "test", "repository": "repo"},
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 1,
            "total_findings": 1
        },
        "findings": [
            {
                "finding_id": "f_1",
                "title": "Possible API Key THIS_SECRET_MUST_NOT_APPEAR Exposed",
                "description": "Found bearer token in file",
                "severity": "low",
                "confidence": "high",
                "category": "Secret Exposure",
                "secret_key": "SUPER_SECRET",
                "raw_code": "SECRET_TOKEN = '12345'",
                "prompt": "Analyze this code"
            }
        ]
    }

    report = build_repository_report(raw_record)

    assert report["review_status"] == "allow"
    finding = report["findings"][0]
    assert "secret_key" not in finding
    assert "raw_code" not in finding
    assert "prompt" not in finding
    assert "THIS_SECRET_MUST_NOT_APPEAR" not in finding["title"]
    assert "[REDACTED_SECRET]" in finding["title"]


def test_static_non_execution_boundary(tmp_path):
    """Verifies that analyzing a repository never executes any executable scripts/code inside it."""
    target_dir = tmp_path / "untrusted_repo"
    target_dir.mkdir()

    sentinel_file = target_dir / "executed.txt"
    script_file = target_dir / "malicious.py"
    script_file.write_text(
        f"import pathlib\npathlib.Path('{sentinel_file.as_posix()}').write_text('EXECUTED!')\n",
        encoding="utf-8"
    )

    run_security_scan(target_dir=str(target_dir))

    # Verify sentinel file was NEVER created
    assert not sentinel_file.exists(), "Code execution boundary violated! Target repository script was executed."


def test_invalid_and_untrusted_target_paths():
    """Verifies proper error handling for non-existent and invalid target paths."""
    with pytest.raises(ValueError):
        run_security_scan(target_dir="")

    with pytest.raises(ValueError, match="does not exist"):
        run_security_scan(target_dir="/non/existent/path/codesentinel_xyz_123")


def test_malformed_analysis_record_handling():
    """Verifies build_repository_report handles malformed or incomplete analysis records gracefully."""
    with pytest.raises(ValueError):
        build_repository_report(None)

    with pytest.raises(ValueError):
        build_repository_report({})

    malformed_record = {
        "status": "unknown",
        "analysis_id": "malformed_123",
        "summary": "not_a_dict",
        "findings": "not_a_list"
    }

    report = build_repository_report(malformed_record)
    assert report["status"] == "failed"
    assert report["summary"]["total_findings"] == 0
    assert report["findings"] == []
