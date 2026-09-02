"""
CodeSentinel — Step 6R-C Unit & Integration Test Suite

Tests CI Security Gate evaluation logic, validation rules, decision mapping
(ALLOW, REVIEW, BLOCK), CLI process exit codes, malformed report handling,
secret safety in gate outputs, and static non-execution boundary preservation.
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

from backend.analysis.security_gate import (
    validate_security_report,
    evaluate_security_gate,
    run_security_gate,
    main
)
from backend.analysis.security_scan import run_security_scan


def test_gate_allow_decision():
    """1. ALLOW decision when no critical, high, or medium findings exist."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_123",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 4,
            "info_count": 2
        }
    }

    is_valid, err, summary = validate_security_report(report)
    assert is_valid
    assert err == ""

    decision, exit_code, msg = evaluate_security_gate(report)
    assert decision == "ALLOW"
    assert exit_code == 0
    assert "PASSED" in msg


def test_gate_review_decision():
    """2. REVIEW decision when medium findings exist (and zero critical/high)."""
    report = {
        "status": "success",
        "review_status": "review",
        "analysis_id": "test_124",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 3,
            "low_count": 1,
            "info_count": 0
        }
    }

    decision, exit_code, msg = evaluate_security_gate(report)
    assert decision == "REVIEW"
    assert exit_code == 2
    assert "REQUIRES REVIEW" in msg


def test_gate_block_decision():
    """3. BLOCK decision when critical or high findings exist."""
    report = {
        "status": "success",
        "review_status": "block",
        "analysis_id": "test_125",
        "summary": {
            "critical_count": 1,
            "high_count": 2,
            "medium_count": 1,
            "low_count": 0,
            "info_count": 0
        }
    }

    decision, exit_code, msg = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1
    assert "FAILED" in msg


def test_critical_finding_causes_block():
    """4. Single critical finding causes BLOCK."""
    report = {
        "status": "completed",
        "review_status": "block",
        "analysis_id": "test_crit",
        "summary": {
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }

    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1


def test_high_finding_causes_block():
    """5. High finding (with zero critical) causes BLOCK."""
    report = {
        "status": "success",
        "review_status": "block",
        "analysis_id": "test_high",
        "summary": {
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }

    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1


def test_medium_only_findings_cause_review():
    """6. Medium-only findings cause REVIEW decision."""
    report = {
        "status": "success",
        "review_status": "review",
        "analysis_id": "test_med",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 5,
            "low_count": 10,
            "info_count": 2
        }
    }

    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "REVIEW"
    assert exit_code == 2


def test_no_medium_high_critical_causes_allow():
    """7. Low/info only findings cause ALLOW decision."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_low",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 12,
            "info_count": 5
        }
    }

    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "ALLOW"
    assert exit_code == 0


def test_negative_severity_count_rejected():
    """8. Negative severity counts cause validation failure."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_neg",
        "summary": {
            "critical_count": 0,
            "high_count": -1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }

    is_valid, err, _ = validate_security_report(report)
    assert not is_valid
    assert "cannot be negative" in err

    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "INVALID"
    assert exit_code == 1


def test_non_integer_severity_count_rejected():
    """9. Non-integer severity counts cause validation failure."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_str",
        "summary": {
            "critical_count": "one",
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }

    is_valid, err, _ = validate_security_report(report)
    assert not is_valid
    assert "must be an integer" in err

    report_bool = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_bool",
        "summary": {
            "critical_count": True,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }
    is_valid_b, err_b, _ = validate_security_report(report_bool)
    assert not is_valid_b
    assert "must be an integer" in err_b


def test_malformed_report_fails_closed(tmp_path):
    """10. Malformed or unparseable reports fail closed with non-zero exit code."""
    bad_file = tmp_path / "bad_report.json"
    bad_file.write_text("NOT_VALID_JSON{", encoding="utf-8")

    exit_code = run_security_gate(str(bad_file))
    assert exit_code != 0

    non_existent = tmp_path / "missing.json"
    exit_code_missing = run_security_gate(str(non_existent))
    assert exit_code_missing != 0


def test_cli_exit_code_for_allow(tmp_path):
    """11. CLI exit code for ALLOW decision is 0."""
    report_file = tmp_path / "allow_report.json"
    report_file.write_text(json.dumps({
        "status": "success",
        "review_status": "allow",
        "analysis_id": "cli_allow",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 1,
            "info_count": 0
        }
    }), encoding="utf-8")

    exit_code = run_security_gate(str(report_file))
    assert exit_code == 0


def test_cli_exit_code_for_review(tmp_path):
    """12. CLI exit code for REVIEW decision is non-zero (2)."""
    report_file = tmp_path / "review_report.json"
    report_file.write_text(json.dumps({
        "status": "success",
        "review_status": "review",
        "analysis_id": "cli_review",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 2,
            "low_count": 0,
            "info_count": 0
        }
    }), encoding="utf-8")

    exit_code = run_security_gate(str(report_file))
    assert exit_code == 2


def test_cli_exit_code_for_block(tmp_path):
    """13. CLI exit code for BLOCK decision is non-zero (1)."""
    report_file = tmp_path / "block_report.json"
    report_file.write_text(json.dumps({
        "status": "success",
        "review_status": "block",
        "analysis_id": "cli_block",
        "summary": {
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }), encoding="utf-8")

    exit_code = run_security_gate(str(report_file))
    assert exit_code == 1


def test_secret_values_never_appear_in_gate_output(capsys, tmp_path):
    """14. Gate output prints concise summaries and never prints raw tokens or secrets."""
    secret_token = "ghp_SECRET_TOKEN_DO_NOT_EXPOSE_123456"
    report_file = tmp_path / "secret_report.json"
    report_file.write_text(json.dumps({
        "status": "success",
        "review_status": "allow",
        "analysis_id": "secret_test",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        },
        "raw_secret": secret_token
    }), encoding="utf-8")

    run_security_gate(str(report_file))
    captured = capsys.readouterr()

    assert secret_token not in captured.out
    assert secret_token not in captured.err
    assert "Decision: ALLOW" in captured.out


def test_static_non_execution_boundary_remains_intact(tmp_path):
    """15. Evaluating the security gate on a report never executes target code."""
    sentinel_file = tmp_path / "executed_gate.txt"
    report_file = tmp_path / "gate_report.json"
    script = f"import pathlib; pathlib.Path('{sentinel_file.as_posix()}').write_text('EXECUTED')"

    report_file.write_text(json.dumps({
        "status": "success",
        "review_status": "allow",
        "analysis_id": "gate_exec_test",
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        },
        "malicious_script": script
    }), encoding="utf-8")

    run_security_gate(str(report_file))
    assert not sentinel_file.exists(), "Security gate execution boundary violated!"


def test_existing_step_6r_b_scan_remains_compatible(tmp_path):
    """16. Step 6R-B run_security_scan report output feeds cleanly into run_security_gate."""
    target_dir = tmp_path / "clean_repo"
    target_dir.mkdir()
    (target_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")

    report_file = tmp_path / "scan_output.json"
    scan_report = run_security_scan(target_dir=str(target_dir), output_path=str(report_file))

    assert report_file.exists()
    exit_code = run_security_gate(str(report_file))
    assert exit_code in (0, 1, 2)
    assert scan_report["review_status"] in ("allow", "review", "block")
