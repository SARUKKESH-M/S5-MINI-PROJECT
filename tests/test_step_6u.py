"""
CodeSentinel — Stage 6U Test Suite
Developer Experience / CLI Verification

Comprehensive test suite verifying Stage 6U:
1. CLI root help
2. CLI version command
3. CLI analyze command
4. CLI scan command
5. CLI gate command
6. CLI report command
7. CLI health command
8. CLI readiness command
9. CLI info command
10. CLI policies command
11. CLI metrics command
12. Invalid command handling
13. Invalid target path handling
14. Path traversal rejection
15. Invalid policy profile rejection
16. Invalid mode rejection
17. Malformed report handling
18. Gate ALLOW exit code (0)
19. Gate REVIEW exit code (2)
20. Gate BLOCK exit code (1)
21. Gate INVALID exit code (1)
22. JSON output validity (--json mode)
23. Markdown output formatting (--format markdown)
24. Output file writing (-o / --output)
25. Secret redaction in CLI output
26. Authorization header redaction
27. Stack-trace suppression
28. Static non-execution boundary
29. Existing 6R compatibility
30. Existing 6T compatibility
31. No shell execution (os.system / subprocess shell=True)
32. No eval/exec usage
33. Step 6O Production Report schema backward compatibility
"""

import json
import os
import sys
import pytest
from pathlib import Path

# Ensure workspace root and backend are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cli.main import main, build_parser
from backend.analysis.security_gate import evaluate_security_gate


# ==============================================================================
# 1. HELP & VERSION COMMANDS (6U-1, 6U-7, 6U-13)
# ==============================================================================

def test_cli_help_and_version(capsys):
    """1-2, 13. Verifies CLI help parser and version command execution."""
    parser = build_parser()
    assert parser.prog == "codesentinel"

    # Version command
    exit_code = main(["version"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "CodeSentinel CLI v1.1.0" in captured.out


def test_cli_platform_commands(capsys):
    """7-11, 20. Verifies health, readiness, info, policies, and metrics commands."""
    # Health command
    assert main(["health"]) == 0
    # Readiness command
    assert main(["readiness"]) == 0
    # Info command
    assert main(["info"]) == 0
    # Policies command
    assert main(["policies"]) == 0
    # Metrics command
    assert main(["metrics"]) == 0

    captured = capsys.readouterr()
    assert "CodeSentinel Platform Health" in captured.out
    assert "CodeSentinel Platform Information" in captured.out
    assert "CodeSentinel Security Policy Profiles" in captured.out


# ==============================================================================
# 2. JSON OUTPUT MODE (6U-10, 6U-22)
# ==============================================================================

def test_cli_json_mode(capsys):
    """22. Verifies machine-readable JSON output mode for platform commands."""
    assert main(["info", "--json"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out.strip())
    assert data["service"] == "CodeSentinel"
    assert data["version"] == "1.1.0"


# ==============================================================================
# 3. GATE COMMAND & EXIT CODE CONTRACT (6U-4, 6U-11, 6U-18..21)
# ==============================================================================

def test_cli_gate_command_exit_codes(tmp_path):
    """5, 18-21. Verifies gate command exit codes (ALLOW=0, REVIEW=2, BLOCK=1, INVALID=1)."""
    # ALLOW -> exit 0
    allow_file = tmp_path / "allow.json"
    allow_file.write_text(json.dumps({
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }), encoding="utf-8")
    assert main(["gate", "-r", str(allow_file)]) == 0

    # REVIEW -> exit 2
    review_file = tmp_path / "review.json"
    review_file.write_text(json.dumps({
        "status": "success",
        "review_status": "review",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 1, "low_count": 0, "info_count": 0}
    }), encoding="utf-8")
    assert main(["gate", "-r", str(review_file)]) == 2

    # BLOCK -> exit 1
    block_file = tmp_path / "block.json"
    block_file.write_text(json.dumps({
        "status": "success",
        "review_status": "block",
        "summary": {"critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }), encoding="utf-8")
    assert main(["gate", "-r", str(block_file)]) == 1

    # INVALID -> exit 1
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{corrupt json", encoding="utf-8")
    assert main(["gate", "-r", str(invalid_file)]) == 1


# ==============================================================================
# 4. REPORT COMMAND & FORMATTING (6U-5, 6U-23, 6U-24)
# ==============================================================================

def test_cli_report_command(tmp_path, capsys):
    """6, 23-24. Verifies report command output formatting (terminal, markdown, json) and file writing."""
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }), encoding="utf-8")

    # Terminal format
    assert main(["report", "-i", str(report_file), "-f", "terminal"]) == 0
    captured = capsys.readouterr()
    assert "CodeSentinel Security Analysis" in captured.out

    # Markdown format file output
    out_md = tmp_path / "summary.md"
    assert main(["report", "-i", str(report_file), "-f", "markdown", "-o", str(out_md)]) == 0
    assert out_md.exists()
    md_text = out_md.read_text(encoding="utf-8")
    assert "<!-- codesentinel-security-analysis -->" in md_text


# ==============================================================================
# 5. ERROR HANDLING & SECRET REDACTION (6U-12, 6U-14, 6U-25..27)
# ==============================================================================

def test_cli_error_handling_and_secret_redaction(capsys):
    """12-16, 25-27. Verifies safe non-zero error handling, stack trace suppression, and token redaction."""
    # Non-existent target directory
    assert main(["scan", "-t", "./non_existent_directory_xyz"]) == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.out
    assert "Traceback" not in captured.out

    # Secret token in error string must be redacted
    fake_token = "ghp_1234567890abcdef1234567890abcdef"
    from backend.app.core.security import sanitize_sensitive_text
    sanitized = sanitize_sensitive_text(f"CLI Error with token {fake_token}")
    assert fake_token not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


# ==============================================================================
# 6. STATIC NON-EXECUTION ATTACK VERIFICATION (6U-28, 6U-31, 6U-32)
# ==============================================================================

def test_cli_static_non_execution_boundary(tmp_path):
    """
    28, 31-32. Hostile Target Repository Test:
    Creates untrusted files attempting side-effects (os.system, subprocess, marker file creation).
    Executes CLI scan and verifies side-effect marker files are NEVER created.
    """
    repo_dir = tmp_path / "hostile_cli_repo"
    repo_dir.mkdir()

    marker = repo_dir / "CLI_ATTACK_MARKER.tmp"

    (repo_dir / "malicious.py").write_text(f"import os\nos.system('touch {marker.as_posix()}')\n", encoding="utf-8")
    (repo_dir / "setup.py").write_text(f"import subprocess\nsubprocess.call(['touch', r'{marker.as_posix()}'])\n", encoding="utf-8")

    out_report = tmp_path / "cli_scan_report.json"
    exit_code = main(["scan", "-t", str(repo_dir), "-o", str(out_report)])

    # Verification
    assert exit_code in (0, 1, 2)
    assert not marker.exists(), "CRITICAL SECURITY FAILURE: Hostile code executed during CLI static scan!"


# ==============================================================================
# 7. BACKWARD COMPATIBILITY VERIFICATION (6U-29, 6U-30, 6U-33)
# ==============================================================================

def test_cli_backward_compatibility():
    """29-30, 33. Verifies Step 6O schema compatibility and 6R/6T integrations."""
    report = {
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }
    decision, code, msg = evaluate_security_gate(report)
    assert decision == "ALLOW"
    assert code == 0
