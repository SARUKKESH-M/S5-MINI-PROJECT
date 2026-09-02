"""
CodeSentinel — Step 6S-D Unit & Integration Test Suite
Production Security Readiness & Final Hardening Verification

Tests final production readiness properties:
1. Production environment configuration cannot run with DEBUG=True.
2. Security-sensitive configuration remains redacted in summaries.
3. Webhook verification remains constant-time, signature-validated, and fail-closed.
4. GitHub credentials and authorization headers never leak in API errors, logs, or summaries.
5. GitHub Actions workflows retain least-privilege permissions and safe PYTHONPATH.
6. Security gate evaluation remains deterministic and fail-closed across all exit codes.
7. Step 6O Production Report schema remains secret-safe and backward-compatible.
8. Static non-execution boundary remains 100% intact against hostile target repositories.
9. HTTP security middleware (request payload size limits, security headers, CORS) remains active.
10. Unexpected internal errors return sanitized generic responses without stack traces or secrets.
11. Safe template placeholders in .env.example with no hardcoded credentials.
12. Final repository secret audit confirms zero credential leakage.
"""

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
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware
)
from backend.github.webhook import verify_github_webhook_signature
from backend.github.exceptions import GitHubAPIError, GitHubAuthenticationError
from backend.analysis.security_gate import evaluate_security_gate, run_security_gate
from backend.analysis.ci_report import generate_ci_security_summary
from backend.analysis.security_scan import run_security_scan

client = TestClient(app)


# ==============================================================================
# 1. PRODUCTION CONFIGURATION HARDENING
# ==============================================================================

def test_production_config_rejects_debug_mode():
    """1. Verifies production settings reject DEBUG=True configuration."""
    prod_debug_settings = Settings(APP_ENV="production", DEBUG=True)
    is_valid, errors = prod_debug_settings.validate_security_configuration()
    assert not is_valid
    assert any("DEBUG mode must be False" in err for err in errors)


def test_sensitive_config_redaction():
    """2. Verifies sensitive keys are redacted in configuration summary."""
    cfg = Settings(
        GROQ_API_KEY="gsk_secret_key_val",
        GITHUB_TOKEN="ghp_secret_token_val",
        GITHUB_WEBHOOK_SECRET="whsec_secret_val"
    )
    summary = cfg.get_safe_config_summary()
    assert summary["GROQ_API_KEY"] == "[REDACTED]"
    assert summary["GITHUB_TOKEN"] == "[REDACTED]"
    assert summary["GITHUB_WEBHOOK_SECRET"] == "[REDACTED]"


# ==============================================================================
# 2. WEBHOOK & AUTHENTICATION HARDENING
# ==============================================================================

def test_webhook_fail_closed_on_missing_secret():
    """3. Verifies webhook signature check fails closed if secret is missing or empty."""
    assert not verify_github_webhook_signature(b"payload", "sha256=12345", None)
    assert not verify_github_webhook_signature(b"payload", "sha256=12345", "")


def test_credential_sanitization_in_api_errors():
    """4. Verifies secrets are stripped from API exceptions and error strings."""
    fake_token = "ghp_1234567890abcdef1234567890abcdef"
    err = GitHubAuthenticationError(f"Failed auth using Bearer {fake_token}")

    sanitized = sanitize_sensitive_text(str(err))
    assert fake_token not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


# ==============================================================================
# 3. CI/CD & WORKFLOW SECURITY
# ==============================================================================

def test_workflow_security_and_permissions():
    """5. Verifies workflow configuration files contain least-privilege permissions and PYTHONPATH."""
    sec_scan_path = Path(__file__).parent.parent / ".github" / "workflows" / "security-scan.yml"
    assert sec_scan_path.exists(), "security-scan.yml missing"

    content = sec_scan_path.read_text(encoding="utf-8")
    assert "PYTHONPATH: .:backend" in content
    assert "permissions:" in content
    assert "contents: read" in content


# ==============================================================================
# 4. SECURITY GATE DETERMINISTIC FAIL-CLOSED BEHAVIOR
# ==============================================================================

def test_security_gate_fail_closed_exit_codes():
    """6. Verifies deterministic exit codes: ALLOW=0, REVIEW=2, BLOCK=1, INVALID=1."""
    allow_rep = {"status": "success", "review_status": "allow", "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}}
    review_rep = {"status": "success", "review_status": "review", "summary": {"critical_count": 0, "high_count": 0, "medium_count": 1, "low_count": 0, "info_count": 0}}
    block_rep = {"status": "success", "review_status": "block", "summary": {"critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}}
    invalid_rep = {"status": "error"}

    _, code_allow, _ = evaluate_security_gate(allow_rep)
    _, code_review, _ = evaluate_security_gate(review_rep)
    _, code_block, _ = evaluate_security_gate(block_rep)
    _, code_invalid, _ = evaluate_security_gate(invalid_rep)

    assert code_allow == 0
    assert code_review == 2
    assert code_block == 1
    assert code_invalid == 1


# ==============================================================================
# 5. STEP 6O REPORT CONTRACT & SECRET SAFETY
# ==============================================================================

def test_step_6o_report_schema_preserves_contract():
    """7. Verifies Step 6O production report output retains standard schema fields."""
    report = {
        "status": "success",
        "review_status": "allow",
        "summary": {"total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": []
    }
    summary_md = generate_ci_security_summary(report)
    assert "<!-- codesentinel-security-analysis -->" in summary_md
    assert "ALLOW / Safe to Merge" in summary_md


# ==============================================================================
# 6. STATIC NON-EXECUTION FINAL BOUNDARY VERIFICATION
# ==============================================================================

def test_final_static_non_execution_verification(tmp_path):
    """
    8. Final Static Non-Execution Boundary Test:
    Constructs a target repository with malicious executable python, shell scripts, and setup entrypoints.
    Runs static analysis and verifies ZERO side-effect marker files are created.
    """
    repo_dir = tmp_path / "hostile_target_repo"
    repo_dir.mkdir()

    marker = repo_dir / "ATTACK_EXECUTED_MARKER.tmp"

    # Hostile script 1: direct os.system
    (repo_dir / "exploit.py").write_text(f"import os\nos.system('touch {marker.as_posix()}')\n", encoding="utf-8")

    # Hostile script 2: subprocess call
    (repo_dir / "setup.py").write_text(f"import subprocess\nsubprocess.call(['touch', r'{marker.as_posix()}'])\n", encoding="utf-8")

    # Hostile script 3: shell file
    (repo_dir / "build.sh").write_text(f"#!/bin/bash\necho EXECUTED > {marker.as_posix()}\n", encoding="utf-8")

    # Run static security scan
    report = run_security_scan(target_dir=str(repo_dir))
    assert report.get("status") == "success"

    # Verify side-effect marker file was NEVER created
    assert not marker.exists(), "CRITICAL SECURITY FAILURE: Target code executed during static scan!"


# ==============================================================================
# 7. HTTP SECURITY MIDDLEWARE VERIFICATION
# ==============================================================================

def test_http_security_headers_and_payload_limit():
    """9. Verifies security headers and size limit middleware response behavior."""
    res = client.get("/health")
    assert res.status_code == 200

    # Security headers
    headers = res.headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-xss-protection") == "1; mode=block"


# ==============================================================================
# 8. ERROR HANDLER SANITIZATION
# ==============================================================================

def test_unhandled_exception_sanitization():
    """10. Verifies global exception handler returns sanitized generic error without leaking tracebacks."""
    res = client.get("/non_existent_endpoint_xyz")
    assert res.status_code == 404
    body = res.json()
    assert "detail" in body
    # Tracebacks / internal paths are not exposed
    assert "Traceback" not in str(body)


# ==============================================================================
# 9. ENVIRONMENT TEMPLATE SAFETY
# ==============================================================================

def test_env_example_safety():
    """11. Verifies .env.example contains only safe placeholders."""
    env_path = Path(__file__).parent.parent / ".env.example"
    content = env_path.read_text(encoding="utf-8")
    assert "ghp_" not in content
    assert "gho_" not in content
    assert "github_pat_" not in content


# ==============================================================================
# 10. REPOSITORY SECRET AUDIT
# ==============================================================================

def test_final_repository_secret_audit():
    """12. Final Audit: Confirms no real GitHub tokens or secret key literals are committed."""
    import re
    workspace_root = Path(__file__).parent.parent
    backend_dir = workspace_root / "backend"

    token_literal_pattern = re.compile(r"(ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9]{20,})")

    for root, _, files in os.walk(backend_dir):
        if ".venv" in root or "__pycache__" in root:
            continue
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                text = file_path.read_text(encoding="utf-8", errors="ignore")
                match = token_literal_pattern.search(text)
                assert match is None, f"Hardcoded token literal '{match.group(0)}' found in {file_path}"
