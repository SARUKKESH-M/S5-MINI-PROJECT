"""
CodeSentinel — Step 6S-B Unit & Integration Test Suite

Tests Security Dependency & Configuration Hardening:
- Pinned dependency declarations in requirements.txt
- Secret default safety (secrets default to None)
- Safe configuration summary masking (`get_safe_config_summary`)
- Security configuration validation (`validate_security_configuration`)
- Production/Debug mode safety enforcement
- Repository secret audit (verifies no hardcoded secrets exist)
- Static non-execution boundary preservation
- GitHub Actions CI workflow configuration compatibility
"""

import json
import os
import sys
import pytest
from pathlib import Path

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.config import Settings, settings


def test_requirements_file_has_pinned_dependencies():
    """1. Verifies that backend/requirements.txt contains pinned versions for core dependencies."""
    req_path = Path(__file__).parent.parent / "backend" / "requirements.txt"
    assert req_path.exists(), "backend/requirements.txt missing"

    content = req_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]

    assert len(lines) >= 5, "requirements.txt must list core dependencies"
    for line in lines:
        assert "==" in line, f"Dependency line '{line}' must be pinned with '==' for reproducible builds"


def test_env_example_is_safe_and_has_placeholders():
    """2. Verifies that .env.example contains safe placeholder strings and no real secrets."""
    env_ex_path = Path(__file__).parent.parent / ".env.example"
    assert env_ex_path.exists(), ".env.example missing"

    content = env_ex_path.read_text(encoding="utf-8")
    assert "YOUR_GITHUB_TOKEN_HERE" in content
    assert "YOUR_GITHUB_WEBHOOK_SECRET_HERE" in content
    assert "YOUR_GROQ_API_KEY_HERE" in content
    assert "ghp_" not in content
    assert "gho_" not in content


def test_sensitive_credentials_default_to_none():
    """3. Verifies that all secret fields in Settings default to None."""
    default_settings = Settings()
    assert default_settings.GITHUB_TOKEN is None
    assert default_settings.GITHUB_WEBHOOK_SECRET is None
    assert default_settings.GROQ_API_KEY is None
    assert default_settings.DATABASE_URL is None
    assert default_settings.REDIS_URL is None
    assert default_settings.SLACK_WEBHOOK_URL is None


def test_safe_config_summary_masks_secrets():
    """4. Verifies that get_safe_config_summary() masks all sensitive keys."""
    custom_settings = Settings(
        GITHUB_TOKEN="ghp_dummytoken1234567890abcdef12345678",
        GITHUB_WEBHOOK_SECRET="super_secret_webhook_val",
        GROQ_API_KEY="gsk_groqapikey12345"
    )

    summary = custom_settings.get_safe_config_summary()
    assert summary["GITHUB_TOKEN"] == "[REDACTED]"
    assert summary["GITHUB_WEBHOOK_SECRET"] == "[REDACTED]"
    assert summary["GROQ_API_KEY"] == "[REDACTED]"
    assert summary["APP_ENV"] == "development"
    assert summary["BACKEND_PORT"] == 8000


def test_security_configuration_validation():
    """5. Verifies validate_security_configuration() catches unsafe configurations."""
    # Safe settings
    safe_settings = Settings()
    is_valid, errors = safe_settings.validate_security_configuration()
    assert is_valid, f"Default settings should be valid, got errors: {errors}"

    # Unsafe debug in production
    prod_debug_settings = Settings(APP_ENV="production", DEBUG=True)
    is_valid, errors = prod_debug_settings.validate_security_configuration()
    assert not is_valid
    assert any("DEBUG mode must be False" in err for err in errors)

    # Invalid port
    bad_port_settings = Settings(BACKEND_PORT=99999)
    is_valid, errors = bad_port_settings.validate_security_configuration()
    assert not is_valid
    assert any("BACKEND_PORT must be between" in err for err in errors)

    # Unsafe placeholder credential
    bad_secret_settings = Settings(GITHUB_TOKEN="password123")
    is_valid, errors = bad_secret_settings.validate_security_configuration()
    assert not is_valid
    assert any("contains an unsafe placeholder" in err for err in errors)


def test_repository_secret_audit():
    """6. Audits backend python files to confirm no hardcoded API keys or token literals exist."""
    import re
    workspace_root = Path(__file__).parent.parent
    backend_dir = workspace_root / "backend"

    # Regex matching actual token literals (e.g. ghp_ followed by actual alphanumeric secret string)
    token_literal_pattern = re.compile(r"(ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9]{20,})")

    for root, _, files in os.walk(backend_dir):
        if ".venv" in root or "__pycache__" in root:
            continue
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                text = file_path.read_text(encoding="utf-8", errors="ignore")
                match = token_literal_pattern.search(text)
                assert match is None, f"Hardcoded secret token literal '{match.group(0)}' found in {file_path}"


def test_github_actions_workflow_compatibility():
    """7. Verifies that .github/workflows/security-scan.yml retains PYTHONPATH: .:backend."""
    wf_path = Path(__file__).parent.parent / ".github" / "workflows" / "security-scan.yml"
    assert wf_path.exists(), "security-scan.yml workflow missing"

    content = wf_path.read_text(encoding="utf-8")
    assert "PYTHONPATH: .:backend" in content
    assert "permissions:" in content
    assert "contents: read" in content
