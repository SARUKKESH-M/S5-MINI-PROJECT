"""
CodeSentinel — Step 6S-A Unit & Integration Test Suite

Tests Security Hardening Foundation controls:
- Payload size limit enforcement (HTTP 413 Payload Too Large)
- Defensive HTTP security headers
- Error response hardening (prevents stack traces / secret leakage)
- Log secret redaction
- Hardened CORS origin handling
- Validation boundary preservation
- Static non-execution boundary preservation
"""

import json
import logging
import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.main import app
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
from backend.analysis.security_scan import run_security_scan

client = TestClient(app)


def test_security_headers_present_in_responses():
    """1. Verifies that defensive HTTP security headers are returned on API endpoints."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert response.headers.get("x-xss-protection") == "1; mode=block"
    assert "default-src 'self'" in response.headers.get("content-security-policy", "")


def test_oversized_request_payload_rejected():
    """2. Verifies that requests exceeding Content-Length limit are rejected with 413 Payload Too Large."""
    from fastapi import FastAPI
    small_app = FastAPI()
    small_app.add_middleware(RequestSizeLimitMiddleware, max_size_bytes=100)

    @small_app.post("/test-upload")
    def upload_endpoint(payload: dict):
        return {"status": "ok"}

    small_client = TestClient(small_app)
    res_small = small_client.post("/test-upload", json={"key": "val"})
    assert res_small.status_code == 200

    headers = {"Content-Length": "1000"}
    res_large = small_client.post("/test-upload", json={"data": "x" * 500}, headers=headers)
    assert res_large.status_code == 413
    assert "exceeds maximum allowed size" in res_large.json().get("detail", "")


def test_cors_origin_headers_behavior():
    """3. Verifies that CORS headers respond appropriately for allowed origins."""
    headers = {"Origin": "http://localhost:3000"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_error_response_hardening_masks_secrets_and_prevents_stacktraces():
    """4. Verifies global exception handler masks sensitive tokens and returns clean 500 JSON without tracebacks."""
    token = "ghp_1234567890abcdef1234567890abcdef"
    secret_text = f"Failed to authenticate with token {token} at C:\\Users\\admin\\secret_config.json"

    sanitized = sanitize_sensitive_text(secret_text)
    assert token not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

    @app.get("/test-internal-error")
    def trigger_error():
        raise RuntimeError(f"Internal crash with token {token}")

    err_client = TestClient(app, raise_server_exceptions=False)
    res = err_client.get("/test-internal-error")
    assert res.status_code == 500
    data = res.json()
    assert "detail" in data
    assert data["detail"] == "An internal server error occurred."
    assert token not in res.text
    assert "C:\\Users\\" not in res.text
    assert "Traceback" not in res.text


def test_logging_filter_redacts_sensitive_records(caplog):
    """5. Verifies Python logging SecurityLogFilter redacts token literals."""
    logger = logging.getLogger("test_security_logger")
    logger.addFilter(SecurityLogFilter())

    token = "ghp_1234567890abcdef1234567890abcdef"
    with caplog.at_level(logging.INFO):
        logger.info("Connecting using token %s", token)

    assert token not in caplog.text
    assert "[REDACTED_SECRET]" in caplog.text


def test_input_validation_boundaries():
    """6. Verifies input validation boundary functions remain fully functional and defensive."""
    url_meta = validate_github_url("https://github.com/owner/repo")
    assert url_meta["owner"] == "owner"
    assert url_meta["repository"] == "repo"

    with pytest.raises(ValueError):
        validate_github_url("http://insecure-http.com/owner/repo")

    with pytest.raises(ValueError):
        validate_github_url("https://user:pass@github.com/owner/repo")

    assert validate_branch("main") == "main"
    with pytest.raises(ValueError):
        validate_branch("branch; rm -rf /")

    assert validate_repo_path("src/app") == "src/app"
    with pytest.raises(ValueError):
        validate_repo_path("../../../etc/passwd")

    assert validate_webhook_owner("owner") == "owner"
    assert validate_webhook_repo("repo") == "repo"
    assert validate_pr_number(42) == 42
    assert validate_commit_sha("a" * 40) == "a" * 40

    with pytest.raises(ValueError):
        validate_commit_sha("invalid_sha_123")


def test_static_non_execution_boundary_remains_intact(tmp_path):
    """7. Verifies static security scanning never executes target repository source files."""
    untrusted_dir = tmp_path / "untrusted_target"
    untrusted_dir.mkdir()
    sentinel = untrusted_dir / "executed.txt"

    malicious_py = untrusted_dir / "bad.py"
    malicious_py.write_text(
        f"import pathlib\npathlib.Path(r'{sentinel.as_posix()}').write_text('EXECUTED!')\n",
        encoding="utf-8"
    )

    report = run_security_scan(target_dir=str(untrusted_dir))
    assert isinstance(report, dict)
    assert not sentinel.exists(), "Security hardening boundary violated! Target code executed."
