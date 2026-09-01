"""
CodeSentinel — Step 6Q-A Unit & Integration Test Suite

Tests GitHub API Client, Webhook Signature Verification, Webhook Input Validators,
and FastAPI GitHub Webhook Ingress Endpoint.
"""

import sys
import os
import hmac
import hashlib
import json
import httpx
import pytest
from fastapi.testclient import TestClient

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from backend.app.main import app
    from backend.app.core.config import settings
    from backend.github.client import GitHubClient
    from backend.github.webhook import verify_github_webhook_signature
    from backend.github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
except ImportError:
    from app.main import app
    from app.core.config import settings
    from github.client import GitHubClient
    from github.webhook import verify_github_webhook_signature
    from github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )

test_client = TestClient(app)


# =====================================================================
# 1. GITHUB API CLIENT TESTS
# =====================================================================

def test_github_client_header_generation():
    """Verifies that GitHubClient generates correct headers without exposing token."""
    client = GitHubClient(token="secret_token_12345", base_url="https://api.github.com", api_version="2022-11-28")
    headers = client._get_headers()

    assert headers["Authorization"] == "Bearer secret_token_12345"
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert headers["User-Agent"] == "CodeSentinel-Security-OS/1.0"
    assert "secret_token_12345" not in repr(client)
    assert "token=SET" in repr(client)


def test_github_client_status_code_mapping(monkeypatch):
    """Verifies HTTP status code error mapping in GitHubClient."""
    client = GitHubClient(token="test_token")

    mock_responses = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if not mock_responses:
            raise RuntimeError("No mock response queued")
        return mock_responses.pop(0)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    # 200 OK
    mock_responses.append(httpx.Response(200, json={"login": "octocat"}))
    res = client.get("/user")
    assert res["login"] == "octocat"

    # 401 Unauthorized
    mock_responses.append(httpx.Response(401, json={"message": "Bad credentials"}))
    with pytest.raises(GitHubAuthenticationError) as exc_info:
        client.get("/user")
    assert "401" in str(exc_info.value)
    assert "test_token" not in str(exc_info.value)

    # 403 Permission Error
    mock_responses.append(httpx.Response(403, text="Forbidden"))
    with pytest.raises(GitHubPermissionError):
        client.get("/user")

    # 403 Rate Limit Error
    mock_responses.append(httpx.Response(403, text="API rate limit exceeded"))
    with pytest.raises(GitHubRateLimitError):
        client.get("/user")

    # 404 Not Found
    mock_responses.append(httpx.Response(404, text="Not Found"))
    with pytest.raises(GitHubNotFoundError):
        client.get("/user")

    # 429 Rate Limit
    mock_responses.append(httpx.Response(429, text="Too Many Requests"))
    with pytest.raises(GitHubRateLimitError):
        client.get("/user")

    # 500 Server Error
    mock_responses.append(httpx.Response(500, text="Internal Server Error"))
    with pytest.raises(GitHubAPIError) as exc_500:
        client.get("/user")
    assert exc_500.value.status_code == 500


# =====================================================================
# 2. WEBHOOK SIGNATURE VERIFICATION TESTS
# =====================================================================

def test_webhook_signature_verification_valid():
    """Verifies HMAC-SHA256 signature verification with valid secret & payload."""
    secret = "my_super_secret_webhook_key_99"
    payload = b'{"action": "opened", "number": 142}'
    signature = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    assert verify_github_webhook_signature(payload, signature, secret) is True


def test_webhook_signature_verification_invalid():
    """Verifies signature rejection on invalid, missing, or malformed data."""
    secret = "my_super_secret_webhook_key_99"
    payload = b'{"action": "opened", "number": 142}'
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    # Wrong secret
    assert verify_github_webhook_signature(payload, valid_sig, "wrong_secret") is False

    # Wrong payload
    assert verify_github_webhook_signature(b'{"tampered": true}', valid_sig, secret) is False

    # Missing prefix 'sha256='
    raw_hex = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    assert verify_github_webhook_signature(payload, raw_hex, secret) is False

    # Missing header / None secret
    assert verify_github_webhook_signature(payload, None, secret) is False
    assert verify_github_webhook_signature(payload, valid_sig, None) is False
    assert verify_github_webhook_signature(payload, valid_sig, "") is False


# =====================================================================
# 3. WEBHOOK INPUT VALIDATOR TESTS
# =====================================================================

def test_webhook_input_validators():
    """Verifies owner, repo, PR number, and commit SHA validators."""
    # Owner validator
    assert validate_webhook_owner("pallets") == "pallets"
    assert validate_webhook_owner("code-sentinel_org") == "code-sentinel_org"
    with pytest.raises(ValueError):
        validate_webhook_owner("../pallets")
    with pytest.raises(ValueError):
        validate_webhook_owner("pallets; rm -rf /")

    # Repo validator
    assert validate_webhook_repo("flask") == "flask"
    assert validate_webhook_repo("flask.git") == "flask"
    with pytest.raises(ValueError):
        validate_webhook_repo("flask/../../etc")
    with pytest.raises(ValueError):
        validate_webhook_repo("flask && echo hacked")

    # PR Number validator
    assert validate_pr_number(142) == 142
    assert validate_pr_number("142") == 142
    with pytest.raises(ValueError):
        validate_pr_number(-5)
    with pytest.raises(ValueError):
        validate_pr_number(0)
    with pytest.raises(ValueError):
        validate_pr_number("142; DROP TABLE")
    with pytest.raises(ValueError):
        validate_pr_number(True)

    # Commit SHA validator
    valid_sha = "8f2a1c9000000000000000000000000000000000"
    assert validate_commit_sha(valid_sha) == valid_sha.lower()
    with pytest.raises(ValueError):
        validate_commit_sha("8f2a1c9")  # Short SHA
    with pytest.raises(ValueError):
        validate_commit_sha("8f2a1c900000000000000000000000000000000Z")  # Invalid hex
    with pytest.raises(ValueError):
        validate_commit_sha(valid_sha + "; ls")


# =====================================================================
# 4. FASTAPI WEBHOOK ENDPOINT TESTS
# =====================================================================

def test_github_webhook_endpoint_unconfigured_secret(monkeypatch):
    """Verifies POST /github/webhook when GITHUB_WEBHOOK_SECRET is empty/None."""
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)

    payload = {"action": "opened", "number": 142}
    response = test_client.post(
        "/github/webhook",
        json=payload,
        headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-uuid-1"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "acknowledged"
    assert data["event"] == "pull_request"
    assert data["delivery"] == "delivery-uuid-1"


def test_github_webhook_endpoint_configured_secret_valid(monkeypatch):
    """Verifies POST /github/webhook signature validation with configured secret."""
    secret = "test_webhook_secret_key"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)

    payload_bytes = json.dumps({"action": "synchronize", "number": 42}).encode("utf-8")
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    response = test_client.post(
        "/github/webhook",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-uuid-2"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "acknowledged"
    assert data["event"] == "push"
    assert data["delivery"] == "delivery-uuid-2"


def test_github_webhook_endpoint_configured_secret_invalid(monkeypatch):
    """Verifies POST /github/webhook rejects invalid or missing signatures."""
    secret = "test_webhook_secret_key"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)

    payload_bytes = json.dumps({"action": "opened"}).encode("utf-8")

    # Missing signature
    resp_missing = test_client.post(
        "/github/webhook",
        content=payload_bytes,
        headers={"Content-Type": "application/json", "X-GitHub-Event": "pull_request"}
    )
    assert resp_missing.status_code == 401

    # Invalid signature
    resp_invalid = test_client.post(
        "/github/webhook",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=invalid_hex_digest_value",
            "X-GitHub-Event": "pull_request"
        }
    )
    assert resp_invalid.status_code == 401


def test_github_webhook_endpoint_unsupported_event(monkeypatch):
    """Verifies POST /github/webhook safely ignores unsupported events."""
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)

    response = test_client.post(
        "/github/webhook",
        json={"action": "created"},
        headers={"X-GitHub-Event": "star", "X-GitHub-Delivery": "del-3"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ignored"
    assert data["event"] == "star"
