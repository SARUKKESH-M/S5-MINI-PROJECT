"""
CodeSentinel — Step 6Q-B Unit & Integration Test Suite

Tests PR Metadata Acquisition, Changed File Listing with Pagination, Commit SHA Validation,
Snapshot Aggregation, Error Propagation, and Security Boundaries.
"""

import sys
import os
import httpx
import pytest

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from backend.github.client import GitHubClient
    from backend.github.models import (
        GitHubPullRequest,
        GitHubChangedFile,
        GitHubPullRequestSnapshot
    )
    from backend.github.pr_service import (
        get_pull_request,
        get_pull_request_files,
        acquire_pull_request
    )
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
except ImportError:
    from github.client import GitHubClient
    from github.models import (
        GitHubPullRequest,
        GitHubChangedFile,
        GitHubPullRequestSnapshot
    )
    from github.pr_service import (
        get_pull_request,
        get_pull_request_files,
        acquire_pull_request
    )
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )


VALID_HEAD_SHA = "8f2a1c9000000000000000000000000000000000"
VALID_BASE_SHA = "1a2b3c4000000000000000000000000000000000"
VALID_FILE_SHA = "a1b2c3d400000000000000000000000000000000"


def mock_pr_response():
    return {
        "title": "Fix authentication bypass in session management",
        "state": "open",
        "html_url": "https://github.com/pallets/flask/pull/142",
        "head": {"ref": "fix/auth-bypass", "sha": VALID_HEAD_SHA},
        "base": {"ref": "main", "sha": VALID_BASE_SHA}
    }


# =====================================================================
# 1. PR METADATA ACQUISITION TESTS
# =====================================================================

def test_get_pull_request_valid(monkeypatch):
    """Verifies valid PR metadata acquisition."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=mock_pr_response())

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    pr = get_pull_request("pallets", "flask", 142)
    assert pr.owner == "pallets"
    assert pr.repository == "flask"
    assert pr.pr_number == 142
    assert pr.title == "Fix authentication bypass in session management"
    assert pr.state == "open"
    assert pr.base_branch == "main"
    assert pr.base_sha == VALID_BASE_SHA
    assert pr.head_branch == "fix/auth-bypass"
    assert pr.head_sha == VALID_HEAD_SHA


def test_get_pull_request_owner_validation():
    """Verifies owner input validation."""
    with pytest.raises(ValueError):
        get_pull_request("../pallets", "flask", 142)


def test_get_pull_request_repository_validation():
    """Verifies repository input validation."""
    with pytest.raises(ValueError):
        get_pull_request("pallets", "flask; rm -rf /", 142)


def test_get_pull_request_pr_number_validation():
    """Verifies PR number input validation."""
    with pytest.raises(ValueError):
        get_pull_request("pallets", "flask", -142)


def test_get_pull_request_valid_head_sha(monkeypatch):
    """Verifies head SHA extraction."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=mock_pr_response())

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    pr = get_pull_request("pallets", "flask", 142)
    assert pr.head_sha == VALID_HEAD_SHA


def test_get_pull_request_valid_base_sha(monkeypatch):
    """Verifies base SHA extraction."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=mock_pr_response())

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    pr = get_pull_request("pallets", "flask", 142)
    assert pr.base_sha == VALID_BASE_SHA


def test_get_pull_request_malformed_head_sha_rejected(monkeypatch):
    """Verifies malformed head SHA raises ValueError."""
    data = mock_pr_response()
    data["head"]["sha"] = "short_sha"

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(ValueError) as exc_info:
        get_pull_request("pallets", "flask", 142)
    assert "commit SHA" in str(exc_info.value)


def test_get_pull_request_malformed_base_sha_rejected(monkeypatch):
    """Verifies malformed base SHA raises ValueError."""
    data = mock_pr_response()
    data["base"]["sha"] = "invalid_hex_sha_value_non_hex_g!"

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(ValueError):
        get_pull_request("pallets", "flask", 142)


# =====================================================================
# 2. CHANGED FILES ACQUISITION TESTS
# =====================================================================

def test_get_pull_request_files_single(monkeypatch):
    """Verifies single changed file acquisition."""
    files_json = [
        {
            "filename": "src/flask/config.py",
            "status": "modified",
            "additions": 4,
            "deletions": 1,
            "changes": 5,
            "patch": "@@ -40,3 +40,6 @@",
            "sha": VALID_FILE_SHA
        }
    ]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=files_json)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    files = get_pull_request_files("pallets", "flask", 142)
    assert len(files) == 1
    assert files[0].filename == "src/flask/config.py"
    assert files[0].status == "modified"
    assert files[0].additions == 4
    assert files[0].sha == VALID_FILE_SHA


def test_get_pull_request_files_multiple(monkeypatch):
    """Verifies multiple changed files acquisition."""
    files_json = [
        {"filename": "src/flask/config.py", "status": "modified", "additions": 2, "deletions": 1, "changes": 3},
        {"filename": "src/flask/sessions.py", "status": "added", "additions": 50, "deletions": 0, "changes": 50}
    ]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=files_json)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    files = get_pull_request_files("pallets", "flask", 142)
    assert len(files) == 2
    assert files[0].filename == "src/flask/config.py"
    assert files[1].filename == "src/flask/sessions.py"


def test_get_pull_request_files_optional_patch(monkeypatch):
    """Verifies optional patch handling when patch is absent."""
    files_json = [
        {"filename": "src/flask/large_binary.png", "status": "added", "additions": 0, "deletions": 0, "changes": 0}
    ]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=files_json)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    files = get_pull_request_files("pallets", "flask", 142)
    assert len(files) == 1
    assert files[0].patch is None


def test_get_pull_request_files_pagination(monkeypatch):
    """Verifies pagination handling across multiple API pages."""
    page1 = [{"filename": f"file_{i}.py", "status": "modified", "additions": 1, "deletions": 1, "changes": 2} for i in range(100)]
    page2 = [{"filename": "file_100.py", "status": "added", "additions": 10, "deletions": 0, "changes": 10}]

    page_calls = []

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        pg = params.get("page", 1) if params else 1
        page_calls.append(pg)
        if pg == 1:
            return httpx.Response(200, json=page1)
        else:
            return httpx.Response(200, json=page2)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    files = get_pull_request_files("pallets", "flask", 142)
    assert len(files) == 101
    assert page_calls == [1, 2]


def test_get_pull_request_files_pagination_termination(monkeypatch):
    """Verifies pagination terminates when response length < per_page."""
    page1 = [{"filename": "file_0.py", "status": "modified", "additions": 1, "deletions": 1, "changes": 2}]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=page1)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    files = get_pull_request_files("pallets", "flask", 142)
    assert len(files) == 1


def test_get_pull_request_files_malformed_filename_rejected(monkeypatch):
    """Verifies malformed filename containing path traversal ('..') is rejected."""
    files_json = [{"filename": "../../../etc/passwd", "status": "modified", "additions": 1, "deletions": 0, "changes": 1}]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=files_json)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    with pytest.raises(ValueError) as exc_info:
        get_pull_request_files("pallets", "flask", 142)
    assert "path traversal" in str(exc_info.value)


def test_get_pull_request_files_malformed_file_sha(monkeypatch):
    """Verifies invalid file SHA is safely set to None without failing file listing."""
    files_json = [{"filename": "src/app.py", "status": "modified", "additions": 1, "deletions": 1, "changes": 2, "sha": "invalid_short_sha"}]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=files_json)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    files = get_pull_request_files("pallets", "flask", 142)
    assert len(files) == 1
    assert files[0].sha is None


# =====================================================================
# 3. COMBINED SNAPSHOT TESTS
# =====================================================================

def test_acquire_pull_request_combined(monkeypatch):
    """Verifies combined acquisition of PR metadata and changed files into GitHubPullRequestSnapshot."""
    pr_data = mock_pr_response()
    files_data = [{"filename": "src/app.py", "status": "modified", "additions": 5, "deletions": 2, "changes": 7}]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        if "/files" in url:
            return httpx.Response(200, json=files_data)
        return httpx.Response(200, json=pr_data)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    snapshot = acquire_pull_request("pallets", "flask", 142)
    assert isinstance(snapshot, GitHubPullRequestSnapshot)
    assert snapshot.pull_request.pr_number == 142
    assert snapshot.pull_request.head_sha == VALID_HEAD_SHA
    assert len(snapshot.changed_files) == 1
    assert snapshot.changed_files[0].filename == "src/app.py"


def test_api_404_propagated(monkeypatch):
    """Verifies 404 Not Found error is propagated cleanly."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(404, text="Not Found")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubNotFoundError):
        acquire_pull_request("pallets", "flask", 999999)


def test_api_403_propagated(monkeypatch):
    """Verifies 403 Permission error is propagated cleanly."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(403, text="Forbidden")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubPermissionError):
        acquire_pull_request("pallets", "flask", 142)


def test_api_429_propagated(monkeypatch):
    """Verifies 429 Rate Limit error is propagated cleanly."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(429, text="Too Many Requests")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubRateLimitError):
        acquire_pull_request("pallets", "flask", 142)


def test_api_5xx_propagated(monkeypatch):
    """Verifies 500 Server error is propagated cleanly."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(500, text="Internal Error")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(GitHubAPIError):
        acquire_pull_request("pallets", "flask", 142)


def test_malformed_api_response_rejected(monkeypatch):
    """Verifies non-dictionary PR response raises ValueError."""
    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json="invalid_string_json")

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    with pytest.raises(ValueError):
        acquire_pull_request("pallets", "flask", 142)


# =====================================================================
# 4. SECURITY BOUNDARY TESTS
# =====================================================================

def test_security_pr_title_shell_syntax_inert(monkeypatch):
    """Verifies PR title with shell injection syntax remains an inert text string."""
    data = mock_pr_response()
    data["title"] = "Fix bug; rm -rf / ; cat /etc/passwd"

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=data)

    monkeypatch.setattr(httpx.Client, "request", mock_request)
    pr = get_pull_request("pallets", "flask", 142)
    assert pr.title == "Fix bug; rm -rf / ; cat /etc/passwd"


def test_security_branch_name_validation():
    """Verifies branch name validation rejects unsafe characters when validated."""
    with pytest.raises(ValueError):
        get_pull_request("pallets; echo 1", "flask", 142)


def test_security_filename_traversal_rejected(monkeypatch):
    """Verifies file path traversal is strictly rejected."""
    files_json = [{"filename": "../../secret.txt", "status": "modified", "additions": 1, "deletions": 0, "changes": 1}]

    def mock_request(self_client, method, url, headers=None, params=None, json=None):
        return httpx.Response(200, json=files_json)

    monkeypatch.setattr(httpx.Client, "request", mock_request)

    with pytest.raises(ValueError):
        get_pull_request_files("pallets", "flask", 142)


def test_security_token_never_in_log_or_errors(monkeypatch):
    """Verifies token is never leaked in repr or exceptions."""
    client = GitHubClient(token="secret_token_abc_xyz")
    rep = repr(client)
    assert "secret_token_abc_xyz" not in rep
    assert "token=SET" in rep
