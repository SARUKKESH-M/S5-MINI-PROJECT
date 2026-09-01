"""
Step 6K Verification Test Suite for CodeSentinel.

Tests GitHub Repository Intake Foundation:
- GitHub URL validation and owner/repo extraction
- Branch and subpath validation
- Supported source file discovery & language detection
- Directory exclusions (.git, node_modules, .venv, etc.)
- Deterministic file path ordering
- File count (500), file size (1MB), and total bytes (25MB) limit enforcement
- Safe UTF-8 source text reading & binary content skipping
- Path traversal & escaping protection
- Public repository metadata generation & raw source code exclusion
- Secret protection (THIS_SECRET_MUST_NOT_APPEAR masking/exclusion)
- Non-execution static boundary
- FastAPI POST /repository/intake endpoint & error handling
- Regression testing across previous steps
"""

import sys
import os
import json
import tempfile
import pytest
from pathlib import Path

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from repository.validator import validate_github_url, validate_branch, validate_repo_path
from repository.models import create_repository_request, create_repository_metadata
from repository.discovery import (
    discover_source_files,
    get_language_for_extension,
    MAX_SOURCE_FILES,
    MAX_TOTAL_SOURCE_BYTES,
    SUPPORTED_EXTENSIONS
)
from repository.reader import read_source_file, is_binary_content, MAX_FILE_SIZE
from repository.service import prepare_repository_for_analysis
from app.main import app
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# TEST 1: Valid GitHub URL Normalization
# ---------------------------------------------------------------------------
def test_1_valid_github_url():
    res = validate_github_url("https://github.com/example/project")
    assert res["owner"] == "example"
    assert res["repository"] == "project"
    assert res["normalized_url"] == "https://github.com/example/project"


# ---------------------------------------------------------------------------
# TEST 2: Trailing Slash Normalization
# ---------------------------------------------------------------------------
def test_2_trailing_slash_normalization():
    res = validate_github_url("https://github.com/my-org/my-repo/")
    assert res["owner"] == "my-org"
    assert res["repository"] == "my-repo"
    assert res["normalized_url"] == "https://github.com/my-org/my-repo"


# ---------------------------------------------------------------------------
# TEST 3: .git Suffix Normalization
# ---------------------------------------------------------------------------
def test_3_git_suffix_normalization():
    res = validate_github_url("https://github.com/owner/repository.git")
    assert res["owner"] == "owner"
    assert res["repository"] == "repository"
    assert res["normalized_url"] == "https://github.com/owner/repository"


# ---------------------------------------------------------------------------
# TEST 4: Owner Extraction
# ---------------------------------------------------------------------------
def test_4_owner_extraction():
    url_info = validate_github_url("https://github.com/sec-team/code-sentinel")
    assert url_info["owner"] == "sec-team"


# ---------------------------------------------------------------------------
# TEST 5: Repository Extraction
# ---------------------------------------------------------------------------
def test_5_repository_extraction():
    url_info = validate_github_url("https://github.com/sec-team/code-sentinel")
    assert url_info["repository"] == "code-sentinel"


# ---------------------------------------------------------------------------
# TEST 6: Invalid GitHub URL Rejection
# ---------------------------------------------------------------------------
def test_6_invalid_github_url():
    with pytest.raises(ValueError, match="domain"):
        validate_github_url("https://gitlab.com/example/project")

    with pytest.raises(ValueError, match="non-empty string"):
        validate_github_url("")


# ---------------------------------------------------------------------------
# TEST 7: Unsupported URL Scheme Rejection
# ---------------------------------------------------------------------------
def test_7_unsupported_url_scheme():
    for bad_url in [
        "http://github.com/owner/repo",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,hack"
    ]:
        with pytest.raises(ValueError):
            validate_github_url(bad_url)


# ---------------------------------------------------------------------------
# TEST 8: Embedded Credential Rejection
# ---------------------------------------------------------------------------
def test_8_embedded_credential_rejection():
    bad_url = "https://user:password@github.com/owner/repo"
    with pytest.raises(ValueError, match="credentials"):
        validate_github_url(bad_url)


# ---------------------------------------------------------------------------
# TEST 9: Invalid Branch Rejection
# ---------------------------------------------------------------------------
def test_9_invalid_branch():
    assert validate_branch("main") == "main"
    assert validate_branch("feature/v1.0") == "feature/v1.0"
    
    with pytest.raises(ValueError):
        validate_branch("main; rm -rf /")

    with pytest.raises(ValueError):
        validate_branch("main | cat /etc/passwd")

    with pytest.raises(ValueError):
        validate_branch("../main")


# ---------------------------------------------------------------------------
# TEST 10: Path Traversal Rejection
# ---------------------------------------------------------------------------
def test_10_path_traversal_rejection():
    assert validate_repo_path("src/utils") == "src/utils"

    with pytest.raises(ValueError, match="Path traversal"):
        validate_repo_path("../secret")

    with pytest.raises(ValueError, match="Path traversal"):
        validate_repo_path("src/../../etc")


# ---------------------------------------------------------------------------
# TEST 11: Safe Repository Relative Path
# ---------------------------------------------------------------------------
def test_11_safe_repository_relative_path():
    res = validate_repo_path("backend/app/api/")
    assert res == "backend/app/api"
    assert validate_repo_path("") == ""


# ---------------------------------------------------------------------------
# TEST 12: Supported Extension Detection
# ---------------------------------------------------------------------------
def test_12_supported_extension_detection():
    assert get_language_for_extension(".py") == "python"
    assert get_language_for_extension(".js") == "javascript"
    assert get_language_for_extension(".ts") == "typescript"
    assert get_language_for_extension(".java") == "java"
    assert get_language_for_extension(".go") == "go"
    assert get_language_for_extension(".rs") == "rust"


# ---------------------------------------------------------------------------
# TEST 13: Unsupported Extension Exclusion
# ---------------------------------------------------------------------------
def test_13_unsupported_extension_exclusion():
    assert get_language_for_extension(".exe") is None
    assert get_language_for_extension(".png") is None
    assert get_language_for_extension(".zip") is None
    assert get_language_for_extension(".db") is None


# ---------------------------------------------------------------------------
# TEST 14: Excluded Directory Handling
# ---------------------------------------------------------------------------
def test_14_excluded_directory_handling():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create normal file
        os.makedirs(os.path.join(tmpdir, "src"))
        with open(os.path.join(tmpdir, "src", "app.py"), "w", encoding="utf-8") as f:
            f.write("print('hello')")

        # Create excluded directory files
        os.makedirs(os.path.join(tmpdir, "node_modules", "pkg"))
        with open(os.path.join(tmpdir, "node_modules", "pkg", "index.js"), "w", encoding="utf-8") as f:
            f.write("module.exports = {}")

        os.makedirs(os.path.join(tmpdir, ".venv", "lib"))
        with open(os.path.join(tmpdir, ".venv", "lib", "site.py"), "w", encoding="utf-8") as f:
            f.write("pass")

        files = discover_source_files(tmpdir)
        paths = [f["path"] for f in files]

        assert "src/app.py" in paths
        assert not any("node_modules" in p for p in paths)
        assert not any(".venv" in p for p in paths)


# ---------------------------------------------------------------------------
# TEST 15: Deterministic File Ordering
# ---------------------------------------------------------------------------
def test_15_deterministic_file_ordering():
    with tempfile.TemporaryDirectory() as tmpdir:
        filenames = ["z.py", "a.py", "m.js", "b.ts"]
        for fn in filenames:
            with open(os.path.join(tmpdir, fn), "w", encoding="utf-8") as f:
                f.write("content")

        files1 = discover_source_files(tmpdir)
        files2 = discover_source_files(tmpdir)

        paths1 = [f["path"] for f in files1]
        paths2 = [f["path"] for f in files2]

        assert paths1 == ["a.py", "b.ts", "m.js", "z.py"]
        assert paths1 == paths2


# ---------------------------------------------------------------------------
# TEST 16: Python Language Detection
# ---------------------------------------------------------------------------
def test_16_python_language_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w", encoding="utf-8") as f:
            f.write("def foo(): pass")

        files = discover_source_files(tmpdir)
        assert len(files) == 1
        assert files[0]["language"] == "python"


# ---------------------------------------------------------------------------
# TEST 17: JavaScript & TypeScript Language Detection
# ---------------------------------------------------------------------------
def test_17_javascript_language_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "index.js"), "w", encoding="utf-8") as f:
            f.write("console.log('hi')")
        with open(os.path.join(tmpdir, "app.tsx"), "w", encoding="utf-8") as f:
            f.write("export const App = () => null;")

        files = discover_source_files(tmpdir)
        langs = {f["path"]: f["language"] for f in files}

        assert langs["index.js"] == "javascript"
        assert langs["app.tsx"] == "typescript"


# ---------------------------------------------------------------------------
# TEST 18: File Count Limit
# ---------------------------------------------------------------------------
def test_18_file_count_limit():
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(MAX_SOURCE_FILES + 5):
            with open(os.path.join(tmpdir, f"file_{i}.py"), "w", encoding="utf-8") as f:
                f.write("x = 1")

        with pytest.raises(ValueError, match="maximum allowed source file count"):
            discover_source_files(tmpdir)


# ---------------------------------------------------------------------------
# TEST 19: Individual File Size Limit
# ---------------------------------------------------------------------------
def test_19_individual_file_size_limit():
    with tempfile.TemporaryDirectory() as tmpdir:
        big_file = os.path.join(tmpdir, "huge.py")
        with open(big_file, "wb") as f:
            f.write(b"a" * (MAX_FILE_SIZE + 100))

        read_res = read_source_file("huge.py", tmpdir)
        assert read_res["skipped"] is True
        assert read_res["reason"] == "exceeds MAX_FILE_SIZE"
        assert read_res["source_code"] == ""


# ---------------------------------------------------------------------------
# TEST 20: Total Repository Size Limit
# ---------------------------------------------------------------------------
def test_20_total_repository_size_limit():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create 26 files of 1MB each -> total 26MB > MAX_TOTAL_SOURCE_BYTES (25MB)
        for i in range(26):
            with open(os.path.join(tmpdir, f"big_{i}.py"), "wb") as f:
                f.write(b"x" * (1_000_000))

        with pytest.raises(ValueError, match="maximum allowed total source content size"):
            discover_source_files(tmpdir)


# ---------------------------------------------------------------------------
# TEST 21: UTF-8 Source Reading
# ---------------------------------------------------------------------------
def test_21_utf8_source_reading():
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_path = os.path.join(tmpdir, "sample.py")
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write("# Hello World\ndef test(): return True")

        read_res = read_source_file("sample.py", tmpdir)
        assert read_res["skipped"] is False
        assert "# Hello World" in read_res["source_code"]


# ---------------------------------------------------------------------------
# TEST 22: Malformed UTF-8 Handling
# ---------------------------------------------------------------------------
def test_22_malformed_utf8_handling():
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_path = os.path.join(tmpdir, "bad_utf8.py")
        with open(sample_path, "wb") as f:
            f.write(b"x = 'hello \x80\xff world'")

        read_res = read_source_file("bad_utf8.py", tmpdir)
        assert read_res["skipped"] is False
        assert "hello" in read_res["source_code"]


# ---------------------------------------------------------------------------
# TEST 23: Binary Detection
# ---------------------------------------------------------------------------
def test_23_binary_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        bin_path = os.path.join(tmpdir, "compiled.py")
        with open(bin_path, "wb") as f:
            f.write(b"\x00\x01\x02\x03\x00BIN_DATA")

        read_res = read_source_file("compiled.py", tmpdir)
        assert read_res["skipped"] is True
        assert read_res["reason"] == "binary_content"
        assert read_res["source_code"] == ""


# ---------------------------------------------------------------------------
# TEST 24: Safe Repository Metadata
# ---------------------------------------------------------------------------
def test_24_safe_repository_metadata():
    meta = create_repository_metadata(
        owner="test-owner",
        repository="test-repo",
        branch="main",
        path="",
        source_file_count=2,
        source_extensions=[".py", ".js"],
        total_source_bytes=1000,
        files_summary=[
            {"path": "b.js", "language": "javascript", "size_bytes": 400},
            {"path": "a.py", "language": "python", "size_bytes": 600}
        ]
    )

    assert meta["status"] == "success"
    assert meta["repository"]["owner"] == "test-owner"
    assert meta["repository"]["repository"] == "test-repo"
    assert meta["file_count"] == 2
    assert meta["source_extensions"] == [".js", ".py"]
    # Deterministic file sorting
    assert meta["files"][0]["path"] == "a.py"
    assert meta["files"][1]["path"] == "b.js"


# ---------------------------------------------------------------------------
# TEST 25: Raw Source Excluded From Public API Metadata
# ---------------------------------------------------------------------------
def test_25_raw_source_excluded_from_public_api():
    meta = create_repository_metadata(
        owner="owner",
        repository="repo",
        branch="main",
        path="",
        source_file_count=1,
        source_extensions=[".py"],
        total_source_bytes=500,
        files_summary=[{"path": "app.py", "language": "python", "size_bytes": 500}]
    )

    meta_str = json.dumps(meta)
    forbidden_fields = ["source_code", "raw_source", "full_source", "original_source", "raw_code"]
    for field in forbidden_fields:
        assert field not in meta_str


# ---------------------------------------------------------------------------
# TEST 26: Secret Protection
# ---------------------------------------------------------------------------
def test_26_secret_protection():
    secret_value = "THIS_SECRET_MUST_NOT_APPEAR"

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "config.py"), "w", encoding="utf-8") as f:
            f.write(f"API_KEY = '{secret_value}'")

        res = prepare_repository_for_analysis(
            repository_path=tmpdir,
            repository_url="https://github.com/example/sec-test"
        )

        public_meta_json = json.dumps(res["public_metadata"])
        assert secret_value not in public_meta_json


# ---------------------------------------------------------------------------
# TEST 27: Source Non-Execution Boundary
# ---------------------------------------------------------------------------
def test_27_source_non_execution_boundary():
    dangerous_code = "import os; os.system('echo HACKED'); eval('1+1')"

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "danger.py"), "w", encoding="utf-8") as f:
            f.write(dangerous_code)

        # Intake reads file purely as static text without executing os.system or eval
        res = prepare_repository_for_analysis(
            repository_path=tmpdir,
            repository_url="https://github.com/example/danger-repo"
        )

        assert res["status"] == "success"
        assert len(res["files_internal"]) == 1
        assert res["files_internal"][0]["source_code"] == dangerous_code


# ---------------------------------------------------------------------------
# TEST 28: FastAPI POST /repository/intake Endpoint
# ---------------------------------------------------------------------------
def test_28_fastapi_repository_intake_endpoint():
    client = TestClient(app)
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w", encoding="utf-8") as f:
            f.write("print('CodeSentinel Intake')")

        payload = {
            "repository_url": "https://github.com/openai/codex",
            "branch": "main",
            "path": "",
            "local_path": tmpdir
        }

        response = client.post("/repository/intake", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "success"
        assert data["repository"]["owner"] == "openai"
        assert data["repository"]["repository"] == "codex"
        assert data["file_count"] == 1
        assert data["files"][0]["path"] == "main.py"

        # Ensure raw source code fields are not exposed in HTTP API response
        res_str = json.dumps(data)
        for field in ["source_code", "raw_source", "full_source", "original_source", "raw_code"]:
            assert field not in res_str


# ---------------------------------------------------------------------------
# TEST 29: FastAPI Intake Error Handling
# ---------------------------------------------------------------------------
def test_29_fastapi_intake_error_handling():
    client = TestClient(app)

    # 400 Bad Request: Invalid GitHub URL
    res_bad_url = client.post("/repository/intake", json={
        "repository_url": "http://invalid-scheme.com/repo"
    })
    assert res_bad_url.status_code == 400

    # 400 Bad Request: Embedded Credentials
    res_creds = client.post("/repository/intake", json={
        "repository_url": "https://user:pass@github.com/owner/repo"
    })
    assert res_creds.status_code == 400

    # 404 Not Found: Non-existent local path
    res_404 = client.post("/repository/intake", json={
        "repository_url": "https://github.com/owner/repo",
        "local_path": "C:/NonExistentPath_12345"
    })
    assert res_404.status_code == 404


# ---------------------------------------------------------------------------
# TEST 30: Full Regression Passthrough
# ---------------------------------------------------------------------------
def test_30_full_regression_passthrough():
    client = TestClient(app)

    # Existing root /
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["service"] == "CodeSentinel"

    # Existing /health
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    # Existing /analyses
    res_hist = client.get("/analyses")
    assert res_hist.status_code == 200
    assert "analyses" in res_hist.json()
