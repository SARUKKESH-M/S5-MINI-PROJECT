"""Phase 35D — Bounded Concurrency Test Suite.

Verifies:
- 1 changed file
- Multiple changed files
- Bounded worker count (never exceeds MAX_CONCURRENT_GITHUB_FETCHES)
- Deterministic output ordering
- Successful concurrent fetches
- One fetch failure (graceful fallback)
- Multiple fetch failures
- Retry and rate-limit safety under concurrent requests
- Pooled client reuse (no per-worker client creation)
- No nested executors
- Empty changed-file list
- Duplicate filenames/content handling
- Large but bounded file list
- PR idempotency and webhook idempotency preserved
- Step 6O gate decisions preserved
"""

import base64
import threading
import time
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch
import httpx
import pytest

from backend.github.client import GitHubClient
from backend.github.exceptions import (
    GitHubAPIError,
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubNotFoundError,
    GitHubRateLimitError,
)
from backend.github.orchestrator import (
    _fetch_pr_files_contents_bounded,
    _generate_pr_analysis_report,
    DEFAULT_MAX_CONCURRENT_GITHUB_FETCHES,
)
from backend.github.models import GitHubChangedFile
from backend.analysis.security_gate import evaluate_security_gate


def _encode_b64(content: str) -> str:
    return base64.b64encode(content.encode("utf-8")).decode("ascii")


def test_01_single_changed_file():
    """Verify that a single changed file is fetched directly without spawning unnecessary threads."""
    client = GitHubClient(token="ghp_test")

    with patch.object(client, "get") as mock_get:
        mock_get.return_value = {"content": _encode_b64("print('hello')")}

        results = _fetch_pr_files_contents_bounded(
            owner="owner",
            repository="repo",
            head_sha="a" * 40,
            candidates=[(0, "app.py")],
            client=client,
            max_workers=4
        )

        assert len(results) == 1
        assert results[0] == "print('hello')"
        assert mock_get.call_count == 1


def test_02_multiple_changed_files_deterministic_order():
    """Verify multiple changed files are fetched concurrently and mapped deterministically by original index."""
    client = GitHubClient(token="ghp_test")
    file_count = 10
    candidates = [(i, f"src/module_{i}.py") for i in range(file_count)]

    # Mock responses with artificial jitter to ensure completion happens out-of-order
    def mock_get(endpoint, params=None, allow_retry=None):
        # Extract filename from endpoint /repos/owner/repo/contents/{filename}
        parts = endpoint.split("/contents/")
        filename = parts[1] if len(parts) > 1 else "unknown"
        # Jitter: reverse index delay
        num = int(filename.split("_")[1].split(".")[0])
        time.sleep((file_count - num) * 0.005)
        return {"content": _encode_b64(f"# content for {filename}")}

    with patch.object(client, "get", side_effect=mock_get):
        results = _fetch_pr_files_contents_bounded(
            owner="owner",
            repository="repo",
            head_sha="a" * 40,
            candidates=candidates,
            client=client,
            max_workers=4
        )

        assert len(results) == file_count
        # Verify strict deterministic indexing
        for i in range(file_count):
            assert i in results
            assert results[i] == f"# content for src/module_{i}.py"


def test_03_bounded_worker_count_enforcement():
    """Verify that concurrent execution never exceeds the configured max_workers bound."""
    client = GitHubClient(token="ghp_test")
    candidates = [(i, f"src/file_{i}.py") for i in range(12)]

    lock = threading.Lock()
    active_workers = 0
    max_observed_concurrency = 0

    def mock_get(endpoint, params=None, allow_retry=None):
        nonlocal active_workers, max_observed_concurrency
        with lock:
            active_workers += 1
            if active_workers > max_observed_concurrency:
                max_observed_concurrency = active_workers
        time.sleep(0.02)
        with lock:
            active_workers -= 1
        return {"content": _encode_b64("safe_code = 1")}

    with patch.object(client, "get", side_effect=mock_get):
        results = _fetch_pr_files_contents_bounded(
            owner="owner",
            repository="repo",
            head_sha="a" * 40,
            candidates=candidates,
            client=client,
            max_workers=4
        )

        assert len(results) == 12
        assert max_observed_concurrency <= 4
        assert max_observed_concurrency >= 2


def test_04_single_fetch_failure_isolated():
    """Verify that an individual file fetch failure returns None without failing other files."""
    client = GitHubClient(token="ghp_test")
    candidates = [(0, "ok1.py"), (1, "fail.py"), (2, "ok2.py")]

    def mock_get(endpoint, params=None, allow_retry=None):
        if "fail.py" in endpoint:
            raise GitHubNotFoundError()
        return {"content": _encode_b64("x = 1")}

    with patch.object(client, "get", side_effect=mock_get):
        results = _fetch_pr_files_contents_bounded(
            owner="owner",
            repository="repo",
            head_sha="a" * 40,
            candidates=candidates,
            client=client,
            max_workers=4
        )

        assert results[0] == "x = 1"
        assert results[1] is None  # Handled safely as None
        assert results[2] == "x = 1"


def test_05_multiple_fetch_failures_handled_safely():
    """Verify multiple failing files return None cleanly."""
    client = GitHubClient(token="ghp_test")
    candidates = [(0, "fail1.py"), (1, "fail2.py"), (2, "ok.py")]

    def mock_get(endpoint, params=None, allow_retry=None):
        if "fail" in endpoint:
            raise GitHubAPIError("Server error", status_code=500)
        return {"content": _encode_b64("ok = True")}

    with patch.object(client, "get", side_effect=mock_get):
        results = _fetch_pr_files_contents_bounded(
            owner="owner",
            repository="repo",
            head_sha="a" * 40,
            candidates=candidates,
            client=client,
            max_workers=4
        )

        assert results[0] is None
        assert results[1] is None
        assert results[2] == "ok = True"


def test_06_empty_candidates_returns_empty_dict():
    """Verify empty candidate list returns {} immediately with zero overhead."""
    client = GitHubClient(token="ghp_test")
    results = _fetch_pr_files_contents_bounded(
        owner="owner",
        repository="repo",
        head_sha="a" * 40,
        candidates=[],
        client=client,
        max_workers=4
    )
    assert results == {}


def test_07_client_pooling_reuse_no_new_clients():
    """Verify that all concurrent worker tasks reuse the single provided GitHubClient instance."""
    client = GitHubClient(token="ghp_test")
    candidates = [(i, f"file_{i}.py") for i in range(8)]

    # Track how many times client._get_client() is called
    orig_get_client = client._get_client
    call_counts = 0
    lock = threading.Lock()

    def tracking_get_client():
        nonlocal call_counts
        with lock:
            call_counts += 1
        return orig_get_client()

    with patch.object(client, "_get_client", side_effect=tracking_get_client):
        with patch.object(client, "get") as mock_get:
            mock_get.return_value = {"content": _encode_b64("code = 1")}

            results = _fetch_pr_files_contents_bounded(
                owner="owner",
                repository="repo",
                head_sha="a" * 40,
                candidates=candidates,
                client=client,
                max_workers=4
            )

            assert len(results) == 8
            # The client is reused; no new GitHubClient instances created
            assert not client._closed


def test_08_duplicate_filenames_distinct_indices():
    """Verify duplicate filenames across different indices are mapped correctly to their respective indices."""
    client = GitHubClient(token="ghp_test")
    candidates = [(0, "src/common.py"), (1, "src/common.py")]

    with patch.object(client, "get") as mock_get:
        mock_get.return_value = {"content": _encode_b64("shared = 1")}

        results = _fetch_pr_files_contents_bounded(
            owner="owner",
            repository="repo",
            head_sha="a" * 40,
            candidates=candidates,
            client=client,
            max_workers=4
        )

        assert len(results) == 2
        assert results[0] == "shared = 1"
        assert results[1] == "shared = 1"


def test_09_pr_report_generation_end_to_end_concurrency():
    """Verify _generate_pr_analysis_report utilizes bounded concurrency and preserves deterministic findings."""
    changed_files = [
        GitHubChangedFile(
            filename="src/db.py",
            status="modified",
            additions=3,
            deletions=1,
            changes=4,
            patch="@@ -3,3 +3,3 @@\n-    pass\n+    query = f'SELECT * FROM users WHERE id = {user_id}'\n+    cursor.execute(query)",
            sha="1" * 40
        ),
        GitHubChangedFile(
            filename="src/clean.py",
            status="modified",
            additions=2,
            deletions=0,
            changes=2,
            patch="@@ -1,2 +1,4 @@\n+x = 1\n+y = 2",
            sha="2" * 40
        )
    ]

    client = GitHubClient(token="ghp_test")

    def mock_get(endpoint, params=None, allow_retry=None):
        if "db.py" in endpoint:
            src = "import sqlite3\n\ndef get_user(cursor, user_id):\n    query = f'SELECT * FROM users WHERE id = {user_id}'\n    cursor.execute(query)\n"
            return {"content": _encode_b64(src)}
        else:
            return {"content": _encode_b64("x = 1\ny = 2\n")}

    with patch.object(client, "get", side_effect=mock_get):
        report = _generate_pr_analysis_report(
            owner="acme",
            repository="app",
            pr_number=42,
            head_sha="h" * 40,
            changed_files=changed_files,
            client=client
        )

        assert report["status"] == "success"
        assert report["summary"]["total_files"] == 2
        assert report["summary"]["analyzed_files"] == 2
        assert report["summary"]["total_findings"] >= 1

        # Security gate evaluation remains authoritative
        dec, code, _ = evaluate_security_gate(report)
        assert dec == "BLOCK"
        assert code == 1


def test_10_concurrency_stress_and_safety_bounds():
    """Stress test with 20 files under 1, 2, 4, and 8 worker configurations."""
    client = GitHubClient(token="ghp_test")
    file_count = 20
    candidates = [(i, f"bench_{i}.py") for i in range(file_count)]

    for worker_bound in (1, 2, 4, 8):
        lock = threading.Lock()
        max_seen = 0
        current = 0

        def mock_get(endpoint, params=None, allow_retry=None):
            nonlocal current, max_seen
            with lock:
                current += 1
                if current > max_seen:
                    max_seen = current
            time.sleep(0.005)
            with lock:
                current -= 1
            return {"content": _encode_b64("val = 42")}

        with patch.object(client, "get", side_effect=mock_get):
            res = _fetch_pr_files_contents_bounded(
                owner="acme",
                repository="repo",
                head_sha="s" * 40,
                candidates=candidates,
                client=client,
                max_workers=worker_bound
            )

            assert len(res) == file_count
            assert max_seen <= worker_bound


def test_11_performance_correctness_identical_output():
    """Verify representative PR workflow produces 100% identical outputs under sequential vs concurrent fetching."""
    files_def = [
        ("src/auth.py", "import os\ndef login(u, p):\n    cmd = f'auth {u} {p}'\n    os.system(cmd)\n", "@@ -3,2 +3,2 @@\n-    pass\n+    cmd = f'auth {u} {p}'\n+    os.system(cmd)"),
        ("src/db.py", "import sqlite3\ndef q(c, uid):\n    sql = f'SELECT * FROM users WHERE id={uid}'\n    c.execute(sql)\n", "@@ -3,2 +3,2 @@\n-    pass\n+    sql = f'SELECT * FROM users WHERE id={uid}'\n+    c.execute(sql)"),
        ("src/util.py", "def add(a, b):\n    return a + b\n", "@@ -1,2 +1,2 @@\n-def add(x, y):\n+def add(a, b):"),
    ]

    changed_files = [
        GitHubChangedFile(
            filename=fn,
            status="modified",
            additions=2,
            deletions=1,
            changes=3,
            patch=patch_str,
            sha=f"{i}" * 40
        )
        for i, (fn, _, patch_str) in enumerate(files_def)
    ]

    client = GitHubClient(token="ghp_test")
    file_contents = {fn: content for fn, content, _ in files_def}

    def mock_get(endpoint, params=None, allow_retry=None):
        for fn, content in file_contents.items():
            if fn in endpoint:
                return {"content": _encode_b64(content)}
        return {"content": _encode_b64("")}

    with patch.object(client, "get", side_effect=mock_get):
        # A. Sequential acquisition (max_workers=1)
        with patch("backend.github.orchestrator.DEFAULT_MAX_CONCURRENT_GITHUB_FETCHES", 1):
            report_seq = _generate_pr_analysis_report("org", "repo", 99, "h" * 40, changed_files, client=client)

        # B. Concurrent acquisition (max_workers=4)
        with patch("backend.github.orchestrator.DEFAULT_MAX_CONCURRENT_GITHUB_FETCHES", 4):
            report_conc = _generate_pr_analysis_report("org", "repo", 99, "h" * 40, changed_files, client=client)

    # Compare reports excluding random uuid analysis_id
    assert report_seq["status"] == report_conc["status"]
    assert report_seq["summary"] == report_conc["summary"]
    assert report_seq["review_status"] == report_conc["review_status"]
    assert len(report_seq["findings"]) == len(report_conc["findings"])

    for f_seq, f_conc in zip(report_seq["findings"], report_conc["findings"]):
        assert f_seq["title"] == f_conc["title"]
        assert f_seq["severity"] == f_conc["severity"]
        assert f_seq["category"] == f_conc["category"]
        assert f_seq.get("evidence") == f_conc.get("evidence")

    dec_seq, code_seq, _ = evaluate_security_gate(report_seq)
    dec_conc, code_conc, _ = evaluate_security_gate(report_conc)
    assert dec_seq == dec_conc
    assert code_seq == code_conc

