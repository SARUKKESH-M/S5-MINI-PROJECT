"""Focused Verification Test Suite for CodeSentinel Upgrade 1B2:
Large-Repository File Discovery, Filtering, and Loading Throughput Optimization.

Tests:
1. Discovery correctness: recursive discovery, language mapping, size tracking, exclusion sets, and limits.
2. Scope exclusion engine: fast-path suffix matching, directory traversal normalization, custom patterns.
3. Safe file reader: regular file check, size thresholding, fast binary detection, path traversal rejection.
4. End-to-end repository loading: small (20), medium (100), and large (500 + 1000 excluded) repos.
5. Deterministic sorting: read files are deterministically ordered by relative path.
6. Throughput verification: large-repo loading achieves >= 5,000 files/s and <= 150ms duration.
"""

import os
import sys
import tempfile
import time
import pytest

# Ensure workspace root and backend are on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.repository.acquirer import acquire_repository
from backend.repository.analyzer import prepare_repository_analysis_files
from backend.repository.discovery import (
    discover_source_files,
    SUPPORTED_EXTENSIONS,
    EXCLUDED_DIRECTORIES,
    MAX_SOURCE_FILES,
    MAX_TOTAL_SOURCE_BYTES,
)
from backend.repository.reader import (
    read_source_file,
    is_binary_content,
    MAX_FILE_SIZE,
)
from backend.analysis.scope import (
    should_exclude_path,
    DEFAULT_EXCLUDED_DIRECTORIES,
    DEFAULT_EXCLUDED_PATTERNS,
)
from tests.test_phase_upgrade_1_representative_benchmarks import _build_synthetic_repo


def test_1_discovery_correctness():
    """Verify discover_source_files finds all supported files and excludes ignored directories."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        repo_dir = _build_synthetic_repo(temp_dir, 50, 2, 10)

        discovered = discover_source_files(repo_dir)
        assert len(discovered) == 50
        assert not any("node_modules" in d["path"] for d in discovered)
        assert not any(".venv" in d["path"] for d in discovered)

        # Check fields
        first = discovered[0]
        assert "path" in first
        assert "abs_path" in first
        assert "language" in first
        assert "extension" in first
        assert "size_bytes" in first
        assert first["language"] == "python"
        assert first["extension"] == ".py"
        assert first["size_bytes"] > 0


def test_2_scope_exclusion_fast_path():
    """Verify should_exclude_path correctly handles fast suffixes, traversal markers, and custom patterns."""
    assert should_exclude_path("dist/bundle.min.js") is True
    assert should_exclude_path("build/output.map") is True
    assert should_exclude_path("module.pyc") is True
    assert should_exclude_path("native.dll") is True
    assert should_exclude_path("node_modules/package/index.js") is True
    assert should_exclude_path("tests/unit/test_app.py") is True
    assert should_exclude_path("src/service.py") is False
    assert should_exclude_path("app/utils.js") is False

    # Path traversal segments
    assert should_exclude_path("src/../node_modules/bad.js") is True

    # Custom glob patterns
    assert should_exclude_path("src/generated/code.py", custom_exclude_patterns=["*generated*"]) is True
    assert should_exclude_path("src/normal/code.py", custom_exclude_patterns=["*generated*"]) is False


def test_3_safe_reader_binary_and_size_limits():
    """Verify read_source_file respects MAX_FILE_SIZE, binary detection, and path boundary."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        repo_dir = os.path.join(temp_dir, "repo")
        os.makedirs(repo_dir, exist_ok=True)

        # Normal text file
        normal_path = os.path.join(repo_dir, "normal.py")
        with open(normal_path, "w", encoding="utf-8") as f:
            f.write("def hello(): return 'world'\n")

        res_normal = read_source_file("normal.py", repo_dir)
        assert res_normal["skipped"] is False
        assert "def hello" in res_normal["source_code"]
        assert res_normal["language"] == "python"

        # Binary file
        bin_path = os.path.join(repo_dir, "binary.py")
        with open(bin_path, "wb") as f:
            f.write(b"\x00\x01\x02\x03\x04binary\x00data")

        res_bin = read_source_file("binary.py", repo_dir)
        assert res_bin["skipped"] is True
        assert res_bin["reason"] == "binary_content"

        # Oversized file
        big_path = os.path.join(repo_dir, "big.py")
        with open(big_path, "wb") as f:
            f.write(b"x" * (MAX_FILE_SIZE + 10))

        res_big = read_source_file("big.py", repo_dir)
        assert res_big["skipped"] is True
        assert res_big["reason"] == "exceeds MAX_FILE_SIZE"

        # Path traversal escape attempt
        with pytest.raises(ValueError, match="escapes repository boundary"):
            read_source_file("../outside.py", repo_dir)


def test_4_end_to_end_loading_and_deterministic_order():
    """Verify prepare_repository_analysis_files produces deterministic, correctly filtered output."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        repo_dir = _build_synthetic_repo(temp_dir, 30, 2, 5)
        acq_id = acquire_repository(
            repository_url="https://github.com/example/test.git",
            local_path=repo_dir,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        meta, read_files, file_stats = prepare_repository_analysis_files(acq_id, workspace_root=temp_dir)

        assert file_stats["total_files"] == 30
        assert file_stats["analyzed_files"] == 30
        assert file_stats["skipped_files"] == 0
        assert len(read_files) == 30

        # Verify deterministic alphabetical sorting
        paths = [f["path"] for f in read_files]
        assert paths == sorted(paths)


def test_5_large_repository_throughput_benchmark():
    """Verify large repo loading satisfies Duration <= 150ms and Throughput >= 5,000 files/s."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        large_repo = _build_synthetic_repo(temp_dir, 500, 1, 1000)
        acq_large = acquire_repository(
            repository_url="https://github.com/example/large.git",
            local_path=large_repo,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        # 2-pass warmup to allow OS directory buffers and filesystem caches to stabilize
        prepare_repository_analysis_files(acq_large, workspace_root=temp_dir, max_files=1000)
        prepare_repository_analysis_files(acq_large, workspace_root=temp_dir, max_files=1000)

        import gc
        gc.collect()
        gc_was_enabled = gc.isenabled()
        gc.disable()

        durations_ms = []
        try:
            for _ in range(7):
                t0 = time.perf_counter()
                meta, files, stats = prepare_repository_analysis_files(acq_large, workspace_root=temp_dir, max_files=1000)
                t1 = time.perf_counter()
                durations_ms.append((t1 - t0) * 1000.0)
                assert len(files) == 500
                assert stats["total_files"] == 500
        finally:
            if gc_was_enabled:
                gc.enable()

        import statistics
        median_ms = statistics.median(durations_ms)
        throughput_fps = 500.0 / (median_ms / 1000.0)

        assert median_ms <= 150.0, f"Duration {median_ms:.2f}ms exceeds target 150ms"
        assert throughput_fps >= 5000.0, f"Throughput {throughput_fps:.1f} files/s below target 5,000 files/s"

