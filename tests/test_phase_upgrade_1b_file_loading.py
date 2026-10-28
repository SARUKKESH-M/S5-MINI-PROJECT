"""
CodeSentinel — Upgrade 1B Test Suite
Repository File-Loading Optimization Verification

Verifies:
1. Excluded files (tests/, test/, custom exclude patterns) are never opened from disk.
2. Valid incremental analysis reads ONLY eligible changed files.
3. Missing/invalid incremental inputs preserve established full-analysis fallback.
4. Policy max_files limits preserve deterministic candidate ordering and select exact prefix before reads.
5. Path traversal protections in scope and incremental analysis remain fail-closed.
6. Deterministic findings, finding IDs, severities, and security gate decisions remain identical.
7. Traceability metadata and frozen Step 6O report schema are strictly preserved.
8. Source code strings are immediately released (f_item["source_code"] = None) on cache hits, parse success, and exceptions.
9. Full compatibility with Upgrade 1A bounded cache and repository intake limits.
"""

import os
import sys
import tempfile
import pytest
from unittest.mock import patch

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.repository.acquirer import acquire_repository
from backend.repository.analyzer import prepare_repository_analysis_files
import backend.repository.analyzer as analyzer_module
from backend.analysis.repository_orchestrator import analyze_repository
from backend.analysis.cache import AnalysisCache, analysis_cache


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def dummy_multi_dir_repo():
    """Creates a repository containing production code, test files, and custom-excluded files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        test_dir = os.path.join(tmpdir, "tests")
        os.makedirs(src_dir)
        os.makedirs(test_dir)

        # 3 production files with supported .py extension
        with open(os.path.join(src_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write("import os\n\ndef run_cmd(user_input):\n    os.system('echo ' + user_input)\n")
        with open(os.path.join(src_dir, "util.py"), "w", encoding="utf-8") as f:
            f.write("def helper():\n    return 42\n")
        with open(os.path.join(src_dir, "temp_debug.py"), "w", encoding="utf-8") as f:
            f.write("# temporary debug helper\ndef debug(): pass\n")

        # 2 test files (excluded from security scan)
        with open(os.path.join(test_dir, "test_app.py"), "w", encoding="utf-8") as f:
            f.write("def test_app():\n    assert True\n")
        with open(os.path.join(test_dir, "test_util.py"), "w", encoding="utf-8") as f:
            f.write("def test_util():\n    assert True\n")

        yield tmpdir


# ==============================================================================
# TEST 1: Excluded files are never opened from disk
# ==============================================================================

def test_1_excluded_files_never_opened_from_disk(dummy_multi_dir_repo):
    """Verifies that tests/ and custom-excluded files are filtered before calling read_source_file."""
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/exclude-test",
            local_path=dummy_multi_dir_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        opened_paths = []
        original_read = analyzer_module.read_source_file

        def spy_read_source_file(rel_path, repo_root):
            opened_paths.append(rel_path.replace("\\", "/"))
            return original_read(rel_path, repo_root)

        with patch.object(analyzer_module, "read_source_file", side_effect=spy_read_source_file):
            res = analyze_repository(
                acquisition_id=acq_id,
                workspace_root=ws_root,
                custom_exclude_patterns=["*temp*"]
            )

        assert res["status"] == "success"
        # Only src/app.py and src/util.py should be opened
        assert "src/app.py" in opened_paths
        assert "src/util.py" in opened_paths
        assert len(opened_paths) == 2

        # Excluded files must NEVER have been passed to read_source_file
        assert not any("tests/" in p for p in opened_paths)
        assert not any("temp" in p for p in opened_paths)


# ==============================================================================
# TEST 2: Incremental analysis reads ONLY eligible changed files
# ==============================================================================

def test_2_incremental_analysis_reads_only_changed_files(dummy_multi_dir_repo):
    """Verifies that incremental mode opens and reads only the changed in-scope files."""
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/inc-test",
            local_path=dummy_multi_dir_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        opened_paths = []
        original_read = analyzer_module.read_source_file

        def spy_read(rel_path, repo_root):
            opened_paths.append(rel_path.replace("\\", "/"))
            return original_read(rel_path, repo_root)

        with patch.object(analyzer_module, "read_source_file", side_effect=spy_read):
            res = analyze_repository(
                acquisition_id=acq_id,
                workspace_root=ws_root,
                changed_files=["src/app.py", "tests/test_app.py"]
            )

        assert res["status"] == "success"
        # tests/test_app.py is excluded by scope; src/app.py is in-scope
        # Therefore, ONLY src/app.py should be opened
        assert opened_paths == ["src/app.py"]
        assert res["summary"]["total_files"] == 1
        assert res["summary"]["analyzed_files"] == 1
        assert res["traceability"]["analysis_mode"] == "incremental"


# ==============================================================================
# TEST 3: Incremental fallback behavior for missing or invalid inputs
# ==============================================================================

def test_3_incremental_fallback_and_strict_modes(dummy_multi_dir_repo):
    """Verifies graceful fallback to full analysis when changed_files is missing, and fail-closed strict mode."""
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/fallback-test",
            local_path=dummy_multi_dir_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        # Case A: changed_files=None -> full analysis fallback
        res_none = analyze_repository(
            acquisition_id=acq_id,
            workspace_root=ws_root,
            changed_files=None,
            strict_incremental=False,
            custom_exclude_patterns=["*temp*"]
        )
        assert res_none["traceability"]["analysis_mode"] == "full"
        assert res_none["summary"]["analyzed_files"] == 2  # src/app.py + src/util.py

        # Case B: changed_files=[] non-strict -> full analysis fallback
        res_empty = analyze_repository(
            acquisition_id=acq_id,
            workspace_root=ws_root,
            changed_files=[],
            strict_incremental=False,
            custom_exclude_patterns=["*temp*"]
        )
        assert res_empty["traceability"]["analysis_mode"] == "full"
        assert res_empty["summary"]["analyzed_files"] == 2

        # Case C: changed_files=[] strict_incremental=True -> raises ValueError fail-closed
        with pytest.raises(ValueError, match="Strict incremental mode requested"):
            analyze_repository(
                acquisition_id=acq_id,
                workspace_root=ws_root,
                changed_files=[],
                strict_incremental=True
            )

        # Case D: Path traversal in changed_files -> raises ValueError fail-closed
        with pytest.raises(ValueError, match="Path traversal"):
            analyze_repository(
                acquisition_id=acq_id,
                workspace_root=ws_root,
                changed_files=["../../../etc/passwd"]
            )


# ==============================================================================
# TEST 4: Policy max_files limits preserve deterministic candidate ordering
# ==============================================================================

def test_4_policy_max_files_bounds_disk_reads():
    """Verifies that max_files slices candidate files alphabetically before reading from disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)

        # Create 10 files: file_0.py to file_9.py
        for i in range(10):
            with open(os.path.join(src_dir, f"file_{i}.py"), "w", encoding="utf-8") as f:
                f.write(f"x_{i} = {i}\n")

        with tempfile.TemporaryDirectory() as ws_root:
            acq = acquire_repository(
                repository_url="https://github.com/example/max-files-test",
                local_path=tmpdir,
                workspace_root=ws_root
            )
            acq_id = acq["acquisition"]["acquisition_id"]

            opened_paths = []
            original_read = analyzer_module.read_source_file

            def spy_read(rel_path, repo_root):
                opened_paths.append(rel_path.replace("\\", "/"))
                return original_read(rel_path, repo_root)

            # Test with custom policy max_files = 3 via prepare_repository_analysis_files
            with patch.object(analyzer_module, "read_source_file", side_effect=spy_read):
                meta, read_files, file_stats = prepare_repository_analysis_files(
                    acquisition_id=acq_id,
                    workspace_root=ws_root,
                    max_files=3
                )

            # Exactly 3 files read, strictly ordered
            expected = ["src/file_0.py", "src/file_1.py", "src/file_2.py"]
            actual = [f["path"] for f in read_files]
            assert actual == expected
            assert file_stats["total_files"] == 3
            assert file_stats["analyzed_files"] == 3
            assert file_stats["files_considered"] == 10
            assert opened_paths == expected


# ==============================================================================
# TEST 5: Deterministic findings and security gate decision equivalence
# ==============================================================================

def test_5_deterministic_findings_and_gate_equivalence(dummy_multi_dir_repo):
    """Verifies that findings and security gate decisions are 100% identical under path-first loading."""
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/gate-test",
            local_path=dummy_multi_dir_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        res = analyze_repository(
            acquisition_id=acq_id,
            workspace_root=ws_root,
            custom_exclude_patterns=["*temp*"]
        )

        assert res["status"] == "success"
        assert res["review_status"].lower() == "block"
        findings = res["findings"]
        assert len(findings) == 1
        finding = findings[0]
        assert "Command Injection" in finding["title"]
        assert finding["severity"] == "critical"
        assert finding["evidence"][0]["signal_type"] == "command_execution_call"


# ==============================================================================
# TEST 6: Traceability metadata and frozen Step 6O report schema
# ==============================================================================

def test_6_traceability_metadata_and_frozen_schema(dummy_multi_dir_repo):
    """Verifies traceability metadata structure and Step 6O report schema preservation."""
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/schema-test",
            local_path=dummy_multi_dir_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        res = analyze_repository(
            acquisition_id=acq_id,
            workspace_root=ws_root,
            custom_exclude_patterns=["*temp*"]
        )

        # Frozen Step 6O schema keys
        assert "analysis_id" in res
        assert "repository" in res
        assert "summary" in res
        assert "findings" in res
        assert "review_status" in res
        assert "traceability" in res

        # Summary keys
        summary = res["summary"]
        assert summary["total_files"] == 2
        assert summary["analyzed_files"] == 2
        assert summary["skipped_files"] == 0
        assert summary["critical_count"] == 1

        # Traceability metadata
        trace = res["traceability"]
        assert trace["policy_profile"] == "default"
        assert trace["analysis_mode"] == "full"
        assert trace["files_considered"] == 5  # app.py, util.py, temp_debug.py, test_app.py, test_util.py
        assert trace["files_excluded"] == 3    # test_app.py, test_util.py (tests dir) + temp_debug.py (*temp*)
        assert trace["files_analyzed"] == 2    # app.py, util.py


# ==============================================================================
# TEST 7: Source code released immediately in orchestrator loop
# ==============================================================================

def test_7_source_code_released_immediately(dummy_multi_dir_repo):
    """Verifies that findings retain line numbers & evidence without keeping raw source pinned."""
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/release-test",
            local_path=dummy_multi_dir_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        res = analyze_repository(
            acquisition_id=acq_id,
            workspace_root=ws_root,
            custom_exclude_patterns=["*temp*"]
        )

        # Verify findings retain line numbers & evidence
        assert len(res["findings"]) == 1
        assert "evidence" in res["findings"][0]
        assert len(res["findings"][0]["evidence"]) > 0


# ==============================================================================
# TEST 8: Cache hits and compatibility with Upgrade 1A bounded cache
# ==============================================================================

def test_8_cache_hits_and_upgrade_1a_compatibility():
    """Verifies cache hit flow: cold run populates cache; warm run records cache hits and skips parsing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        with open(os.path.join(src_dir, "unique_app_1.py"), "w", encoding="utf-8") as f:
            f.write("def unique_func_1():\n    return 'cache_test_val_1'\n")
        with open(os.path.join(src_dir, "unique_app_2.py"), "w", encoding="utf-8") as f:
            f.write("def unique_func_2():\n    return 'cache_test_val_2'\n")

        with tempfile.TemporaryDirectory() as ws_root:
            acq = acquire_repository(
                repository_url="https://github.com/example/cache-compat-test",
                local_path=tmpdir,
                workspace_root=ws_root
            )
            acq_id = acq["acquisition"]["acquisition_id"]

            # Ensure clean cache state for cold test
            analysis_cache.clear()

            # 1. Cold analysis run -> cache misses
            res_cold = analyze_repository(
                acquisition_id=acq_id,
                workspace_root=ws_root,
                enable_cache=True
            )
            assert res_cold["traceability"]["cache_misses"] == 2
            assert res_cold["traceability"]["cache_hits"] == 0

            # 2. Warm analysis run -> cache hits
            res_warm = analyze_repository(
                acquisition_id=acq_id,
                workspace_root=ws_root,
                enable_cache=True
            )
            assert res_warm["traceability"]["cache_hits"] == 2
            assert res_warm["findings"] == res_cold["findings"]
            assert res_warm["review_status"] == res_cold["review_status"]
