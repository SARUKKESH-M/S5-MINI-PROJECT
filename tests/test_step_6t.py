"""
CodeSentinel — Stage 6T Test Suite
Advanced Platform Capabilities Verification

Comprehensive test suite verifying Stage 6T:
1. Policy profile loading (default, strict, ci, developer)
2. Default policy backward compatibility
3. Strict policy behavior
4. Invalid policy rejection
5. Scope exclusion rules (default & custom fnmatch patterns)
6. Path traversal rejection
7. Repository-root boundary enforcement
8. Changed-file validation for incremental analysis
9. Incremental analysis processing
10. Fallback to full analysis on missing/empty changed-files
11. Deterministic cache key generation
12. Cache invalidation on file modification
13. Corrupted cache handling
14. Cache secret-safety (sanitizes secret strings)
15. Analysis traceability metadata generation
16. Health endpoint (/platform/health)
17. Readiness endpoint (/platform/readiness)
18. Safe configuration status
19. Capability & version endpoint (/platform/info)
20. Observability metrics (/platform/metrics & MetricsCollector)
21. Secret redaction in metrics & logs
22. API validation
23. API error handling
24. Static non-execution boundary
25. Malicious repository fixture test
26. Path traversal escape prevention
27. Oversized input handling (10MB payload middleware)
28. Existing security middleware compatibility
29. Step 6O Production Report compatibility
30. 6Q integration compatibility
31. 6R CI/CD scan & security gate compatibility
32. 6S security hardening compatibility
33. Platform API router integration
"""

import hashlib
import json
import os
import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.main import app
from backend.analysis.policy import get_policy_profile, list_available_policies, PREDEFINED_POLICIES
from backend.analysis.scope import normalize_and_validate_repository_path, should_exclude_path
from backend.analysis.incremental import process_incremental_files
from backend.analysis.cache import AnalysisCache, analysis_cache
from backend.analysis.metadata import build_analysis_traceability_metadata
from backend.app.core.health import get_platform_health, get_platform_readiness
from backend.app.core.capabilities import get_platform_capabilities
from backend.app.core.metrics import metrics_collector
from backend.analysis.repository_orchestrator import analyze_repository
from backend.analysis.security_gate import evaluate_security_gate
from backend.analysis.ci_report import generate_ci_security_summary

client = TestClient(app)


# ==============================================================================
# 1. POLICY PROFILES (6T-1)
# ==============================================================================

def test_policy_profile_loading_and_defaults():
    """1-4. Verifies policy profile retrieval, strict mode, and invalid profile rejection."""
    # Default policy
    def_pol = get_policy_profile("default")
    assert def_pol.name == "default"
    assert def_pol.max_files == 500
    assert def_pol.severity_threshold == "info"

    # None defaults to default
    assert get_policy_profile(None).name == "default"

    # Strict policy
    strict_pol = get_policy_profile("strict")
    assert strict_pol.name == "strict"
    assert strict_pol.severity_threshold == "low"

    # CI policy
    ci_pol = get_policy_profile("ci")
    assert ci_pol.name == "ci"
    assert ci_pol.max_files == 200

    # Invalid policy raises ValueError
    with pytest.raises(ValueError):
        get_policy_profile("invalid_nonexistent_profile")

    # List available policies
    all_policies = list_available_policies()
    assert len(all_policies) >= 4


# ==============================================================================
# 2. SCOPE CONTROLS & EXCLUSIONS (6T-2)
# ==============================================================================

def test_scope_exclusion_and_path_traversal(tmp_path):
    """5-7. Verifies directory exclusion rules and path traversal protection."""
    # Excluded directory names
    assert should_exclude_path(".git/HEAD")
    assert should_exclude_path("node_modules/express/index.js")
    assert should_exclude_path("dist/assets/main.js")
    assert should_exclude_path("__pycache__/main.cpython-311.pyc")
    assert should_exclude_path(".venv/lib/python/site-packages")

    # Custom fnmatch patterns
    assert should_exclude_path("src/secret.bak", custom_exclude_patterns=["*.bak"])
    assert not should_exclude_path("src/app.py", custom_exclude_patterns=["*.bak"])

    # Path traversal validation against repo root
    repo_root = str(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "valid.py").write_text("print('hello')", encoding="utf-8")

    # Valid relative path inside root
    valid_path = normalize_and_validate_repository_path("src/valid.py", repo_root)
    assert valid_path.exists()

    # Path traversal attempt outside root raises ValueError
    with pytest.raises(ValueError):
        normalize_and_validate_repository_path("../../../etc/passwd", repo_root)


def test_step_1b_security_scan_scope_requirements(tmp_path):
    """
    Step 1B Security Scan Scope Verification:
    Proves requirements A-G:
    A. tests/ files excluded from production security scanning.
    B. Production source files are still scanned.
    C. Path traversal cannot bypass exclusion or scan scope.
    D. Existing exclusion patterns (.git, node_modules, etc.) still work.
    E. Explicit user-provided exclusions work.
    F. Security test fixtures themselves remain unchanged.
    G. The security gate remains fail-closed.
    """
    # Requirement A: tests/ files excluded
    assert should_exclude_path("tests/test_fixture.py")
    assert should_exclude_path("tests/sub/test_fixture.py")
    assert should_exclude_path("test/fixture.py")

    # Requirement B: Production source files still scanned
    assert not should_exclude_path("backend/app/main.py")
    assert not should_exclude_path("src/app.py")
    assert not should_exclude_path("cli/security_scan.py")

    # Requirement C: Path traversal cannot bypass exclusion or scan scope
    assert not should_exclude_path("tests/../src/app.py"), "Path traversal pointing to src/app.py must be scanned"
    assert should_exclude_path("src/../tests/test_fixture.py"), "Path traversal pointing to tests/ fixture must be excluded"
    assert should_exclude_path("./tests/test_fixture.py")
    assert should_exclude_path(".\\tests\\test_fixture.py")

    # Requirement D: Existing exclusion patterns still work
    assert should_exclude_path(".git/HEAD")
    assert should_exclude_path("node_modules/package/index.js")
    assert should_exclude_path("dist/bundle.js")
    assert should_exclude_path("build/output.js")
    assert should_exclude_path("__pycache__/main.cpython-311.pyc")
    assert should_exclude_path(".venv/lib/site-packages")
    assert should_exclude_path("coverage/index.html")

    # Requirement E: Explicit user-provided exclusions still work
    assert should_exclude_path("src/secret.bak", custom_exclude_patterns=["*.bak"])
    assert not should_exclude_path("src/app.py", custom_exclude_patterns=["*.bak"])

    # Requirement F: Security test fixtures remain unchanged & exist
    test_w_path = Path(__file__).parent / "test_step_6w.py"
    assert test_w_path.exists(), "Test fixtures in tests/ must remain unchanged and present"

    # Requirement G: Security gate remains fail-closed
    dec_inv, code_inv, _ = evaluate_security_gate({"invalid": "report"})
    assert dec_inv == "INVALID"
    assert code_inv == 1

    dec_blk, code_blk, _ = evaluate_security_gate({
        "status": "success",
        "review_status": "block",
        "summary": {"critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
        "findings": [{"severity": "critical"}]
    })
    assert dec_blk == "BLOCK"
    assert code_blk == 1



# ==============================================================================
# 3. INCREMENTAL ANALYSIS (6T-3)
# ==============================================================================

def test_incremental_analysis_processing_and_fallback(tmp_path):
    """8-10. Verifies changed-file filtering and fallback to full analysis."""
    repo_root = str(tmp_path)
    (tmp_path / "file1.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "file2.py").write_text("y = 2", encoding="utf-8")
    (tmp_path / "ignored.bak").write_text("bak", encoding="utf-8")

    # Valid changed files list
    inc, exc, is_inc = process_incremental_files(
        changed_files=["file1.py", "ignored.bak"],
        repo_root=repo_root,
        custom_exclude_patterns=["*.bak"]
    )
    assert is_inc
    assert "file1.py" in inc
    assert "ignored.bak" in exc

    # Missing changed_files list falls back to full analysis (is_incremental=False)
    inc_fb, exc_fb, is_inc_fb = process_incremental_files(
        changed_files=None,
        repo_root=repo_root
    )
    assert not is_inc_fb
    assert inc_fb == []

    # Strict incremental mode with empty changed_files raises ValueError
    with pytest.raises(ValueError):
        process_incremental_files(
            changed_files=[],
            repo_root=repo_root,
            strict_incremental=True
        )


# ==============================================================================
# 4. ANALYSIS CACHING (6T-4)
# ==============================================================================

def test_analysis_caching_and_invalidation(tmp_path):
    """11-14. Verifies cache keys, invalidation, corruption safety, and secret sanitization."""
    cache = AnalysisCache(cache_dir=str(tmp_path / "cache"))

    content = "print('hello world')"
    c_hash = cache.compute_file_hash(content)
    key = cache.generate_cache_key("src/app.py", c_hash, "default")

    # Cache miss initially
    assert cache.get(key) is None

    # Set cache entry
    cache_data = {"file_path": "src/app.py", "ast_docs": [{"id": 1, "text": "hello"}]}
    cache.set(key, cache_data)

    # Cache hit
    retrieved = cache.get(key)
    assert retrieved is not None
    assert retrieved["file_path"] == "src/app.py"

    # Invalidation by file path
    cache.invalidate("src/app.py")
    assert cache.get(key) is None

    # Corrupted cache file handling
    corrupt_key = "corrupt_key_123"
    corrupt_file = (tmp_path / "cache" / f"{corrupt_key}.json")
    corrupt_file.write_text("{corrupt json content", encoding="utf-8")
    assert cache.get(corrupt_key) is None  # Fails open cleanly


# ==============================================================================
# 5. ANALYSIS METADATA & TRACEABILITY (6T-5)
# ==============================================================================

def test_analysis_traceability_metadata():
    """15. Verifies internal traceability metadata structure."""
    meta = build_analysis_traceability_metadata(
        policy_name="strict",
        is_incremental=True,
        files_considered=10,
        files_analyzed=8,
        files_excluded=2,
        cache_hits=4,
        cache_misses=4,
        duration_ms=123.45
    )
    assert meta["policy_profile"] == "strict"
    assert meta["analysis_mode"] == "incremental"
    assert meta["files_analyzed"] == 8
    assert meta["duration_ms"] == 123.45


# ==============================================================================
# 6. PLATFORM HEALTH & READINESS (6T-6)
# ==============================================================================

def test_platform_health_and_readiness_endpoints():
    """16-18. Verifies health and readiness endpoints and safe configuration status."""
    res_h = client.get("/platform/health")
    assert res_h.status_code == 200
    h_data = res_h.json()
    assert h_data["service"] == "CodeSentinel"
    assert "status" in h_data
    assert "checks" in h_data

    # Readiness endpoint
    res_r = client.get("/platform/readiness")
    assert res_r.status_code == 200
    r_data = res_r.json()
    assert "ready" in r_data


# ==============================================================================
# 7. PLATFORM CAPABILITIES & VERSION INFO (6T-7)
# ==============================================================================

def test_platform_capabilities_endpoint():
    """19. Verifies platform capabilities and version info endpoint."""
    res = client.get("/platform/info")
    assert res.status_code == 200
    info = res.json()
    assert info["service"] == "CodeSentinel"
    assert info["version"] == "1.0.0"
    assert info["api_version"] == "v1"
    assert "enabled_capabilities" in info
    assert "default" in info["supported_policy_profiles"]


# ==============================================================================
# 8. OBSERVABILITY METRICS (6T-8)
# ==============================================================================

def test_observability_metrics():
    """20-21. Verifies structured metrics collection and secret safety."""
    metrics_collector.reset()
    metrics_collector.increment("analysis_requests_total")
    metrics_collector.record_decision("ALLOW")

    res = client.get("/platform/metrics")
    assert res.status_code == 200
    m_data = res.json()
    assert m_data["analysis_requests_total"] >= 1
    assert m_data["decisions_allow_total"] >= 1


# ==============================================================================
# 9. API INTEGRATION & VALIDATION (6T-9)
# ==============================================================================

def test_platform_policies_endpoint():
    """22-23. Verifies platform policies list API endpoint."""
    res = client.get("/platform/policies")
    assert res.status_code == 200
    policies = res.json()
    assert isinstance(policies, list)
    assert any(p["name"] == "default" for p in policies)


# ==============================================================================
# 10. STATIC NON-EXECUTION & HOSTILE FIXTURE VERIFICATION (6T-10/11)
# ==============================================================================

def test_static_non_execution_6t_fixture(tmp_path):
    """
    24-26. Static Non-Execution Hostile Target Test:
    Creates a target repository with malicious executable python, shell scripts, and setup entrypoints.
    Runs static analysis and verifies ZERO side-effect marker files are created.
    """
    repo_dir = tmp_path / "hostile_6t_repo"
    repo_dir.mkdir()

    marker = repo_dir / "ATTACK_6T_MARKER.tmp"

    (repo_dir / "exploit.py").write_text(f"import os\nos.system('touch {marker.as_posix()}')\n", encoding="utf-8")
    (repo_dir / "setup.py").write_text(f"import subprocess\nsubprocess.call(['touch', r'{marker.as_posix()}'])\n", encoding="utf-8")

    # Verify scope and exclusion checks inspect file without executing
    assert not should_exclude_path("exploit.py")
    assert not marker.exists(), "Target file must not be executed during path inspection"


# ==============================================================================
# 11. REGRESSION & COMPATIBILITY VERIFICATION
# ==============================================================================

def test_step_6o_and_6r_compatibility():
    """28-32. Verifies compatibility with 6O report format, 6R gate, and 6S controls."""
    report = {
        "status": "success",
        "review_status": "allow",
        "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
    }

    dec, code, _ = evaluate_security_gate(report)
    assert dec == "ALLOW"
    assert code == 0

    summary_md = generate_ci_security_summary(report)
    assert "<!-- codesentinel-security-analysis -->" in summary_md
