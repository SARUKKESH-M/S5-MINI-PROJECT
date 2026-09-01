"""
Step 6L Verification Test Suite for CodeSentinel.

Tests Repository Acquisition Foundation:
1. Valid acquisition input
2. Invalid GitHub URL
3. Non-HTTPS URL
4. Arbitrary domain rejection
5. Embedded credential rejection
6. Branch validation
7. Workspace creation
8. Workspace boundary enforcement
9. Path traversal rejection
10. Acquisition metadata schema
11. No raw source in response
12. No secret leakage
13. Acquisition timeout handling
14. Failed acquisition cleanup
15. Deterministic acquisition metadata
16. Unique workspace isolation
17. Existing Step 6K validation regression
18. Step 6D regression
19. Step 6E regression
20. Step 6F regression
21. Step 6G regression
22. Step 6H regression
23. Step 6I regression
24. Step 6J regression
25. FastAPI /health and /repository/acquire regression
"""

import sys
import os
import json
import shutil
import tempfile
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from repository.validator import validate_github_url, validate_branch, validate_repo_path
from repository.acquirer import (
    acquire_repository,
    MAX_ACQUISITION_TIMEOUT_SECONDS,
    MAX_REPOSITORY_SIZE_BYTES,
    MAX_ACQUISITION_FILES,
    ACQUISITION_SCHEMA_VERSION
)
from app.main import app
from fastapi.testclient import TestClient


# Helper fixture for creating a dummy source repository
@pytest.fixture
def dummy_repo_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "src"))
        with open(os.path.join(tmpdir, "src", "app.py"), "w", encoding="utf-8") as f:
            f.write("print('CodeSentinel Test App')")
        with open(os.path.join(tmpdir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Sample Project")
        yield tmpdir


# ---------------------------------------------------------------------------
# TEST 1: Valid Acquisition Input
# ---------------------------------------------------------------------------
def test_1_valid_acquisition_input(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res = acquire_repository(
            repository_url="https://github.com/example/demo-repo",
            branch="main",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )

        assert res["status"] == "success"
        assert res["repository"]["owner"] == "example"
        assert res["repository"]["repository"] == "demo-repo"
        assert res["repository"]["branch"] == "main"
        assert res["acquisition"]["source"] == "github"
        assert res["acquisition"]["method"] == "local"
        assert res["acquisition"]["schema_version"] == ACQUISITION_SCHEMA_VERSION
        assert os.path.exists(res["acquisition"]["workspace"])


# ---------------------------------------------------------------------------
# TEST 2: Invalid GitHub URL
# ---------------------------------------------------------------------------
def test_2_invalid_github_url(dummy_repo_dir):
    with pytest.raises(ValueError):
        acquire_repository(
            repository_url="not-a-url",
            local_path=dummy_repo_dir
        )

    with pytest.raises(ValueError):
        acquire_repository(
            repository_url="",
            local_path=dummy_repo_dir
        )


# ---------------------------------------------------------------------------
# TEST 3: Non-HTTPS URL
# ---------------------------------------------------------------------------
def test_3_non_https_url(dummy_repo_dir):
    for bad_url in [
        "http://github.com/example/repo",
        "file:///etc/passwd",
        "ftp://github.com/example/repo"
    ]:
        with pytest.raises(ValueError, match="scheme"):
            acquire_repository(
                repository_url=bad_url,
                local_path=dummy_repo_dir
            )


# ---------------------------------------------------------------------------
# TEST 4: Arbitrary Domain Rejection
# ---------------------------------------------------------------------------
def test_4_arbitrary_domain_rejection(dummy_repo_dir):
    for bad_domain_url in [
        "https://gitlab.com/example/repo",
        "https://bitbucket.org/example/repo",
        "https://evil-domain.com/github.com/repo"
    ]:
        with pytest.raises(ValueError, match="domain"):
            acquire_repository(
                repository_url=bad_domain_url,
                local_path=dummy_repo_dir
            )


# ---------------------------------------------------------------------------
# TEST 5: Embedded Credential Rejection
# ---------------------------------------------------------------------------
def test_5_embedded_credential_rejection(dummy_repo_dir):
    bad_url = "https://admin:secret123@github.com/example/repo"
    with pytest.raises(ValueError, match="credentials"):
        acquire_repository(
            repository_url=bad_url,
            local_path=dummy_repo_dir
        )


# ---------------------------------------------------------------------------
# TEST 6: Branch Validation
# ---------------------------------------------------------------------------
def test_6_branch_validation(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res = acquire_repository(
            repository_url="https://github.com/example/repo",
            branch="feature/v2.0",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )
        assert res["repository"]["branch"] == "feature/v2.0"

    with pytest.raises(ValueError):
        acquire_repository(
            repository_url="https://github.com/example/repo",
            branch="main; rm -rf /",
            local_path=dummy_repo_dir
        )

    with pytest.raises(ValueError):
        acquire_repository(
            repository_url="https://github.com/example/repo",
            branch="../main",
            local_path=dummy_repo_dir
        )


# ---------------------------------------------------------------------------
# TEST 7: Workspace Creation
# ---------------------------------------------------------------------------
def test_7_workspace_creation(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res = acquire_repository(
            repository_url="https://github.com/example/ws-repo",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )
        ws_path = Path(res["acquisition"]["workspace"])
        repo_path = Path(res["acquisition"]["repo_path"])

        assert ws_path.exists()
        assert ws_path.is_dir()
        assert repo_path.exists()
        assert repo_path.is_dir()
        assert (repo_path / "src" / "app.py").exists()


# ---------------------------------------------------------------------------
# TEST 8: Workspace Boundary Enforcement
# ---------------------------------------------------------------------------
def test_8_workspace_boundary_enforcement(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res = acquire_repository(
            repository_url="https://github.com/example/bounds-repo",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )
        ws_path = Path(res["acquisition"]["workspace"]).resolve()
        repo_path = Path(res["acquisition"]["repo_path"]).resolve()

        # Verify repo_path is strictly inside workspace
        assert ws_path in repo_path.parents or repo_path == ws_path


# ---------------------------------------------------------------------------
# TEST 9: Path Traversal Rejection
# ---------------------------------------------------------------------------
def test_9_path_traversal_rejection(dummy_repo_dir):
    with pytest.raises(ValueError, match="Path traversal"):
        acquire_repository(
            repository_url="https://github.com/example/path-repo",
            path="../outside",
            local_path=dummy_repo_dir
        )


# ---------------------------------------------------------------------------
# TEST 10: Acquisition Metadata Schema
# ---------------------------------------------------------------------------
def test_10_acquisition_metadata_schema(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res = acquire_repository(
            repository_url="https://github.com/schema-owner/schema-repo",
            branch="main",
            path="src",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )

        assert "status" in res
        assert "repository" in res
        assert "acquisition" in res

        assert res["repository"]["owner"] == "schema-owner"
        assert res["repository"]["repository"] == "schema-repo"
        assert res["repository"]["branch"] == "main"
        assert res["repository"]["path"] == "src"

        acq = res["acquisition"]
        assert acq["acquisition_id"].startswith("acq_")
        assert "workspace" in acq
        assert "repo_path" in acq
        assert acq["source"] == "github"
        assert acq["method"] == "local"
        assert acq["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# TEST 11: No Raw Source in Response
# ---------------------------------------------------------------------------
def test_11_no_raw_source_in_response(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res = acquire_repository(
            repository_url="https://github.com/example/source-test",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )

        res_str = json.dumps(res)
        forbidden_fields = ["source_code", "raw_source", "full_source", "original_source", "raw_code"]
        for field in forbidden_fields:
            assert field not in res_str


# ---------------------------------------------------------------------------
# TEST 12: Secret Protection
# ---------------------------------------------------------------------------
def test_12_secret_protection():
    secret_val = "SUPER_SECRET_TOKEN_DO_NOT_LEAK_12345"

    with tempfile.TemporaryDirectory() as secret_repo:
        with open(os.path.join(secret_repo, "config.py"), "w", encoding="utf-8") as f:
            f.write(f"SECRET_KEY = '{secret_val}'")

        with tempfile.TemporaryDirectory() as ws_root:
            res = acquire_repository(
                repository_url="https://github.com/example/secret-test",
                local_path=secret_repo,
                workspace_root=ws_root
            )

            res_json = json.dumps(res)
            assert secret_val not in res_json


# ---------------------------------------------------------------------------
# TEST 13: Acquisition Timeout Handling
# ---------------------------------------------------------------------------
def test_13_acquisition_timeout_handling():
    with tempfile.TemporaryDirectory() as ws_root:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git clone", timeout=30)):
            with patch("shutil.which", return_value="/usr/bin/git"):
                with pytest.raises(RuntimeError, match="timed out"):
                    acquire_repository(
                        repository_url="https://github.com/example/slow-repo",
                        workspace_root=ws_root
                    )


# ---------------------------------------------------------------------------
# TEST 14: Failed Acquisition Cleanup
# ---------------------------------------------------------------------------
def test_14_failed_acquisition_cleanup():
    with tempfile.TemporaryDirectory() as ws_root:
        initial_dirs = set(os.listdir(ws_root))

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(returncode=128, cmd="git clone", stderr="Remote branch non-existent not found")):
            with patch("shutil.which", return_value="/usr/bin/git"):
                with pytest.raises(RuntimeError):
                    acquire_repository(
                        repository_url="https://github.com/example/fail-repo",
                        branch="non-existent",
                        workspace_root=ws_root
                    )

        # Verify failed workspace directory was cleaned up
        final_dirs = set(os.listdir(ws_root))
        assert initial_dirs == final_dirs


# ---------------------------------------------------------------------------
# TEST 15: Deterministic Acquisition Metadata
# ---------------------------------------------------------------------------
def test_15_deterministic_acquisition_metadata(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res1 = acquire_repository(
            repository_url="https://github.com/example/det-repo",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )
        res2 = acquire_repository(
            repository_url="https://github.com/example/det-repo",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )

        assert res1["status"] == res2["status"]
        assert res1["repository"] == res2["repository"]
        assert res1["acquisition"]["schema_version"] == res2["acquisition"]["schema_version"]
        assert res1["acquisition"]["source"] == res2["acquisition"]["source"]


# ---------------------------------------------------------------------------
# TEST 16: Unique Workspace Isolation
# ---------------------------------------------------------------------------
def test_16_unique_workspace_isolation(dummy_repo_dir):
    with tempfile.TemporaryDirectory() as ws_root:
        res1 = acquire_repository(
            repository_url="https://github.com/example/iso-repo",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )
        res2 = acquire_repository(
            repository_url="https://github.com/example/iso-repo",
            local_path=dummy_repo_dir,
            workspace_root=ws_root
        )

        assert res1["acquisition"]["acquisition_id"] != res2["acquisition"]["acquisition_id"]
        assert res1["acquisition"]["workspace"] != res2["acquisition"]["workspace"]


# ---------------------------------------------------------------------------
# TEST 17: Step 6K Validation Regression
# ---------------------------------------------------------------------------
def test_17_step_6k_validation_regression():
    v1 = validate_github_url("https://github.com/foo/bar.git")
    assert v1["owner"] == "foo"
    assert v1["repository"] == "bar"

    b1 = validate_branch("dev/feature-1")
    assert b1 == "dev/feature-1"

    p1 = validate_repo_path("src/backend/")
    assert p1 == "src/backend"


# ---------------------------------------------------------------------------
# TEST 18: Step 6D Regression (Knowledge Store & Ingestion)
# ---------------------------------------------------------------------------
def test_18_step_6d_regression():
    from knowledge.models import create_knowledge_document
    doc = create_knowledge_document(
        document_id="KNOW-6L-01",
        title="Acquisition Security",
        content="Controlled repository workspace isolation.",
        source="standard",
        category="security",
        security_topic="workspace_isolation"
    )
    assert doc["document_id"] == "KNOW-6L-01"


# ---------------------------------------------------------------------------
# TEST 19: Step 6E Regression (Hybrid Retrieval)
# ---------------------------------------------------------------------------
def test_19_step_6e_regression():
    from rag.hybrid_retrieval import retrieve_hybrid_context
    res = retrieve_hybrid_context(query="path traversal", top_k_ast=0, top_k_knowledge=0)
    assert "ast_results" in res
    assert "knowledge_results" in res


# ---------------------------------------------------------------------------
# TEST 20: Step 6F Regression (Context Ranker)
# ---------------------------------------------------------------------------
def test_20_step_6f_regression():
    from rag.context_ranker import rank_and_deduplicate_context
    ranked = rank_and_deduplicate_context(hybrid_result={"ast_results": [], "knowledge_results": []})
    assert isinstance(ranked, dict)



# ---------------------------------------------------------------------------
# TEST 21: Step 6G Regression (Context Assembly)
# ---------------------------------------------------------------------------
def test_21_step_6g_regression():
    from rag.context_builder import build_security_analysis_context
    context_obj = build_security_analysis_context(query="sanitization")
    assert "context" in context_obj


# ---------------------------------------------------------------------------
# TEST 22: Step 6H Regression (Analysis Prompting & Provider)
# ---------------------------------------------------------------------------
def test_22_step_6h_regression():
    from llm import MockLLMProvider
    provider = MockLLMProvider()
    res = provider.analyze(system_prompt="sys", user_prompt="user", context_input={})
    assert isinstance(res, dict)



# ---------------------------------------------------------------------------
# TEST 23: Step 6I Regression (Mock LLM Execution & Orchestration)
# ---------------------------------------------------------------------------
def test_23_step_6i_regression():
    from backend.analysis.orchestrator import analyze_source_code
    res = analyze_source_code(source_code="eval(input())", query="eval vulnerability")
    assert res["status"] == "success"
    assert "analysis_id" in res


# ---------------------------------------------------------------------------
# TEST 24: Step 6J Regression (Analysis Storage & History)
# ---------------------------------------------------------------------------
def test_24_step_6j_regression():
    from backend.analysis.storage import AnalysisStore
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        store = AnalysisStore(db_path=temp_db)
        rec = store.save_analysis({
            "status": "success",
            "analysis_id": "ana_step_6l_reg",
            "query": "Step 6L test",
            "summary": {"total_findings": 0},
            "findings": []
        })
        assert rec["analysis_id"] == "ana_step_6l_reg"
        fetched = store.get_analysis("ana_step_6l_reg")
        assert fetched["analysis_id"] == "ana_step_6l_reg"
    finally:
        try:
            os.remove(temp_db)
        except Exception:
            pass




# ---------------------------------------------------------------------------
# TEST 25: FastAPI /health and /repository/acquire Regression
# ---------------------------------------------------------------------------
def test_25_fastapi_health_and_acquire_regression(dummy_repo_dir):
    client = TestClient(app)

    # Health endpoint
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    # Acquire endpoint with local path
    payload = {
        "repository_url": "https://github.com/api-owner/api-repo",
        "branch": "main",
        "path": "",
        "local_path": dummy_repo_dir
    }
    res_acq = client.post("/repository/acquire", json=payload)
    assert res_acq.status_code == 200

    data = res_acq.json()
    assert data["status"] == "success"
    assert data["repository"]["owner"] == "api-owner"
    assert data["repository"]["repository"] == "api-repo"
    assert data["acquisition"]["source"] == "github"

    # Ensure raw source code is excluded from API response
    data_str = json.dumps(data)
    for field in ["source_code", "raw_source", "full_source", "original_source", "raw_code"]:
        assert field not in data_str

    # Bad Request handling
    res_bad = client.post("/repository/acquire", json={"repository_url": "http://bad-scheme.com/repo"})
    assert res_bad.status_code == 400
