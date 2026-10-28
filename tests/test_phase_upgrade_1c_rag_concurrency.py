"""Verification Test Suite for CodeSentinel Upgrade 1C:
Backend Performance & Reliability — RAG Concurrency & Curated Knowledge Caching.

Covers:
1. Deterministic and valid transient collection name generation.
2. Protection of permanent collections from transient deletion.
3. Backward compatibility for RAG callers omitting ast_collection_name.
4. Thread-safe curated knowledge caching, force=True bypass, and unverified failure handling.
5. Concurrent multi-threaded repository analyses without cross-contamination.
6. Guaranteed transient collection cleanup on both normal completion and injected failures.
7. Safe logging on transient collection deletion failure without credential exposure.
"""

import os
import sys
import threading
import time
from typing import Any, Dict, List
import pytest

# Ensure workspace root and backend are on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rag.vector_store import (
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
    initialize_vector_store,
    get_collection,
    generate_transient_ast_collection_name,
    delete_transient_collection,
)
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.context_builder import build_security_analysis_context
from rag.ingestion import (
    ensure_curated_knowledge_ingested,
    reset_curated_knowledge_cache,
    ingest_documents,
)
from backend.analysis.finding_enrichment import enrich_findings
from backend.analysis.repository_orchestrator import analyze_repository
from backend.repository.acquirer import acquire_repository


# ---------------------------------------------------------------------------
# Test 1: Transient Collection Name Generation
# ---------------------------------------------------------------------------
def test_1_transient_collection_name_generation():
    """Verify generated transient collection names satisfy ChromaDB constraints."""
    name1 = generate_transient_ast_collection_name("repo_ana_12345678")
    assert name1.startswith("ast_repo_ana_12345678")
    assert 3 <= len(name1) <= 63
    assert name1[0].isalnum() and name1[-1].isalnum()

    # Special characters and edge cases
    name_special = generate_transient_ast_collection_name("test/repo:v1.0@sha-1234")
    assert "/" not in name_special and ":" not in name_special and "@" not in name_special
    assert 3 <= len(name_special) <= 63
    assert name_special[0].isalnum() and name_special[-1].isalnum()

    # Empty string fallback
    name_empty = generate_transient_ast_collection_name("")
    assert 3 <= len(name_empty) <= 63
    assert name_empty.startswith("ast_")


# ---------------------------------------------------------------------------
# Test 2: Safe Collection Deletion Guards
# ---------------------------------------------------------------------------
def test_2_safe_collection_deletion_guards():
    """Verify delete_transient_collection protects permanent collections and handles missing ones safely."""
    # Never delete permanent security knowledge collection
    refused = delete_transient_collection(SECURITY_KNOWLEDGE_COLLECTION_NAME)
    assert refused is False

    # Never delete empty or whitespace names
    assert delete_transient_collection("") is False
    assert delete_transient_collection("   ") is False
    assert delete_transient_collection(None) is False

    # Safely return False on non-existent collection without raising
    non_existent = "ast_non_existent_collection_99999"
    result = delete_transient_collection(non_existent)
    assert result is False


# ---------------------------------------------------------------------------
# Test 3: Backward Compatibility for Callers Omitting ast_collection_name
# ---------------------------------------------------------------------------
def test_3_backward_compatibility_rag_callers():
    """Verify that omitting ast_collection_name preserves exact existing behavior."""
    # 1. retrieve_hybrid_context without ast_collection_name
    hybrid_res = retrieve_hybrid_context(query="SQL injection vulnerability", top_k_ast=2, top_k_knowledge=2)
    assert hybrid_res["status"] == "success"
    assert "ast_results" in hybrid_res
    assert "knowledge_results" in hybrid_res

    # 2. build_security_analysis_context without ast_collection_name
    ctx_res = build_security_analysis_context(query="command injection vulnerability", top_k=2)
    assert ctx_res["status"] == "success"
    assert "context" in ctx_res

    # 3. enrich_findings without ast_collection_name
    dummy_findings = [{
        "finding_id": "test_find_1",
        "title": "SQL Injection in User Query",
        "severity": "HIGH",
        "cwe_id": "CWE-89",
        "category": "injection",
        "evidence": "SELECT * FROM users WHERE name = %s"
    }]
    enriched = enrich_findings(dummy_findings)
    assert len(enriched) == 1
    assert enriched[0]["finding_id"] == "test_find_1"
    assert enriched[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Test 4: Thread-Safe Curated Knowledge Caching & Force Bypass
# ---------------------------------------------------------------------------
def test_4_curated_knowledge_cache_and_force():
    """Verify thread-safe process caching, low warm latency, and force=True bypass."""
    reset_curated_knowledge_cache()

    # 1. Cold call verifies and caches
    t0 = time.perf_counter()
    res1 = ensure_curated_knowledge_ingested(force=False)
    t1 = time.perf_counter()
    cold_ms = (t1 - t0) * 1000.0
    assert res1["status"] == "success"

    # 2. Warm call uses in-memory cache
    t0 = time.perf_counter()
    res2 = ensure_curated_knowledge_ingested(force=False)
    t1 = time.perf_counter()
    warm_ms = (t1 - t0) * 1000.0
    assert res2["status"] == "success"
    assert res2.get("already_present") is True
    assert res2.get("ingested_count") == 0
    # Warm call should be substantially faster than cold verification
    assert warm_ms < 10.0, f"Expected fast warm call, got {warm_ms:.2f}ms"

    # 3. force=True bypasses cache
    res_force = ensure_curated_knowledge_ingested(force=True)
    assert res_force["status"] == "success"
    assert res_force.get("ingested_count", 0) >= 12

    # 4. Unverified failure is not cached
    reset_curated_knowledge_cache()
    from rag import ingestion as ing_module
    orig_fn = ing_module.ingest_security_knowledge

    def failing_ingest(*args, **kwargs):
        return {"status": "error", "error_message": "simulated ingestion error"}

    ing_module.ingest_security_knowledge = failing_ingest
    try:
        # Pass a bogus sample chunk check by pointing to empty collection or force
        fail_res = ensure_curated_knowledge_ingested(force=True)
        assert fail_res["status"] == "error"
        # Verify not cached
        assert len(ing_module._VERIFIED_KNOWLEDGE_PATHS) == 0
    finally:
        ing_module.ingest_security_knowledge = orig_fn
        reset_curated_knowledge_cache()


# ---------------------------------------------------------------------------
# Test 5: Concurrent Curated Knowledge Access
# ---------------------------------------------------------------------------
def test_5_curated_knowledge_concurrent_threads():
    """Verify that multiple threads calling ensure_curated_knowledge_ingested do not race."""
    reset_curated_knowledge_cache()
    errors = []
    results = []

    def worker():
        try:
            r = ensure_curated_knowledge_ingested(force=False)
            results.append(r)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Encountered thread errors: {errors}"
    assert len(results) == 10
    for r in results:
        assert r["status"] == "success"


# ---------------------------------------------------------------------------
# Test 6: Concurrent Repository Analyses (Zero Cross-Contamination)
# ---------------------------------------------------------------------------
def test_6_concurrent_repository_analyses_zero_cross_contamination(tmp_path):
    """Verify two concurrent repository analyses operate on isolated collections without cross-contamination."""
    # Create Repo A with command injection
    repo_a = tmp_path / "repo_a"
    repo_a.mkdir()
    (repo_a / "cmd_runner.py").write_text(
        "import os\ndef run_user_cmd(cmd):\n    os.system(cmd)\n",
        encoding="utf-8"
    )

    # Create Repo B with SQL injection
    repo_b = tmp_path / "repo_b"
    repo_b.mkdir()
    (repo_b / "db_query.py").write_text(
        "import sqlite3\ndef find_user(name):\n    conn = sqlite3.connect(':memory:')\n    conn.execute(f'SELECT * FROM users WHERE name = {name}')\n",
        encoding="utf-8"
    )

    acq_a = acquire_repository(
        repository_url="https://github.com/example/repo-a.git",
        local_path=str(repo_a),
        workspace_root=str(tmp_path)
    )["acquisition"]["acquisition_id"]
    acq_b = acquire_repository(
        repository_url="https://github.com/example/repo-b.git",
        local_path=str(repo_b),
        workspace_root=str(tmp_path)
    )["acquisition"]["acquisition_id"]

    results: Dict[str, Any] = {}
    thread_errors: List[Exception] = []

    def run_analysis(acq_id, root, res_key):
        try:
            res = analyze_repository(
                acquisition_id=acq_id,
                workspace_root=str(tmp_path),
                enable_cache=False,
            )
            results[res_key] = res
        except Exception as exc:
            thread_errors.append(exc)

    t1 = threading.Thread(target=run_analysis, args=(acq_a, repo_a, "repo_a"))
    t2 = threading.Thread(target=run_analysis, args=(acq_b, repo_b, "repo_b"))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(thread_errors) == 0, f"Thread errors during concurrent analysis: {thread_errors}"
    assert "repo_a" in results and "repo_b" in results

    res_a = results["repo_a"]
    res_b = results["repo_b"]

    assert res_a["status"] == "success"
    assert res_b["status"] == "success"
    assert res_a["analysis_id"] != res_b["analysis_id"]

    # Verify Repo A findings do not contain Repo B files or SQL findings
    findings_a = res_a.get("findings", [])
    for f in findings_a:
        evidence = str(f.get("evidence", ""))
        assert "db_query.py" not in evidence
        assert "SELECT * FROM users" not in evidence

    # Verify Repo B findings do not contain Repo A files or os.system findings
    findings_b = res_b.get("findings", [])
    for f in findings_b:
        evidence = str(f.get("evidence", ""))
        assert "cmd_runner.py" not in evidence
        assert "os.system" not in evidence


# ---------------------------------------------------------------------------
# Test 7: Guaranteed Transient Collection Cleanup on Normal Completion
# ---------------------------------------------------------------------------
def test_7_transient_collection_cleanup_on_success(tmp_path):
    """Verify that the analysis-scoped AST collection is deleted from ChromaDB upon completion."""
    repo_dir = tmp_path / "repo_cleanup"
    repo_dir.mkdir()
    (repo_dir / "vuln.py").write_text("import os\nos.system('echo hi')\n", encoding="utf-8")

    acq = acquire_repository(
        repository_url="https://github.com/example/repo-cleanup.git",
        local_path=str(repo_dir),
        workspace_root=str(tmp_path)
    )
    acq_id = acq["acquisition"]["acquisition_id"]
    res = analyze_repository(
        acquisition_id=acq_id,
        workspace_root=str(tmp_path),
        enable_cache=False,
    )

    assert res["status"] == "success"
    aid = res["analysis_id"]
    transient_name = generate_transient_ast_collection_name(aid)

    # Verify collection does not exist in ChromaDB client
    client = initialize_vector_store()
    existing_collections = [c.name for c in client.list_collections()]
    assert transient_name not in existing_collections, f"Stale collection {transient_name} leaked in ChromaDB!"


# ---------------------------------------------------------------------------
# Test 8: Guaranteed Transient Collection Cleanup on Failure
# ---------------------------------------------------------------------------
def test_8_transient_collection_cleanup_on_failure(tmp_path):
    """Verify that transient AST collections are deleted even if an exception occurs mid-analysis."""
    repo_dir = tmp_path / "repo_fail"
    repo_dir.mkdir()
    (repo_dir / "vuln.py").write_text("import os\nos.system('echo hi')\n", encoding="utf-8")

    acq = acquire_repository(
        repository_url="https://github.com/example/repo-fail.git",
        local_path=str(repo_dir),
        workspace_root=str(tmp_path)
    )
    acq_id = acq["acquisition"]["acquisition_id"]

    import backend.analysis.repository_orchestrator as rep_orch
    orig_enrich = rep_orch.enrich_findings

    def failing_enrich(*args, **kwargs):
        raise RuntimeError("Injected mid-pipeline failure")

    rep_orch.enrich_findings = failing_enrich

    client = initialize_vector_store()
    collections_before = {c.name for c in client.list_collections()}

    with pytest.raises(RuntimeError, match="Injected mid-pipeline failure"):
        try:
            analyze_repository(
                acquisition_id=acq_id,
                workspace_root=str(tmp_path),
                enable_cache=False,
            )
        finally:
            rep_orch.enrich_findings = orig_enrich

    collections_after = {c.name for c in client.list_collections()}
    new_collections = collections_after - collections_before
    # None of the new collections should be an ast_ collection
    leaked_ast_collections = [c for c in new_collections if c.startswith("ast_repo_ana_")]
    assert len(leaked_ast_collections) == 0, f"Leaked transient collections on failure: {leaked_ast_collections}"


# ---------------------------------------------------------------------------
# Test 9: Safe Logging on Transient Collection Deletion Failure
# ---------------------------------------------------------------------------
def test_9_transient_collection_cleanup_failure_logged_safely(caplog):
    """Verify that if deletion encounters an error, it logs safely without secrets and returns False."""
    import logging
    from unittest.mock import patch

    with patch("rag.vector_store.initialize_vector_store") as mock_init:
        mock_client = mock_init.return_value
        mock_client.delete_collection.side_effect = RuntimeError("Disk locked error during ChromaDB cleanup")

        with caplog.at_level(logging.WARNING):
            deleted = delete_transient_collection("ast_repo_ana_fail123")

        assert deleted is False
        assert "Failed to delete transient collection: name=ast_repo_ana_fail123" in caplog.text
        assert "RuntimeError" in caplog.text
        # Assert no sensitive keywords or source code are present in the log
        assert "ghp_" not in caplog.text
        assert "password" not in caplog.text
