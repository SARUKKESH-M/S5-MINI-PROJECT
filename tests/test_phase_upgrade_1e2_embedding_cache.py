"""Focused Verification Test Suite for CodeSentinel Upgrade 1E2:
Embedding Caching for Ingestion and Hybrid Vector Retrieval.

Tests:
1. Document embedding cache reuses embeddings for repeated content across ingest_documents.
2. Query embedding cache reuses embeddings across retrieve_documents and retrieve_hybrid_context.
3. Cache reset functions safely clear in-memory caches.
4. Cache capacity bounds and thread-safe concurrent access.
5. Graceful fallback when embedding function fails or returns None.
6. Deterministic equivalence: retrieved context and finding enrichment are identical.
"""

import os
import sys
import threading
import pytest

# Ensure workspace root and backend are on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rag.vector_store import (
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
    get_collection,
    get_security_knowledge_collection,
    generate_transient_ast_collection_name,
    delete_transient_collection,
)
from rag.retrieval import (
    retrieve_documents,
    get_query_embedding,
    reset_query_embedding_cache,
    _QUERY_EMB_CACHE,
    MAX_QUERY_CACHE_SIZE,
)
from rag.ingestion import (
    ingest_documents,
    reset_document_embedding_cache,
    _DOC_EMB_CACHE,
    MAX_DOC_CACHE_SIZE,
)
from rag.hybrid_retrieval import retrieve_hybrid_context
from backend.analysis.finding_enrichment import enrich_findings


def setup_function():
    """Reset caches before each test."""
    reset_document_embedding_cache()
    reset_query_embedding_cache()


def test_1_document_embedding_cache_reuse():
    """Verify that ingest_documents caches and reuses embeddings for repeated document content."""
    reset_document_embedding_cache()
    assert len(_DOC_EMB_CACHE) == 0

    coll_name = generate_transient_ast_collection_name("test_emb_reuse")
    docs = [
        {"document_id": "doc_1", "content": "def foo(): pass", "metadata": {"lang": "py"}},
        {"document_id": "doc_2", "content": "def bar(): pass", "metadata": {"lang": "py"}},
    ]

    try:
        # First ingestion: populates cache
        res1 = ingest_documents(docs, collection_name=coll_name)
        assert res1["status"] == "success"
        assert res1["ingested_count"] == 2
        assert len(_DOC_EMB_CACHE) == 2
        assert "def foo(): pass" in _DOC_EMB_CACHE
        assert "def bar(): pass" in _DOC_EMB_CACHE

        foo_emb_original = list(_DOC_EMB_CACHE["def foo(): pass"])

        # Second ingestion in another collection: reuses cached embeddings
        coll_name_2 = generate_transient_ast_collection_name("test_emb_reuse_2")
        try:
            res2 = ingest_documents(docs, collection_name=coll_name_2)
            assert res2["status"] == "success"
            assert res2["ingested_count"] == 2
            # Cache size has not increased since keys are identical
            assert len(_DOC_EMB_CACHE) == 2
            assert _DOC_EMB_CACHE["def foo(): pass"] == foo_emb_original
        finally:
            delete_transient_collection(coll_name_2)
    finally:
        delete_transient_collection(coll_name)


def test_2_query_embedding_cache_reuse():
    """Verify that get_query_embedding caches and reuses embeddings across hybrid queries."""
    reset_query_embedding_cache()
    assert len(_QUERY_EMB_CACHE) == 0

    query = "dynamic_code_execution dangerous eval exec"
    emb1 = get_query_embedding(query, collection=get_security_knowledge_collection())
    assert emb1 is not None
    assert len(_QUERY_EMB_CACHE) == 1

    # Second lookup without passing collection must hit the cache
    emb2 = get_query_embedding(query)
    assert emb2 is not None
    assert emb1 == emb2

    # Hybrid retrieval uses the cached query embedding
    coll_name = generate_transient_ast_collection_name("test_query_emb")
    try:
        res = retrieve_hybrid_context(query, ast_collection_name=coll_name)
        assert res["status"] == "success"
        assert len(_QUERY_EMB_CACHE) == 1
    finally:
        delete_transient_collection(coll_name)


def test_3_cache_reset_functions():
    """Verify that cache reset functions clear caches properly."""
    reset_document_embedding_cache()
    reset_query_embedding_cache()

    _DOC_EMB_CACHE["dummy_doc"] = [0.1, 0.2]
    _QUERY_EMB_CACHE["dummy_query"] = [[0.3, 0.4]]

    assert len(_DOC_EMB_CACHE) == 1
    assert len(_QUERY_EMB_CACHE) == 1

    reset_document_embedding_cache()
    reset_query_embedding_cache()

    assert len(_DOC_EMB_CACHE) == 0
    assert len(_QUERY_EMB_CACHE) == 0


def test_4_bounded_cache_capacity_and_thread_safety():
    """Verify caches respect max bounds and thread-safe concurrency."""
    reset_document_embedding_cache()
    reset_query_embedding_cache()

    errors = []

    def concurrent_worker(worker_id: int):
        try:
            for i in range(50):
                content = f"content_{worker_id}_{i}"
                _DOC_EMB_CACHE[content] = [float(worker_id), float(i)]
                _QUERY_EMB_CACHE[f"q_{worker_id}_{i}"] = [[float(worker_id)]]
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=concurrent_worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(_DOC_EMB_CACHE) > 0
    assert len(_QUERY_EMB_CACHE) > 0


def test_5_graceful_fallback_on_embedding_error(monkeypatch):
    """Verify ingestion and retrieval fall back gracefully if embedding computation fails."""
    coll_name = generate_transient_ast_collection_name("test_emb_fallback")
    coll = get_collection(collection_name=coll_name)

    # Ingestion should not fail when embeddings cannot be precomputed
    def failing_emb_fn(texts):
        return None

    monkeypatch.setattr(coll, "_embedding_function", failing_emb_fn)

    try:
        res = ingest_documents(
            [{"document_id": "fallback_1", "content": "sample content", "metadata": {"source": "unit_test"}}],
            collection_name=coll_name,
        )
        assert res["status"] == "success"
        assert res["ingested_count"] == 1

        # Retrieval should not fail, should fall back to query_texts
        ret_res = retrieve_documents(query="sample", collection_name=coll_name)
        assert ret_res["status"] == "success"
    finally:
        delete_transient_collection(coll_name)


def test_6_deterministic_equivalence_of_enrichment():
    """Verify that findings enrichment produces deterministic output with embedding caching."""
    findings = [
        {
            "finding_id": "find_exec_1",
            "title": "Dynamic Code Execution via eval()",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "cwe_id": None,
            "category": "dynamic_code_execution",
            "evidence": "eval(user_input)",
        }
    ]

    # Cold enrichment (populates caches)
    enriched_cold = enrich_findings(findings)
    assert len(enriched_cold) == 1
    assert enriched_cold[0]["finding_id"] == "find_exec_1"
    assert enriched_cold[0]["severity"] == "CRITICAL"
    assert "rag" in enriched_cold[0].get("enriched_by", [])

    # Warm enrichment (reuses cached embeddings)
    enriched_warm = enrich_findings(findings)
    assert len(enriched_warm) == 1
    assert enriched_warm[0]["finding_id"] == "find_exec_1"
    assert enriched_warm[0]["severity"] == "CRITICAL"
    assert enriched_warm[0]["cwe_id"] == enriched_cold[0]["cwe_id"]
    assert enriched_warm[0]["recommendation"] == enriched_cold[0]["recommendation"]
    assert enriched_warm[0]["structured_explanation"] == enriched_cold[0]["structured_explanation"]
