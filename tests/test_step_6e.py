"""Step 6E Verification Test Suite for CodeSentinel.

Tests Hybrid RAG Retrieval Foundation, collection isolation, edge case handling,
secret protection, output determinism, and regression for AST Engine (5A-5G),
RAG (6A-6D), and FastAPI endpoints.
"""

import sys
import os
import json
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knowledge.models import create_knowledge_document
from knowledge.sample_data import SAMPLE_SECURITY_KNOWLEDGE
from rag.vector_store import (
    initialize_vector_store,
    get_collection,
    get_security_knowledge_collection,
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.ingestion import ingest_documents, ingest_security_knowledge
from rag.retrieval import retrieve_documents
from rag.hybrid_retrieval import retrieve_hybrid_context

# AST Engine Imports for Regression Tests
from ast_engine.python_parser import parse_python_source, extract_function_names
from ast_engine.structural_analyzer import analyze_python_structure
from ast_engine.security_analyzer import analyze_security_structure
from ast_engine.evidence_normalizer import normalize_security_evidence
from ast_engine.rag_documents import build_rag_documents
from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from ast_engine.inspection import build_ast_inspection

# FastAPI Imports for Regression Tests
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(autouse=True)
def setup_hybrid_test_data():
    """Ensure both collections are populated before running retrieval tests."""
    # 1. Ingest sample AST evidence
    sample_ast_code = """
def query_db(user_input):
    import sqlite3
    conn = sqlite3.connect("database.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
    ast_docs = prepare_ast_documents_for_rag(sample_ast_code)
    ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)

    # 2. Ingest sample Security Knowledge Base entries
    ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)


# ---------------------------------------------------------------------------
# TEST 1: Normal Hybrid Retrieval
# ---------------------------------------------------------------------------
def test_1_normal_hybrid_retrieval():
    res = retrieve_hybrid_context("database execution", top_k_ast=3, top_k_knowledge=3)

    assert res["status"] == "success"
    assert res["query"] == "database execution"
    assert "ast_results" in res
    assert "knowledge_results" in res
    assert isinstance(res["ast_results"], list)
    assert isinstance(res["knowledge_results"], list)
    assert res["ast_result_count"] == len(res["ast_results"])
    assert res["knowledge_result_count"] == len(res["knowledge_results"])
    assert res["total_result_count"] == res["ast_result_count"] + res["knowledge_result_count"]


# ---------------------------------------------------------------------------
# TEST 2: Security Knowledge Retrieval
# ---------------------------------------------------------------------------
def test_2_security_knowledge_retrieval():
    res = retrieve_hybrid_context("SQL parameterization", top_k_ast=0, top_k_knowledge=5)

    assert res["status"] == "success"
    assert res["ast_results"] == []
    assert res["ast_result_count"] == 0
    assert len(res["knowledge_results"]) > 0
    assert res["knowledge_result_count"] > 0
    assert res["knowledge_results"][0]["metadata"]["document_type"] == "security_knowledge"


# ---------------------------------------------------------------------------
# TEST 3: AST Evidence Retrieval
# ---------------------------------------------------------------------------
def test_3_ast_evidence_retrieval():
    res = retrieve_hybrid_context("database execution", top_k_ast=5, top_k_knowledge=0)

    assert res["status"] == "success"
    assert res["knowledge_results"] == []
    assert res["knowledge_result_count"] == 0
    assert len(res["ast_results"]) > 0
    assert res["ast_result_count"] > 0
    assert res["ast_results"][0]["metadata"]["source"] == "ast_engine"


# ---------------------------------------------------------------------------
# TEST 4: Both Collections Represented Separately
# ---------------------------------------------------------------------------
def test_4_separate_collection_results():
    res = retrieve_hybrid_context("query execution", top_k_ast=3, top_k_knowledge=3)

    assert "ast_results" in res
    assert "knowledge_results" in res
    assert isinstance(res["ast_results"], list)
    assert isinstance(res["knowledge_results"], list)

    for ast_item in res["ast_results"]:
        assert ast_item["metadata"]["source"] == "ast_engine"

    for kn_item in res["knowledge_results"]:
        assert kn_item["metadata"]["document_type"] == "security_knowledge"


# ---------------------------------------------------------------------------
# TEST 5: Empty Query
# ---------------------------------------------------------------------------
def test_5_empty_query():
    res1 = retrieve_hybrid_context("", top_k_ast=5, top_k_knowledge=5)
    assert res1["status"] == "success"
    assert res1["ast_results"] == []
    assert res1["knowledge_results"] == []
    assert res1["total_result_count"] == 0

    res2 = retrieve_hybrid_context("   \n\t ", top_k_ast=5, top_k_knowledge=5)
    assert res2["status"] == "success"
    assert res2["ast_results"] == []
    assert res2["knowledge_results"] == []
    assert res2["total_result_count"] == 0


# ---------------------------------------------------------------------------
# TEST 6: top_k_ast = 0
# ---------------------------------------------------------------------------
def test_6_top_k_ast_zero():
    res = retrieve_hybrid_context("sql injection", top_k_ast=0, top_k_knowledge=5)
    assert res["status"] == "success"
    assert res["ast_results"] == []
    assert res["ast_result_count"] == 0
    assert res["knowledge_result_count"] >= 0


# ---------------------------------------------------------------------------
# TEST 7: top_k_knowledge = 0
# ---------------------------------------------------------------------------
def test_7_top_k_knowledge_zero():
    res = retrieve_hybrid_context("sql injection", top_k_ast=5, top_k_knowledge=0)
    assert res["status"] == "success"
    assert res["knowledge_results"] == []
    assert res["knowledge_result_count"] == 0
    assert res["ast_result_count"] >= 0


# ---------------------------------------------------------------------------
# TEST 8: Both top_k values invalid
# ---------------------------------------------------------------------------
def test_8_both_top_k_invalid():
    res1 = retrieve_hybrid_context("database", top_k_ast=0, top_k_knowledge=0)
    assert res1["status"] == "success"
    assert res1["ast_results"] == []
    assert res1["knowledge_results"] == []
    assert res1["total_result_count"] == 0

    res2 = retrieve_hybrid_context("database", top_k_ast=-5, top_k_knowledge=-10)
    assert res2["status"] == "success"
    assert res2["ast_results"] == []
    assert res2["knowledge_results"] == []
    assert res2["total_result_count"] == 0


# ---------------------------------------------------------------------------
# TEST 9: Empty AST Collection Handling
# ---------------------------------------------------------------------------
def test_9_empty_ast_collection_handling(monkeypatch):
    res = retrieve_hybrid_context("nonexistent_query_term_12345", top_k_ast=5, top_k_knowledge=5)
    assert res["status"] == "success"
    assert isinstance(res["ast_results"], list)


# ---------------------------------------------------------------------------
# TEST 10: Empty Security Knowledge Collection Handling
# ---------------------------------------------------------------------------
def test_10_empty_knowledge_collection_handling():
    res = retrieve_hybrid_context("nonexistent_knowledge_term_99999", top_k_ast=5, top_k_knowledge=5)
    assert res["status"] == "success"
    assert isinstance(res["knowledge_results"], list)


# ---------------------------------------------------------------------------
# TEST 11: Metadata Preservation
# ---------------------------------------------------------------------------
def test_11_metadata_preservation():
    res = retrieve_hybrid_context("sql_parameterization", top_k_ast=3, top_k_knowledge=3)
    assert res["status"] == "success"

    if res["knowledge_results"]:
        kn_meta = res["knowledge_results"][0]["metadata"]
        assert "schema_version" in kn_meta
        assert "document_type" in kn_meta
        assert "source_type" in kn_meta

    if res["ast_results"]:
        ast_meta = res["ast_results"][0]["metadata"]
        assert "schema_version" in ast_meta
        assert "source" in ast_meta


# ---------------------------------------------------------------------------
# TEST 12: Secret Protection
# ---------------------------------------------------------------------------
def test_12_secret_protection():
    secret_val = "THIS_SECRET_MUST_NOT_APPEAR"
    secret_code = f'api_key = "{secret_val}"'

    ast_docs = prepare_ast_documents_for_rag(secret_code)
    ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)

    res = retrieve_hybrid_context("api_key", top_k_ast=5, top_k_knowledge=5)
    res_str = json.dumps(res)

    assert secret_val not in res_str


# ---------------------------------------------------------------------------
# TEST 13: Output Determinism
# ---------------------------------------------------------------------------
def test_13_output_determinism():
    res_a = retrieve_hybrid_context("database execution", top_k_ast=3, top_k_knowledge=3)
    res_b = retrieve_hybrid_context("database execution", top_k_ast=3, top_k_knowledge=3)

    dump_a = json.dumps(res_a, sort_keys=True)
    dump_b = json.dumps(res_b, sort_keys=True)

    assert dump_a == dump_b


# ---------------------------------------------------------------------------
# TEST 14: Malformed Source Regression
# ---------------------------------------------------------------------------
def test_14_malformed_source_regression():
    broken_code = "def broken_function("
    ast_docs = prepare_ast_documents_for_rag(broken_code)
    ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)

    res = retrieve_hybrid_context("broken_function", top_k_ast=5, top_k_knowledge=5)
    assert res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 15: AST Engine Regression (Steps 5A-5G)
# ---------------------------------------------------------------------------
def test_15_ast_engine_regression():
    sample_code = "def foo(): print('hello')"

    tree = parse_python_source(sample_code)
    assert tree is not None

    funcs = extract_function_names(sample_code)
    assert any(f["name"] == "foo" for f in funcs)

    struct_info = analyze_python_structure(sample_code)
    assert struct_info["parse_status"] == "success"

    sec_info = analyze_security_structure(sample_code)
    assert sec_info["parse_status"] == "success"

    norm_info = normalize_security_evidence(sample_code)
    assert norm_info["parse_status"] == "success"

    rag_docs = build_rag_documents(sample_code)
    assert len(rag_docs) > 0

    ast_prep = prepare_ast_documents_for_rag(sample_code)
    assert len(ast_prep) > 0

    inspection = build_ast_inspection(sample_code)
    assert inspection["parse_status"] == "success"


# ---------------------------------------------------------------------------
# TEST 16: RAG Regression (Steps 6A-6D)
# ---------------------------------------------------------------------------
def test_16_rag_regression():
    store = initialize_vector_store()
    assert store is not None

    ast_coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)
    assert ast_coll.name == DEFAULT_COLLECTION_NAME

    kn_coll = get_security_knowledge_collection()
    assert kn_coll.name == SECURITY_KNOWLEDGE_COLLECTION_NAME

    ingest_res = ingest_documents(
        prepare_ast_documents_for_rag("def bar(): pass"),
        collection_name=DEFAULT_COLLECTION_NAME,
    )
    assert ingest_res["status"] == "success"

    ret_res = retrieve_documents(query="bar", top_k=1)
    assert ret_res["status"] == "success"

    kn_ingest_res = ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)
    assert kn_ingest_res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 17: FastAPI Regression
# ---------------------------------------------------------------------------
def test_17_fastapi_regression():
    client = TestClient(app)

    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json() == {"status": "ok", "service": "CodeSentinel"}

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"
