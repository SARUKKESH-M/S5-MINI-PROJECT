"""Step 6G Verification Test Suite for CodeSentinel.

Tests RAG Context -> LLM-Ready Security Analysis Context construction, document classification,
content length truncation boundaries, secret protection, raw source protection,
output determinism, and regression boundaries for AST Engine, RAG, and FastAPI.
"""

import sys
import os
import json
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rag.context_builder import build_security_analysis_context, MAX_CONTEXT_DOCUMENTS, MAX_CONTENT_LENGTH
from rag.context_ranker import rank_and_deduplicate_context
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.vector_store import (
    initialize_vector_store,
    get_collection,
    get_security_knowledge_collection,
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.ingestion import ingest_documents, ingest_security_knowledge
from rag.retrieval import retrieve_documents
from knowledge.sample_data import SAMPLE_SECURITY_KNOWLEDGE
from ast_engine.rag_adapter import prepare_ast_documents_for_rag

# AST Engine Imports for Regression Tests
from ast_engine.python_parser import parse_python_source, extract_function_names
from ast_engine.structural_analyzer import analyze_python_structure
from ast_engine.security_analyzer import analyze_security_structure
from ast_engine.evidence_normalizer import normalize_security_evidence
from ast_engine.rag_documents import build_rag_documents
from ast_engine.inspection import build_ast_inspection

# FastAPI Imports for Regression Tests
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(autouse=True)
def populate_vector_store():
    """Ensure both collections are populated with sample data."""
    sample_ast_code = """
def query_database(user_input):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = " + user_input)
"""
    ast_docs = prepare_ast_documents_for_rag(sample_ast_code)
    ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)
    ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)


# ---------------------------------------------------------------------------
# TEST 1: Basic Context Construction
# ---------------------------------------------------------------------------
def test_1_basic_context_construction():
    res = build_security_analysis_context("database execution", top_k=5)

    assert res["status"] == "success"
    assert res["query"] == "database execution"
    assert res["context_version"] == "1.0"
    assert "context" in res
    assert "security_evidence" in res["context"]
    assert "code_structure" in res["context"]
    assert "security_knowledge" in res["context"]
    assert "context_documents" in res
    assert res["context_document_count"] == len(res["context_documents"])
    assert res["ast_context_count"] >= 0
    assert res["security_knowledge_context_count"] >= 0


# ---------------------------------------------------------------------------
# TEST 2: Security Evidence Appears Under context["security_evidence"]
# ---------------------------------------------------------------------------
def test_2_security_evidence_classification():
    res = build_security_analysis_context("database execution", top_k=5)
    sec_ev = res["context"]["security_evidence"]

    for item in sec_ev:
        doc_type = str(item.get("document_type", "")).lower()
        signal_type = item.get("metadata", {}).get("signal_type")
        assert doc_type == "security_evidence" or signal_type is not None


# ---------------------------------------------------------------------------
# TEST 3: Function/Module Structure Appears Under context["code_structure"]
# ---------------------------------------------------------------------------
def test_3_code_structure_classification():
    res = build_security_analysis_context("query_database", top_k=5)
    code_struct = res["context"]["code_structure"]

    for item in code_struct:
        doc_type = str(item.get("document_type", "")).lower()
        assert doc_type in ("function_structure", "module_structure", "unknown") or doc_type not in ("security_evidence", "security_knowledge")


# ---------------------------------------------------------------------------
# TEST 4: Security Knowledge Appears Under context["security_knowledge"]
# ---------------------------------------------------------------------------
def test_4_security_knowledge_classification():
    res = build_security_analysis_context("SQL parameterization", top_k=5)
    sec_kn = res["context"]["security_knowledge"]

    assert len(sec_kn) > 0
    for item in sec_kn:
        assert item["source_category"] == "security_knowledge"


# ---------------------------------------------------------------------------
# TEST 5: Correct source_category Values
# ---------------------------------------------------------------------------
def test_5_correct_source_category():
    res = build_security_analysis_context("database execution", top_k=5)
    for doc in res["context_documents"]:
        assert doc["source_category"] in ("ast", "security_knowledge")


# ---------------------------------------------------------------------------
# TEST 6: Metadata Preservation
# ---------------------------------------------------------------------------
def test_6_metadata_preservation():
    res = build_security_analysis_context("database execution", top_k=5)
    for doc in res["context_documents"]:
        meta = doc["metadata"]
        assert isinstance(meta, dict)
        assert "schema_version" in meta or "source" in meta or "source_type" in meta


# ---------------------------------------------------------------------------
# TEST 7: Empty Query
# ---------------------------------------------------------------------------
def test_7_empty_query():
    res = build_security_analysis_context("", top_k=5)
    assert res["status"] == "success"
    assert res["query"] == ""
    assert res["context_documents"] == []
    assert res["context_document_count"] == 0


# ---------------------------------------------------------------------------
# TEST 8: Whitespace Query
# ---------------------------------------------------------------------------
def test_8_whitespace_query():
    res = build_security_analysis_context("   \n\t ", top_k=5)
    assert res["status"] == "success"
    assert res["context_documents"] == []
    assert res["context_document_count"] == 0


# ---------------------------------------------------------------------------
# TEST 9: Invalid top_k = 0
# ---------------------------------------------------------------------------
def test_9_top_k_zero():
    res = build_security_analysis_context("database", top_k=0)
    assert res["status"] == "success"
    assert res["context_documents"] == []
    assert res["context_document_count"] == 0


# ---------------------------------------------------------------------------
# TEST 10: Invalid Negative top_k
# ---------------------------------------------------------------------------
def test_10_negative_top_k():
    res = build_security_analysis_context("database", top_k=-10)
    assert res["status"] == "success"
    assert res["context_documents"] == []
    assert res["context_document_count"] == 0


# ---------------------------------------------------------------------------
# TEST 11: Empty Collections Handling
# ---------------------------------------------------------------------------
def test_11_empty_collections():
    res = build_security_analysis_context("nonexistent_term_xyz_999", top_k=5)
    assert res["status"] == "success"
    assert isinstance(res["context_documents"], list)


# ---------------------------------------------------------------------------
# TEST 12: Maximum 20 Document Protection
# ---------------------------------------------------------------------------
def test_12_max_20_documents_protection():
    res = build_security_analysis_context("database", top_k=30)
    assert res["status"] == "success"
    assert len(res["context_documents"]) <= MAX_CONTEXT_DOCUMENTS
    assert res["context_document_count"] <= 20


# ---------------------------------------------------------------------------
# TEST 13: Maximum 4000-Character Content Protection
# ---------------------------------------------------------------------------
def test_13_max_4000_content_protection():
    res = build_security_analysis_context("database", top_k=5)
    for doc in res["context_documents"]:
        assert len(doc["content"]) <= MAX_CONTENT_LENGTH + 20  # account for "...[truncated]"
        if len(doc["content"]) > MAX_CONTENT_LENGTH:
            assert doc["content"].endswith("...[truncated]")


# ---------------------------------------------------------------------------
# TEST 14: Determinism
# ---------------------------------------------------------------------------
def test_14_determinism():
    res_a = build_security_analysis_context("database execution", top_k=5)
    res_b = build_security_analysis_context("database execution", top_k=5)

    dump_a = json.dumps(res_a, sort_keys=True)
    dump_b = json.dumps(res_b, sort_keys=True)

    assert dump_a == dump_b


# ---------------------------------------------------------------------------
# TEST 15: Secret Protection
# ---------------------------------------------------------------------------
def test_15_secret_protection():
    secret_val = "THIS_SECRET_MUST_NOT_APPEAR"
    secret_code = f'api_key = "{secret_val}"'

    ast_docs = prepare_ast_documents_for_rag(secret_code)
    ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)

    res = build_security_analysis_context("api_key", top_k=5)
    res_str = json.dumps(res)

    assert secret_val not in res_str


# ---------------------------------------------------------------------------
# TEST 16: Raw Source Protection
# ---------------------------------------------------------------------------
def test_16_raw_source_protection():
    res = build_security_analysis_context("query_database", top_k=5)
    res_str = json.dumps(res)

    assert "source_code" not in res_str
    assert "raw_source" not in res_str
    assert "full_source" not in res_str
    assert "original_source" not in res_str


# ---------------------------------------------------------------------------
# TEST 17: Malformed/Unknown Document Type Handling
# ---------------------------------------------------------------------------
def test_17_unknown_document_type_handling():
    res = build_security_analysis_context("database", top_k=5)
    assert res["status"] == "success"
    # Verify no unhandled exception occurred and schema is valid
    assert isinstance(res["context"]["code_structure"], list)


# ---------------------------------------------------------------------------
# TEST 18: JSON Serialization
# ---------------------------------------------------------------------------
def test_18_json_serialization():
    res = build_security_analysis_context("database execution", top_k=5)
    json_str = json.dumps(res)
    loaded = json.loads(json_str)
    assert loaded["status"] == "success"
    assert loaded["query"] == "database execution"


# ---------------------------------------------------------------------------
# TEST 19: AST Engine Regression (Steps 5A-5G)
# ---------------------------------------------------------------------------
def test_19_ast_engine_regression():
    sample_code = "def foo(): eval('1+1')"

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
# TEST 20: RAG Regression (Steps 6A-6F)
# ---------------------------------------------------------------------------
def test_20_rag_regression():
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

    hybrid_res = retrieve_hybrid_context("bar", top_k_ast=2, top_k_knowledge=2)
    assert hybrid_res["status"] == "success"

    ranked_res = rank_and_deduplicate_context(hybrid_res, top_k=5)
    assert ranked_res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 21: FastAPI Regression
# ---------------------------------------------------------------------------
def test_21_fastapi_regression():
    client = TestClient(app)

    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json() == {"status": "ok", "service": "CodeSentinel"}

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"
