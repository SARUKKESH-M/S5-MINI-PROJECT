"""Step 6F Verification Test Suite for CodeSentinel.

Tests RAG Context Ranking and Deduplication Foundation, deterministic scoring,
source category classification, metadata completeness, secret protection,
output determinism, and regression boundaries for AST Engine, RAG, and FastAPI.
"""

import sys
import os
import json
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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


# ---------------------------------------------------------------------------
# TEST 1: Basic Hybrid Ranking
# ---------------------------------------------------------------------------
def test_1_basic_hybrid_ranking():
    hybrid_input = {
        "status": "success",
        "query": "database execution",
        "ast_results": [
            {
                "document_id": "ast_doc_1",
                "content": "Function query_db executes cursor.execute call.",
                "metadata": {"source": "ast_engine", "document_type": "security_evidence", "signal_type": "database_execution_call"},
            }
        ],
        "knowledge_results": [
            {
                "document_id": "kn_doc_1",
                "content": "SQL Parameterization Guidelines for database execution.",
                "metadata": {"source_type": "knowledge_base", "document_type": "security_knowledge", "security_topic": "sql_parameterization"},
            }
        ],
        "ast_result_count": 1,
        "knowledge_result_count": 1,
        "total_result_count": 2,
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["status"] == "success"
    assert res["query"] == "database execution"
    assert res["ast_result_count"] == 1
    assert res["knowledge_result_count"] == 1
    assert res["deduplicated_count"] == 2
    assert res["result_count"] == 2
    assert res["ranking_version"] == "1.0"
    assert len(res["results"]) == 2
    assert res["results"][0]["rank"] == 1
    assert res["results"][1]["rank"] == 2


# ---------------------------------------------------------------------------
# TEST 2: Security Evidence Priority
# ---------------------------------------------------------------------------
def test_2_security_evidence_priority():
    hybrid_input = {
        "query": "database",
        "ast_results": [
            {
                "document_id": "ast_struct_1",
                "content": "Function database_connect parameters none.",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            },
            {
                "document_id": "ast_evidence_1",
                "content": "Security evidence: database_execution_call.",
                "metadata": {"source": "ast_engine", "document_type": "security_evidence", "signal_type": "database_execution_call"},
            },
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)
    top_result = res["results"][0]

    assert top_result["document_id"] == "ast_evidence_1"
    assert top_result["metadata"]["document_type"] == "security_evidence"


# ---------------------------------------------------------------------------
# TEST 3: Source Category Classification
# ---------------------------------------------------------------------------
def test_3_source_category_classification():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {
                "document_id": "doc_ast",
                "content": "AST evidence text",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            }
        ],
        "knowledge_results": [
            {
                "document_id": "doc_kn",
                "content": "Security knowledge text",
                "metadata": {"source_type": "knowledge_base", "document_type": "security_knowledge"},
            }
        ],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)
    res_map = {item["document_id"]: item["source_category"] for item in res["results"]}

    assert res_map["doc_ast"] == "ast"
    assert res_map["doc_kn"] == "security_knowledge"


# ---------------------------------------------------------------------------
# TEST 4: Token Overlap
# ---------------------------------------------------------------------------
def test_4_token_overlap():
    hybrid_input = {
        "query": "parameterized SQL query",
        "ast_results": [],
        "knowledge_results": [
            {
                "document_id": "kn_low_match",
                "content": "General guidance on external input handling.",
                "metadata": {"document_type": "security_knowledge"},
            },
            {
                "document_id": "kn_high_match",
                "content": "Always use a parameterized SQL query to avoid injection.",
                "metadata": {"document_type": "security_knowledge"},
            },
        ],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["results"][0]["document_id"] == "kn_high_match"
    assert res["results"][0]["relevance_score"] > res["results"][1]["relevance_score"]


# ---------------------------------------------------------------------------
# TEST 5: Metadata Bonus
# ---------------------------------------------------------------------------
def test_5_metadata_bonus():
    hybrid_input = {
        "query": "sql_parameterization",
        "ast_results": [],
        "knowledge_results": [
            {
                "document_id": "doc_no_meta_match",
                "content": "Content for document without metadata match.",
                "metadata": {"document_type": "security_knowledge", "security_topic": "other_topic"},
            },
            {
                "document_id": "doc_meta_match",
                "content": "Content for document with metadata match.",
                "metadata": {"document_type": "security_knowledge", "security_topic": "sql_parameterization"},
            },
        ],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["results"][0]["document_id"] == "doc_meta_match"
    assert res["results"][0]["relevance_score"] > res["results"][1]["relevance_score"]


# ---------------------------------------------------------------------------
# TEST 6: Duplicate document_id
# ---------------------------------------------------------------------------
def test_6_duplicate_document_id():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {
                "document_id": "dup_doc_1",
                "content": "First instance content",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            },
            {
                "document_id": "dup_doc_1",
                "content": "Second instance content",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            },
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["deduplicated_count"] == 1
    assert len(res["results"]) == 1
    assert res["results"][0]["document_id"] == "dup_doc_1"


# ---------------------------------------------------------------------------
# TEST 7: Duplicate Content Fingerprint
# ---------------------------------------------------------------------------
def test_7_duplicate_content_fingerprint():
    hybrid_input = {
        "query": "test",
        "ast_results": [
            {
                "document_id": "doc_id_A",
                "content": "Identical normalized text content for testing fingerprint deduplication.",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            },
            {
                "document_id": "doc_id_B",
                "content": "Identical normalized text content for testing fingerprint deduplication.",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            },
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["deduplicated_count"] == 1
    assert len(res["results"]) == 1


# ---------------------------------------------------------------------------
# TEST 8: Metadata Completeness
# ---------------------------------------------------------------------------
def test_8_metadata_completeness():
    hybrid_input = {
        "query": "test",
        "ast_results": [
            {
                "document_id": "comp_doc_1",
                "content": "Content text string.",
                "metadata": {"source": "ast_engine"}, # completeness = 1
            },
            {
                "document_id": "comp_doc_1",
                "content": "Content text string.",
                "metadata": {
                    "source": "ast_engine",
                    "document_type": "function_structure",
                    "function_name": "my_func",
                    "line_start": 10,
                }, # completeness = 4
            },
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["deduplicated_count"] == 1
    assert len(res["results"][0]["metadata"]) == 4


# ---------------------------------------------------------------------------
# TEST 9: top_k = 1
# ---------------------------------------------------------------------------
def test_9_top_k_one():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {"document_id": "doc_1", "content": "Content 1", "metadata": {}},
            {"document_id": "doc_2", "content": "Content 2", "metadata": {}},
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=1)

    assert res["result_count"] == 1
    assert len(res["results"]) == 1
    assert res["results"][0]["rank"] == 1


# ---------------------------------------------------------------------------
# TEST 10: top_k Larger Than Available
# ---------------------------------------------------------------------------
def test_10_top_k_larger_than_available():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {"document_id": "doc_1", "content": "Content 1", "metadata": {}}
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=100)

    assert res["result_count"] == 1
    assert len(res["results"]) == 1


# ---------------------------------------------------------------------------
# TEST 11: top_k <= 0
# ---------------------------------------------------------------------------
def test_11_top_k_non_positive():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {"document_id": "doc_1", "content": "Content 1", "metadata": {}}
        ],
        "knowledge_results": [],
    }

    res0 = rank_and_deduplicate_context(hybrid_input, top_k=0)
    assert res0["status"] == "success"
    assert res0["results"] == []
    assert res0["result_count"] == 0

    res_neg = rank_and_deduplicate_context(hybrid_input, top_k=-5)
    assert res_neg["status"] == "success"
    assert res_neg["results"] == []
    assert res_neg["result_count"] == 0


# ---------------------------------------------------------------------------
# TEST 12: Empty Hybrid Result
# ---------------------------------------------------------------------------
def test_12_empty_hybrid_result():
    assert rank_and_deduplicate_context({}, top_k=10)["status"] == "success"
    assert rank_and_deduplicate_context(None, top_k=10)["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 13: Determinism
# ---------------------------------------------------------------------------
def test_13_determinism():
    hybrid_input = {
        "query": "database command execution",
        "ast_results": [
            {"document_id": "ast_1", "content": "database call execute", "metadata": {"document_type": "security_evidence"}},
            {"document_id": "ast_2", "content": "command call run", "metadata": {"document_type": "security_evidence"}},
        ],
        "knowledge_results": [
            {"document_id": "kn_1", "content": "SQL parameterization safety", "metadata": {"document_type": "security_knowledge"}},
        ],
    }

    res_a = rank_and_deduplicate_context(hybrid_input, top_k=10)
    res_b = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert json.dumps(res_a, sort_keys=True) == json.dumps(res_b, sort_keys=True)


# ---------------------------------------------------------------------------
# TEST 14: Secret Protection
# ---------------------------------------------------------------------------
def test_14_secret_protection():
    secret_val = "THIS_SECRET_MUST_NOT_APPEAR"
    hybrid_input = {
        "query": "api_key",
        "ast_results": [
            {
                "document_id": "sec_doc_1",
                "content": "Security evidence: possible_hardcoded_secret. Name: api_key. Line: 3. Evidence: api_key assigned a string literal.",
                "metadata": {"source": "ast_engine", "document_type": "security_evidence"},
            }
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)
    res_str = json.dumps(res)

    assert secret_val not in res_str


# ---------------------------------------------------------------------------
# TEST 15: Raw Source Protection
# ---------------------------------------------------------------------------
def test_15_raw_source_protection():
    hybrid_input = {
        "query": "query",
        "ast_results": [
            {
                "document_id": "ast_doc",
                "content": "Function execute_query is a synchronous function.",
                "metadata": {"source": "ast_engine", "document_type": "function_structure"},
            }
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)
    res_str = json.dumps(res)

    # Ensure no raw source execution fields or unmasked source code blocks are added
    assert "raw_source_code" not in res_str
    assert "source_code_block" not in res_str


# ---------------------------------------------------------------------------
# TEST 16: Missing Metadata
# ---------------------------------------------------------------------------
def test_16_missing_metadata():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {"document_id": "no_meta_1", "content": "Content text without metadata field."},
            {"document_id": "no_meta_2", "content": "Content text with empty metadata.", "metadata": {}},
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["status"] == "success"
    assert len(res["results"]) == 2
    assert res["results"][0]["metadata"] == {}
    assert res["results"][1]["metadata"] == {}


# ---------------------------------------------------------------------------
# TEST 17: Unknown Document Type
# ---------------------------------------------------------------------------
def test_17_unknown_document_type():
    hybrid_input = {
        "query": "test query",
        "ast_results": [
            {
                "document_id": "unknown_type_doc",
                "content": "Custom document content.",
                "metadata": {"document_type": "custom_unknown_type"},
            }
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    assert res["status"] == "success"
    assert res["results"][0]["relevance_score"] >= 0.5


# ---------------------------------------------------------------------------
# TEST 18: Ranking Order Stability
# ---------------------------------------------------------------------------
def test_18_ranking_order_stability():
    hybrid_input = {
        "query": "test",
        "ast_results": [
            {
                "document_id": "doc_z",
                "content": "Content for Z doc.",
                "metadata": {"document_type": "function_structure"},
            },
            {
                "document_id": "doc_a",
                "content": "Content for A doc.",
                "metadata": {"document_type": "function_structure"},
            },
        ],
        "knowledge_results": [],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=10)

    # Equal scores should resolve deterministically using document_id ascending ("doc_a" before "doc_z")
    assert res["results"][0]["document_id"] == "doc_a"
    assert res["results"][1]["document_id"] == "doc_z"


# ---------------------------------------------------------------------------
# AST & RAG REGRESSION TESTS (5A-5G & 6A-6E)
# ---------------------------------------------------------------------------
def test_ast_engine_regression_5a_5g():
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


def test_rag_regression_6a_6e():
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


def test_fastapi_regression():
    client = TestClient(app)

    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json() == {"status": "ok", "service": "CodeSentinel"}

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"
