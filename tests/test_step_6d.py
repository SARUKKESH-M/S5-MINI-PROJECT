"""Step 6D Verification Test Suite for CodeSentinel.

Tests Security Knowledge Base Foundation, deterministic chunking, storage separation,
secret protection, and regression for Steps 5A-5G, Steps 6A-6C, and FastAPI endpoints.
"""

import sys
import os
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knowledge.models import create_knowledge_document
from knowledge.loader import load_security_knowledge, chunk_security_knowledge
from knowledge.sample_data import SAMPLE_SECURITY_KNOWLEDGE
from rag.vector_store import (
    get_collection,
    get_security_knowledge_collection,
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.ingestion import ingest_documents, ingest_security_knowledge
from rag.retrieval import retrieve_documents

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


# ---------------------------------------------------------------------------
# TEST 1: Knowledge Document Creation
# ---------------------------------------------------------------------------
def test_1_knowledge_document_creation():
    doc = create_knowledge_document(
        document_id="test_doc_1",
        title="SQL Injection Prevention",
        content="Use parameterized queries.",
        source="test_source",
        category="secure_coding",
        security_topic="sql_injection",
        language="python",
    )

    assert doc["document_id"] == "test_doc_1"
    assert doc["content"] == "Use parameterized queries."
    meta = doc["metadata"]
    assert meta["schema_version"] == "1.0"
    assert meta["language"] == "python"
    assert meta["document_type"] == "security_knowledge"
    assert meta["title"] == "SQL Injection Prevention"
    assert meta["source"] == "test_source"
    assert meta["category"] == "secure_coding"
    assert meta["security_topic"] == "sql_injection"
    assert meta["source_type"] == "knowledge_base"


# ---------------------------------------------------------------------------
# TEST 2: Deterministic Chunking
# ---------------------------------------------------------------------------
def test_2_deterministic_chunking():
    doc = create_knowledge_document(
        document_id="test_doc_2",
        title="Test Title",
        content="A" * 2500,
        source="src",
        category="cat",
        security_topic="topic",
    )

    chunks_1 = chunk_security_knowledge(doc, chunk_size=1000, overlap=100)
    chunks_2 = chunk_security_knowledge(doc, chunk_size=1000, overlap=100)

    assert len(chunks_1) > 1
    assert len(chunks_1) == len(chunks_2)
    for c1, c2 in zip(chunks_1, chunks_2):
        assert c1["document_id"] == c2["document_id"]
        assert c1["content"] == c2["content"]
        assert c1["metadata"] == c2["metadata"]


# ---------------------------------------------------------------------------
# TEST 3: Short Content
# ---------------------------------------------------------------------------
def test_3_short_content():
    doc = create_knowledge_document(
        document_id="test_doc_short",
        title="Short Title",
        content="Short content under 100 characters.",
        source="src",
        category="cat",
        security_topic="topic",
    )

    chunks = chunk_security_knowledge(doc, chunk_size=1000, overlap=100)
    assert len(chunks) == 1
    assert chunks[0]["document_id"] == "test_doc_short_chunk_1"
    assert chunks[0]["content"] == "Short content under 100 characters."
    assert chunks[0]["metadata"]["chunk_index"] == 1
    assert chunks[0]["metadata"]["parent_document_id"] == "test_doc_short"


# ---------------------------------------------------------------------------
# TEST 4: Long Content
# ---------------------------------------------------------------------------
def test_4_long_content():
    doc = create_knowledge_document(
        document_id="test_doc_long",
        title="Long Document",
        content="B" * 2500,
        source="src",
        category="cat",
        security_topic="topic",
    )

    chunks = chunk_security_knowledge(doc, chunk_size=1000, overlap=100)
    assert len(chunks) == 3
    assert chunks[0]["document_id"] == "test_doc_long_chunk_1"
    assert chunks[1]["document_id"] == "test_doc_long_chunk_2"
    assert chunks[2]["document_id"] == "test_doc_long_chunk_3"
    assert chunks[0]["metadata"]["chunk_index"] == 1
    assert chunks[1]["metadata"]["chunk_index"] == 2
    assert chunks[2]["metadata"]["chunk_index"] == 3


# ---------------------------------------------------------------------------
# TEST 5: Empty Content
# ---------------------------------------------------------------------------
def test_5_empty_content():
    doc = create_knowledge_document(
        document_id="test_doc_empty",
        title="Empty Document",
        content="",
        source="src",
        category="cat",
        security_topic="topic",
    )

    chunks = chunk_security_knowledge(doc, chunk_size=1000, overlap=100)
    assert chunks == []


# ---------------------------------------------------------------------------
# TEST 6: Invalid Chunk Parameters
# ---------------------------------------------------------------------------
def test_6_invalid_chunk_parameters():
    doc = create_knowledge_document(
        document_id="test_doc_invalid",
        title="Invalid Params Test",
        content="Sample content string for testing invalid parameters.",
        source="src",
        category="cat",
        security_topic="topic",
    )

    assert chunk_security_knowledge(doc, chunk_size=0, overlap=10) == []
    assert chunk_security_knowledge(doc, chunk_size=-100, overlap=10) == []
    assert chunk_security_knowledge(doc, chunk_size=500, overlap=-50) == []
    assert chunk_security_knowledge(doc, chunk_size=500, overlap=500) == []
    assert chunk_security_knowledge(doc, chunk_size=500, overlap=600) == []


# ---------------------------------------------------------------------------
# TEST 7: Security Knowledge Collection
# ---------------------------------------------------------------------------
def test_7_security_knowledge_collection():
    coll = get_security_knowledge_collection()
    assert coll.name == SECURITY_KNOWLEDGE_COLLECTION_NAME
    assert coll.name == "codesentinel_security_knowledge"


# ---------------------------------------------------------------------------
# TEST 8: Knowledge Ingestion
# ---------------------------------------------------------------------------
def test_8_knowledge_ingestion():
    res = ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)
    assert res["status"] == "success"
    assert res["ingested_count"] == len(SAMPLE_SECURITY_KNOWLEDGE)
    assert res["collection_name"] == SECURITY_KNOWLEDGE_COLLECTION_NAME

    coll = get_security_knowledge_collection()
    assert coll.count() >= len(SAMPLE_SECURITY_KNOWLEDGE)


# ---------------------------------------------------------------------------
# TEST 9: Re-ingestion (Idempotency)
# ---------------------------------------------------------------------------
def test_9_re_ingestion():
    coll = get_security_knowledge_collection()
    res_1 = ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)
    count_after_first = coll.count()

    res_2 = ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)
    count_after_second = coll.count()

    assert count_after_first == count_after_second


# ---------------------------------------------------------------------------
# TEST 10: Metadata Preservation
# ---------------------------------------------------------------------------
def test_10_metadata_preservation():
    ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)
    coll = get_security_knowledge_collection()

    results = coll.get(ids=["knowledge_sql_parameterization_1_chunk_1"])
    assert len(results["ids"]) == 1
    meta = results["metadatas"][0]

    assert meta["schema_version"] == "1.0"
    assert meta["language"] == "python"
    assert meta["document_type"] == "security_knowledge"
    assert meta["title"] == "SQL Query Parameterization Guidelines"
    assert meta["source"] == "local_security_knowledge"
    assert meta["category"] == "secure_coding"
    assert meta["security_topic"] == "sql_parameterization"
    assert meta["source_type"] == "knowledge_base"
    assert meta["parent_document_id"] == "knowledge_sql_parameterization_1"
    assert meta["chunk_index"] == 1


# ---------------------------------------------------------------------------
# TEST 11: Secret Protection
# ---------------------------------------------------------------------------
def test_11_secret_protection():
    secret_value = "THIS_SECRET_MUST_NOT_APPEAR"
    doc_with_secret = create_knowledge_document(
        document_id="secret_test_doc",
        title="Secret Test Title",
        content=f'api_key = "{secret_value}" # Educational note',
        source="src",
        category="cat",
        security_topic="topic",
    )

    chunks = chunk_security_knowledge(doc_with_secret)
    assert len(chunks) == 1
    chunk_meta = chunks[0]["metadata"]

    # Verify secret does NOT leak into metadata keys or values
    for k, v in chunk_meta.items():
        assert secret_value not in str(k)
        assert secret_value not in str(v)


# ---------------------------------------------------------------------------
# TEST 12: AST Engine Regression (Steps 5A-5G)
# ---------------------------------------------------------------------------
def test_12_ast_engine_regression():
    sample_code = """
def execute_query(user_input):
    import sqlite3
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = " + user_input)
"""
    # 5A
    ast_tree = parse_python_source(sample_code)
    assert ast_tree is not None

    # 5B
    funcs = extract_function_names(sample_code)
    assert any(f["name"] == "execute_query" for f in funcs)

    # 5C
    struct_info = analyze_python_structure(sample_code)
    assert struct_info["parse_status"] == "success"

    # 5D
    sec_info = analyze_security_structure(sample_code)
    assert sec_info["parse_status"] == "success"

    # 5E
    norm_info = normalize_security_evidence(sample_code)
    assert norm_info["parse_status"] == "success"

    # 5F
    rag_docs = build_rag_documents(sample_code)
    assert len(rag_docs) > 0

    ast_rag_prep = prepare_ast_documents_for_rag(sample_code)
    assert isinstance(ast_rag_prep, list)
    assert len(ast_rag_prep) > 0

    # 5G
    inspection = build_ast_inspection(sample_code)
    assert inspection["parse_status"] == "success"


# ---------------------------------------------------------------------------
# TEST 13: AST RAG Regression (Steps 6A-6C)
# ---------------------------------------------------------------------------
def test_13_ast_rag_regression():
    sample_code = "def foo(): eval('1+1')"
    docs = prepare_ast_documents_for_rag(sample_code)

    # 6A & 6B
    ingest_res = ingest_documents(docs, collection_name=DEFAULT_COLLECTION_NAME)
    assert ingest_res["status"] == "success"
    assert ingest_res["collection_name"] == DEFAULT_COLLECTION_NAME
    assert ingest_res["ingested_count"] > 0

    # Verify collection
    ast_coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)
    assert ast_coll.name == DEFAULT_COLLECTION_NAME
    assert ast_coll.name != SECURITY_KNOWLEDGE_COLLECTION_NAME

    # 6C
    retrieved = retrieve_documents(query="eval", top_k=1)
    assert retrieved["status"] == "success"
    assert isinstance(retrieved["results"], list)


# ---------------------------------------------------------------------------
# TEST 14: FastAPI Regression
# ---------------------------------------------------------------------------
def test_14_fastapi_regression():
    client = TestClient(app)

    response_root = client.get("/")
    assert response_root.status_code == 200
    assert response_root.json() == {"status": "ok", "service": "CodeSentinel"}

    response_health = client.get("/health")
    assert response_health.status_code == 200
    assert response_health.json()["status"] == "healthy"
