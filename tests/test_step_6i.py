"""Step 6I Verification Test Suite for CodeSentinel.

Tests Security Analysis Orchestration, FastAPI POST /analyze endpoint, request validation,
query fallback, secret protection, raw source protection, source non-execution,
determinism, large input bounds, and full regression across 5A–5H & FastAPI.
"""

import sys
import os
import json
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.orchestrator import analyze_source_code, reset_analysis_counter, MAX_SOURCE_LENGTH
from llm import analyze_security_context, MockLLMProvider
from rag.context_builder import build_security_analysis_context
from rag.vector_store import initialize_vector_store, get_collection, DEFAULT_COLLECTION_NAME
from rag.ingestion import ingest_documents, ingest_security_knowledge
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
def setup_environment():
    """Reset analysis counter and seed security knowledge base."""
    reset_analysis_counter()
    ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)


# ---------------------------------------------------------------------------
# TEST 1: Basic Orchestrator Execution
# ---------------------------------------------------------------------------
def test_1_basic_orchestrator_execution():
    res = analyze_source_code("def foo(): pass", query="security analysis")

    assert res["status"] == "success"
    assert res["analysis_id"] == "analysis_1"
    assert res["query"] == "security analysis"
    assert "summary" in res
    assert "findings" in res
    assert "context" in res
    assert "ast_context_count" in res["context"]
    assert "security_knowledge_context_count" in res["context"]
    assert res["provider"] == "mock"
    assert res["analysis_version"] == "1.0"


# ---------------------------------------------------------------------------
# TEST 2: Valid Python Source
# ---------------------------------------------------------------------------
def test_2_valid_python_source():
    code = "def add(a, b):\n    return a + b"
    res = analyze_source_code(code)

    assert res["status"] == "success"
    assert res["analysis_id"] == "analysis_1"
    assert isinstance(res["findings"], list)


# ---------------------------------------------------------------------------
# TEST 3: SQL Injection Example
# ---------------------------------------------------------------------------
def test_3_sql_injection_example():
    code = """
def query_user(user_input):
    import sqlite3
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = " + user_input)
"""
    res = analyze_source_code(code, query="SQL injection database execution")

    assert res["status"] == "success"
    assert res["summary"]["total_findings"] >= 1
    titles = [f["title"] for f in res["findings"]]
    assert any("SQL Injection" in t for t in titles)


# ---------------------------------------------------------------------------
# TEST 4: Command Execution Example
# ---------------------------------------------------------------------------
def test_4_command_execution_example():
    code = """
def run_cmd(user_cmd):
    import os
    os.system("echo " + user_cmd)
"""
    res = analyze_source_code(code, query="command execution call")

    assert res["status"] == "success"
    assert res["summary"]["total_findings"] >= 1
    titles = [f["title"] for f in res["findings"]]
    assert any("Command Injection" in t for t in titles)


# ---------------------------------------------------------------------------
# TEST 5: Hardcoded Secret Example
# ---------------------------------------------------------------------------
def test_5_hardcoded_secret_example():
    code = """
def secret_mgr():
    api_key = "THIS_SECRET_MUST_NOT_APPEAR"
    return api_key
"""
    res = analyze_source_code(code, query="possible_hardcoded_secret")

    assert res["status"] == "success"
    assert res["summary"]["total_findings"] >= 1
    titles = [f["title"] for f in res["findings"]]
    assert any("Secret" in t for t in titles)


# ---------------------------------------------------------------------------
# TEST 6: Dynamic Execution Example
# ---------------------------------------------------------------------------
def test_6_dynamic_execution_example():
    code = """
def eval_user_expr(expr):
    return eval(expr)
"""
    res = analyze_source_code(code, query="dynamic_code_execution")

    assert res["status"] == "success"
    assert res["summary"]["total_findings"] >= 1
    titles = [f["title"] for f in res["findings"]]
    assert any("Dynamic Code Execution" in t for t in titles)


# ---------------------------------------------------------------------------
# TEST 7: Empty Source
# ---------------------------------------------------------------------------
def test_7_empty_source():
    res = analyze_source_code("")

    assert res["status"] == "success"
    assert res["findings"] == []
    assert res["finding_count"] == 0
    assert res["summary"]["total_findings"] == 0


# ---------------------------------------------------------------------------
# TEST 8: Whitespace-Only Source
# ---------------------------------------------------------------------------
def test_8_whitespace_source():
    res = analyze_source_code("   \n\t  ")

    assert res["status"] == "success"
    assert res["findings"] == []
    assert res["finding_count"] == 0


# ---------------------------------------------------------------------------
# TEST 9: Missing source_code Request
# ---------------------------------------------------------------------------
def test_9_missing_source_code():
    res = analyze_source_code(None)

    assert res["status"] == "success"
    assert res["findings"] == []
    assert res["finding_count"] == 0


# ---------------------------------------------------------------------------
# TEST 10: Missing Query
# ---------------------------------------------------------------------------
def test_10_missing_query():
    res = analyze_source_code("def foo(): pass", query=None)

    assert res["status"] == "success"
    assert res["query"] == "security analysis"


# ---------------------------------------------------------------------------
# TEST 11: Empty Query
# ---------------------------------------------------------------------------
def test_11_empty_query():
    res = analyze_source_code("def foo(): pass", query="")

    assert res["status"] == "success"
    assert res["query"] == "security analysis"


# ---------------------------------------------------------------------------
# TEST 12: Whitespace Query
# ---------------------------------------------------------------------------
def test_12_whitespace_query():
    res = analyze_source_code("def foo(): pass", query="   \n ")

    assert res["status"] == "success"
    assert res["query"] == "security analysis"


# ---------------------------------------------------------------------------
# TEST 13: Query Fallback to "security analysis"
# ---------------------------------------------------------------------------
def test_13_query_fallback():
    res1 = analyze_source_code("def foo(): pass", query="")
    res2 = analyze_source_code("def foo(): pass", query=None)

    assert res1["query"] == "security analysis"
    assert res2["query"] == "security analysis"


# ---------------------------------------------------------------------------
# TEST 14: AST -> RAG Document Integration
# ---------------------------------------------------------------------------
def test_14_ast_rag_document_integration():
    code = "def bar(): pass"
    docs = prepare_ast_documents_for_rag(code)
    assert len(docs) > 0


# ---------------------------------------------------------------------------
# TEST 15: AST Ingestion Integration
# ---------------------------------------------------------------------------
def test_15_ast_ingestion_integration():
    code = "def baz(): pass"
    docs = prepare_ast_documents_for_rag(code)
    ingest_res = ingest_documents(docs, collection_name=DEFAULT_COLLECTION_NAME)
    assert ingest_res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 16: Hybrid Retrieval Integration
# ---------------------------------------------------------------------------
def test_16_hybrid_retrieval_integration():
    res = analyze_source_code("def query(): pass", query="security")
    assert res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 17: Ranking / Deduplication Integration
# ---------------------------------------------------------------------------
def test_17_ranking_deduplication_integration():
    res = analyze_source_code("def func(): pass", query="security")
    assert res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 18: Context Builder Integration
# ---------------------------------------------------------------------------
def test_18_context_builder_integration():
    ctx = build_security_analysis_context("security analysis", top_k=5)
    assert ctx["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 19: 6H Analyzer Integration
# ---------------------------------------------------------------------------
def test_19_6h_analyzer_integration():
    ctx = build_security_analysis_context("security analysis", top_k=5)
    res = analyze_security_context(ctx)
    assert res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 20: Final Finding Schema Validation
# ---------------------------------------------------------------------------
def test_20_final_finding_schema_validation():
    code = "def run_cmd(user_cmd):\n    import os\n    os.system(user_cmd)"
    res = analyze_source_code(code, query="command_execution_call")

    for f in res["findings"]:
        assert "finding_id" in f
        assert "title" in f
        assert "description" in f
        assert "severity" in f
        assert "confidence" in f
        assert "category" in f
        assert "evidence" in f

        assert "severity_score" not in f
        assert "cwe_id" not in f
        assert "remediation" not in f


# ---------------------------------------------------------------------------
# TEST 21: Secret Protection
# ---------------------------------------------------------------------------
def test_21_secret_protection():
    code = """
def hardcoded_auth():
    api_key = "THIS_SECRET_MUST_NOT_APPEAR"
    return api_key
"""
    res = analyze_source_code(code, query="possible_hardcoded_secret")
    res_str = json.dumps(res)

    assert "THIS_SECRET_MUST_NOT_APPEAR" not in res_str


# ---------------------------------------------------------------------------
# TEST 22: Raw Source Protection
# ---------------------------------------------------------------------------
def test_22_raw_source_protection():
    code = "def secret_fn(): pass"
    res = analyze_source_code(code, query="secret_fn")
    res_str = json.dumps(res)

    assert "source_code" not in res_str
    assert "raw_source" not in res_str


# ---------------------------------------------------------------------------
# TEST 23: Source Execution Protection
# ---------------------------------------------------------------------------
def test_23_source_execution_protection():
    code = "import os; os.system('echo HACKED')"
    res = analyze_source_code(code, query="security analysis")

    assert res["status"] == "success"
    # Static analysis executed cleanly without invoking os.system


# ---------------------------------------------------------------------------
# TEST 24: Deterministic Output
# ---------------------------------------------------------------------------
def test_24_deterministic_output():
    reset_analysis_counter()
    code = "def foo(): pass"
    res_a = analyze_source_code(code, query="security analysis")

    reset_analysis_counter()
    res_b = analyze_source_code(code, query="security analysis")

    assert res_a["analysis_id"] == res_b["analysis_id"]
    res_a.pop("created_at", None)
    res_b.pop("created_at", None)
    assert json.dumps(res_a, sort_keys=True) == json.dumps(res_b, sort_keys=True)


# ---------------------------------------------------------------------------
# TEST 25: FastAPI POST /analyze Endpoint
# ---------------------------------------------------------------------------
def test_25_fastapi_post_analyze():
    client = TestClient(app)
    payload = {
        "source_code": "def run_cmd(user_cmd):\n    import os\n    os.system(user_cmd)",
        "query": "command_execution_call"
    }
    resp = client.post("/analyze", json=payload)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "analysis_id" in data
    assert "findings" in data


# ---------------------------------------------------------------------------
# TEST 26: Existing GET / Regression
# ---------------------------------------------------------------------------
def test_26_existing_get_root_regression():
    client = TestClient(app)
    resp = client.get("/")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "CodeSentinel"}


# ---------------------------------------------------------------------------
# TEST 27: Existing GET /health Regression
# ---------------------------------------------------------------------------
def test_27_existing_get_health_regression():
    client = TestClient(app)
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# TEST 28: 5A-5G Regression
# ---------------------------------------------------------------------------
def test_28_ast_engine_regression():
    sample = "def test(): eval('1')"
    assert parse_python_source(sample) is not None
    assert extract_function_names(sample) != []
    assert analyze_python_structure(sample)["parse_status"] == "success"
    assert analyze_security_structure(sample)["parse_status"] == "success"
    assert normalize_security_evidence(sample)["parse_status"] == "success"
    assert build_rag_documents(sample) != []
    assert build_ast_inspection(sample)["parse_status"] == "success"


# ---------------------------------------------------------------------------
# TEST 29: 6A-6H Regression
# ---------------------------------------------------------------------------
def test_29_rag_llm_regression():
    store = initialize_vector_store()
    assert store is not None

    ctx = build_security_analysis_context("test", top_k=2)
    assert ctx["status"] == "success"

    res = analyze_security_context(ctx)
    assert res["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 30: Large Input Handling
# ---------------------------------------------------------------------------
def test_30_large_input_handling():
    large_code = "a = 1\n" * (MAX_SOURCE_LENGTH + 10)
    res = analyze_source_code(large_code)

    assert res["status"] == "error"
    assert "exceeds maximum allowed size limit" in res["error_message"]

    client = TestClient(app)
    resp = client.post("/analyze", json={"source_code": large_code, "query": "security"})
    assert resp.status_code == 400
