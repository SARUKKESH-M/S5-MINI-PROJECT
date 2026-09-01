"""Step 6J Verification Test Suite for CodeSentinel.

Tests Analysis Storage Engine, SQLite persistence, idempotent saving, finding persistence,
history APIs (GET /analyses, GET /analyses/{id}, GET /analyses/{id}/findings, DELETE /analyses/{id}),
RAG collection isolation, secret protection, raw source protection, and regressions.
"""

import sys
import os
import json
import tempfile
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.storage import AnalysisStore, create_analysis_record, ANALYSIS_SCHEMA_VERSION
from backend.analysis.orchestrator import analyze_source_code, reset_analysis_counter
from rag.vector_store import initialize_vector_store, get_collection, DEFAULT_COLLECTION_NAME
from rag.ingestion import ingest_security_knowledge
from knowledge.sample_data import SAMPLE_SECURITY_KNOWLEDGE

# FastAPI Imports for Regression Tests
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def temp_store():
    """Fixture providing an isolated AnalysisStore with a temporary SQLite database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    store = AnalysisStore(db_path=temp_db_path)
    yield store

    # Cleanup temp file
    try:
        os.remove(temp_db_path)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def setup_environment():
    """Reset analysis counter and seed security knowledge base."""
    reset_analysis_counter()
    ingest_security_knowledge(SAMPLE_SECURITY_KNOWLEDGE)


# ---------------------------------------------------------------------------
# TEST 1: Storage Initialization
# ---------------------------------------------------------------------------
def test_1_storage_initialization(temp_store):
    assert temp_store is not None
    assert temp_store.count_analyses() == 0


# ---------------------------------------------------------------------------
# TEST 2: Database Creation
# ---------------------------------------------------------------------------
def test_2_database_creation(temp_store):
    assert os.path.exists(temp_store.db_path)


# ---------------------------------------------------------------------------
# TEST 3: Analysis Record Creation Helper
# ---------------------------------------------------------------------------
def test_3_analysis_record_creation():
    rec = create_analysis_record(
        analysis_id="analysis_1",
        status="success",
        query="security",
        summary={"total_findings": 2, "high_count": 2},
    )

    assert rec["analysis_id"] == "analysis_1"
    assert rec["status"] == "success"
    assert rec["query"] == "security"
    assert rec["finding_count"] == 2
    assert rec["schema_version"] == ANALYSIS_SCHEMA_VERSION
    assert "source_code" not in rec


# ---------------------------------------------------------------------------
# TEST 4: Analysis Persistence
# ---------------------------------------------------------------------------
def test_4_analysis_persistence(temp_store):
    analysis_data = {
        "status": "success",
        "analysis_id": "analysis_100",
        "query": "SQL injection",
        "summary": {"total_findings": 1, "high_count": 1},
        "findings": [
            {
                "finding_id": "finding_1",
                "title": "SQL Injection Risk",
                "description": "Risk detected",
                "severity": "high",
                "confidence": "high",
                "category": "Injection",
                "evidence": [{"document_id": "doc_1"}],
            }
        ],
    }

    res = temp_store.save_analysis(analysis_data)
    assert res["analysis_id"] == "analysis_100"
    assert temp_store.count_analyses() == 1


# ---------------------------------------------------------------------------
# TEST 5: Analysis Retrieval
# ---------------------------------------------------------------------------
def test_5_analysis_retrieval(temp_store):
    analysis_data = {
        "status": "success",
        "analysis_id": "analysis_200",
        "query": "command injection",
        "summary": {"total_findings": 1, "critical_count": 1},
        "findings": [
            {
                "finding_id": "finding_1",
                "title": "Cmd Risk",
                "description": "Desc",
                "severity": "critical",
                "confidence": "high",
                "category": "Injection",
                "evidence": [{"document_id": "doc_2"}],
            }
        ],
    }
    temp_store.save_analysis(analysis_data)

    retrieved = temp_store.get_analysis("analysis_200")
    assert retrieved is not None
    assert retrieved["analysis_id"] == "analysis_200"
    assert retrieved["query"] == "command injection"
    assert len(retrieved["findings"]) == 1


# ---------------------------------------------------------------------------
# TEST 6: Analysis History Listing
# ---------------------------------------------------------------------------
def test_6_analysis_history_listing(temp_store):
    for i in range(3):
        temp_store.save_analysis({
            "status": "success",
            "analysis_id": f"analysis_{i}",
            "query": "query",
            "summary": {"total_findings": 0},
            "findings": [],
        })

    lst = temp_store.list_analyses(limit=10)
    assert len(lst) == 3


# ---------------------------------------------------------------------------
# TEST 7: Finding Persistence
# ---------------------------------------------------------------------------
def test_7_finding_persistence(temp_store):
    analysis_data = {
        "status": "success",
        "analysis_id": "analysis_300",
        "query": "hardcoded secret",
        "summary": {"total_findings": 1, "medium_count": 1},
        "findings": [
            {
                "finding_id": "finding_1",
                "title": "Secret Found",
                "description": "Found secret",
                "severity": "medium",
                "confidence": "medium",
                "category": "Credentials",
                "evidence": [{"document_id": "doc_3"}],
            }
        ],
    }
    temp_store.save_analysis(analysis_data)
    findings = temp_store.get_findings("analysis_300")

    assert findings is not None
    assert len(findings) == 1
    assert findings[0]["finding_id"] == "finding_1"


# ---------------------------------------------------------------------------
# TEST 8: Finding Retrieval
# ---------------------------------------------------------------------------
def test_8_finding_retrieval(temp_store):
    analysis_data = {
        "status": "success",
        "analysis_id": "analysis_400",
        "query": "test",
        "summary": {"total_findings": 2},
        "findings": [
            {"finding_id": "finding_1", "title": "F1", "description": "D1", "severity": "low", "confidence": "low", "category": "C", "evidence": []},
            {"finding_id": "finding_2", "title": "F2", "description": "D2", "severity": "low", "confidence": "low", "category": "C", "evidence": []},
        ],
    }
    temp_store.save_analysis(analysis_data)
    findings = temp_store.get_findings("analysis_400")

    assert len(findings) == 2


# ---------------------------------------------------------------------------
# TEST 9: Empty Database Behavior
# ---------------------------------------------------------------------------
def test_9_empty_database_behavior(temp_store):
    assert temp_store.count_analyses() == 0
    assert temp_store.list_analyses() == []
    assert temp_store.get_analysis("nonexistent") is None
    assert temp_store.get_findings("nonexistent") is None


# ---------------------------------------------------------------------------
# TEST 10: Multiple Analyses Persistence
# ---------------------------------------------------------------------------
def test_10_multiple_analyses(temp_store):
    for i in range(5):
        temp_store.save_analysis({
            "status": "success",
            "analysis_id": f"mult_{i}",
            "query": f"query_{i}",
            "summary": {"total_findings": i},
            "findings": [],
        })
    assert temp_store.count_analyses() == 5


# ---------------------------------------------------------------------------
# TEST 11: Deterministic Retrieval Structure
# ---------------------------------------------------------------------------
def test_11_deterministic_retrieval_structure(temp_store):
    data = {
        "status": "success",
        "analysis_id": "det_1",
        "query": "q",
        "summary": {"total_findings": 0},
        "findings": [],
    }
    temp_store.save_analysis(data)

    ret1 = temp_store.get_analysis("det_1")
    ret2 = temp_store.get_analysis("det_1")

    assert json.dumps(ret1, sort_keys=True) == json.dumps(ret2, sort_keys=True)


# ---------------------------------------------------------------------------
# TEST 12: Idempotent Analysis Save
# ---------------------------------------------------------------------------
def test_12_idempotent_analysis_save(temp_store):
    data = {
        "status": "success",
        "analysis_id": "idem_1",
        "query": "q",
        "summary": {"total_findings": 1},
        "findings": [{"finding_id": "f1", "title": "T", "description": "D", "severity": "low", "confidence": "low", "category": "C", "evidence": []}],
    }

    temp_store.save_analysis(data)
    temp_store.save_analysis(data)  # Repeat save

    assert temp_store.count_analyses() == 1
    ret = temp_store.get_analysis("idem_1")
    assert len(ret["findings"]) == 1


# ---------------------------------------------------------------------------
# TEST 13: Idempotent Finding Save
# ---------------------------------------------------------------------------
def test_13_idempotent_finding_save(temp_store):
    data1 = {
        "status": "success",
        "analysis_id": "idem_2",
        "query": "q",
        "summary": {"total_findings": 1},
        "findings": [{"finding_id": "f1", "title": "T1", "description": "D", "severity": "low", "confidence": "low", "category": "C", "evidence": []}],
    }
    data2 = {
        "status": "success",
        "analysis_id": "idem_2",
        "query": "q",
        "summary": {"total_findings": 1},
        "findings": [{"finding_id": "f1", "title": "T2_Updated", "description": "D", "severity": "low", "confidence": "low", "category": "C", "evidence": []}],
    }

    temp_store.save_analysis(data1)
    temp_store.save_analysis(data2)

    findings = temp_store.get_findings("idem_2")
    assert len(findings) == 1
    assert findings[0]["title"] == "T2_Updated"


# ---------------------------------------------------------------------------
# TEST 14: Pagination (Limit / Offset)
# ---------------------------------------------------------------------------
def test_14_pagination(temp_store):
    for i in range(15):
        temp_store.save_analysis({
            "status": "success",
            "analysis_id": f"page_{i:02d}",
            "query": f"query_{i}",
            "summary": {"total_findings": 0},
            "findings": [],
        })

    page1 = temp_store.list_analyses(limit=5, offset=0)
    page2 = temp_store.list_analyses(limit=5, offset=5)

    assert len(page1) == 5
    assert len(page2) == 5
    ids1 = [item["analysis_id"] for item in page1]
    ids2 = [item["analysis_id"] for item in page2]
    assert set(ids1).isdisjoint(set(ids2))


# ---------------------------------------------------------------------------
# TEST 15: Limit Validation
# ---------------------------------------------------------------------------
def test_15_limit_validation(temp_store):
    for i in range(5):
        temp_store.save_analysis({"status": "success", "analysis_id": f"lim_{i}", "query": "q", "summary": {}, "findings": []})

    assert len(temp_store.list_analyses(limit=-5)) == 5  # Normalized to default
    assert len(temp_store.list_analyses(limit=150)) == 5  # Capped at 100


# ---------------------------------------------------------------------------
# TEST 16: Offset Validation
# ---------------------------------------------------------------------------
def test_16_offset_validation(temp_store):
    temp_store.save_analysis({"status": "success", "analysis_id": "off_1", "query": "q", "summary": {}, "findings": []})

    lst = temp_store.list_analyses(limit=10, offset=-10)  # Normalized to 0
    assert len(lst) == 1


# ---------------------------------------------------------------------------
# TEST 17: Missing Analysis Handling
# ---------------------------------------------------------------------------
def test_17_missing_analysis_handling(temp_store):
    assert temp_store.get_analysis("missing_999") is None

    client = TestClient(app)
    resp = client.get("/analyses/missing_999")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# TEST 18: Delete Analysis
# ---------------------------------------------------------------------------
def test_18_delete_analysis(temp_store):
    temp_store.save_analysis({"status": "success", "analysis_id": "del_1", "query": "q", "summary": {}, "findings": []})
    assert temp_store.get_analysis("del_1") is not None

    deleted = temp_store.delete_analysis("del_1")
    assert deleted is True
    assert temp_store.get_analysis("del_1") is None


# ---------------------------------------------------------------------------
# TEST 19: Delete Associated Findings (Cascade Delete)
# ---------------------------------------------------------------------------
def test_19_delete_associated_findings(temp_store):
    temp_store.save_analysis({
        "status": "success",
        "analysis_id": "del_casc",
        "query": "q",
        "summary": {"total_findings": 1},
        "findings": [{"finding_id": "f1", "title": "T", "description": "D", "severity": "low", "confidence": "low", "category": "C", "evidence": []}],
    })

    temp_store.delete_analysis("del_casc")

    with temp_store._get_connection() as conn:
        f_count = conn.execute("SELECT COUNT(*) FROM findings WHERE analysis_id = 'del_casc';").fetchone()[0]
        assert f_count == 0


# ---------------------------------------------------------------------------
# TEST 20: RAG Collection Isolation
# ---------------------------------------------------------------------------
def test_20_rag_collection_isolation(temp_store):
    coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)
    initial_count = coll.count()

    temp_store.save_analysis({"status": "success", "analysis_id": "iso_1", "query": "q", "summary": {}, "findings": []})
    temp_store.delete_analysis("iso_1")

    assert coll.count() == initial_count


# ---------------------------------------------------------------------------
# TEST 21: Secret Protection
# ---------------------------------------------------------------------------
def test_21_secret_protection(temp_store):
    code = """
def auth():
    api_key = "THIS_SECRET_MUST_NOT_APPEAR"
    return api_key
"""
    res = analyze_source_code(code, query="possible_hardcoded_secret", db_path=temp_store.db_path)
    res_str = json.dumps(res)

    assert "THIS_SECRET_MUST_NOT_APPEAR" not in res_str

    saved = temp_store.get_analysis(res["analysis_id"])
    saved_str = json.dumps(saved)
    assert "THIS_SECRET_MUST_NOT_APPEAR" not in saved_str


# ---------------------------------------------------------------------------
# TEST 22: Raw Source Protection
# ---------------------------------------------------------------------------
def test_22_raw_source_protection(temp_store):
    code = "def confidential(): pass"
    res = analyze_source_code(code, query="confidential", db_path=temp_store.db_path)

    saved = temp_store.get_analysis(res["analysis_id"])
    saved_str = json.dumps(saved)

    assert "def confidential()" not in saved_str
    assert "source_code" not in saved_str
    assert "raw_source" not in saved_str


# ---------------------------------------------------------------------------
# TEST 23: JSON Serialization Validity
# ---------------------------------------------------------------------------
def test_23_json_serialization(temp_store):
    temp_store.save_analysis({
        "status": "success",
        "analysis_id": "json_1",
        "query": "q",
        "summary": {"total_findings": 0},
        "findings": [],
    })
    res = temp_store.get_analysis("json_1")

    dumped = json.dumps(res)
    loaded = json.loads(dumped)
    assert loaded["analysis_id"] == "json_1"


# ---------------------------------------------------------------------------
# TEST 24: Step 6I Regression (POST /analyze persistence)
# ---------------------------------------------------------------------------
def test_24_step_6i_regression():
    client = TestClient(app)
    resp = client.post("/analyze", json={"source_code": "def foo(): pass", "query": "security"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "analysis_id" in data


# ---------------------------------------------------------------------------
# TEST 25: FastAPI History Endpoints Regression
# ---------------------------------------------------------------------------
def test_25_fastapi_history_endpoints_regression():
    client = TestClient(app)

    # 1. Run analysis via POST /analyze
    post_resp = client.post("/analyze", json={"source_code": "def run_cmd(c):\n    import os\n    os.system(c)", "query": "command"})
    assert post_resp.status_code == 200
    analysis_id = post_resp.json()["analysis_id"]

    # 2. GET /analyses
    get_list_resp = client.get("/analyses")
    assert get_list_resp.status_code == 200
    assert get_list_resp.json()["status"] == "success"

    # 3. GET /analyses/{analysis_id}
    get_single_resp = client.get(f"/analyses/{analysis_id}")
    assert get_single_resp.status_code == 200
    assert get_single_resp.json()["analysis"]["analysis_id"] == analysis_id

    # 4. GET /analyses/{analysis_id}/findings
    get_findings_resp = client.get(f"/analyses/{analysis_id}/findings")
    assert get_findings_resp.status_code == 200
    assert "findings" in get_findings_resp.json()

    # 5. DELETE /analyses/{analysis_id}
    del_resp = client.delete(f"/analyses/{analysis_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # 6. Verify 404 after delete
    get_again_resp = client.get(f"/analyses/{analysis_id}")
    assert get_again_resp.status_code == 404
