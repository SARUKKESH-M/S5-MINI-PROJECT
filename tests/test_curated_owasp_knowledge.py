"""Verification Test Suite for Curated OWASP / CWE Security Knowledge Base (P0 #3).

Covers all 25 required verification test categories:
  1. Exactly 12 curated CWE documents exist
  2. All document IDs are unique
  3. All document IDs follow the naming convention (knowledge_cwe_*)
  4. Every document has valid required metadata
  5. Every document has a valid CWE ID
  6. Every document has a valid severity
  7. Every document has a non-empty title
  8. Every document has vulnerable-pattern content
  9. Every document has remediation content
 10. Every document has a normalized security topic
 11. Curated knowledge can be loaded successfully via load_security_knowledge()
 12. Curated knowledge can be ingested via ensure_curated_knowledge_ingested()
 13. Repeated ingestion is idempotent
 14. Security knowledge collection remains isolated from AST evidence collection
 15. CWE-89 / SQL injection retrieval works
 16. CWE-78 / command injection retrieval works
 17. CWE-798 / credential handling retrieval works
 18. CWE-327 / weak cryptography retrieval works
 19. CWE-502 / deserialization retrieval works
 20. CWE-22 / path traversal retrieval works
 21. CWE-79 / XSS retrieval works
 22. Relevant curated context reaches the enrichment pipeline
 23. Curated knowledge does not alter deterministic finding severity
 24. Curated knowledge does not alter security gate decisions
 25. Bounded context constraints are preserved

ZERO real external network or LLM calls. Completely offline and deterministic.
"""

import os
import sys
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knowledge.curated_owasp import CURATED_OWASP_KNOWLEDGE
from knowledge.loader import load_security_knowledge, chunk_security_knowledge
from rag.ingestion import (
    ingest_security_knowledge,
    ensure_curated_knowledge_ingested,
    ingest_documents,
)
from rag.vector_store import (
    get_security_knowledge_collection,
    get_collection,
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.retrieval import retrieve_documents
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.context_builder import build_security_analysis_context, MAX_CONTEXT_DOCUMENTS
from backend.analysis.finding_enrichment import enrich_findings
from backend.analysis.security_gate import evaluate_security_gate


EXPECTED_CWES = {
    "CWE-89", "CWE-79", "CWE-798", "CWE-78", "CWE-327", "CWE-502",
    "CWE-22", "CWE-306", "CWE-352", "CWE-434", "CWE-200", "CWE-476"
}

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}


@pytest.fixture(autouse=True)
def setup_curated_store():
    """Ensure the curated knowledge base is ingested once before running retrieval tests."""
    ensure_curated_knowledge_ingested(force=True)


# ---------------------------------------------------------------------------
# TEST 1: Exactly 12 Curated Documents Exist
# ---------------------------------------------------------------------------
def test_1_exactly_12_curated_documents_exist():
    assert len(CURATED_OWASP_KNOWLEDGE) == 12


# ---------------------------------------------------------------------------
# TEST 2: All Document IDs are Unique
# ---------------------------------------------------------------------------
def test_2_all_document_ids_unique():
    doc_ids = [doc.get("document_id") for doc in CURATED_OWASP_KNOWLEDGE]
    assert len(doc_ids) == 12
    assert len(set(doc_ids)) == 12


# ---------------------------------------------------------------------------
# TEST 3: All Document IDs Follow the Naming Convention
# ---------------------------------------------------------------------------
def test_3_document_id_naming_convention():
    for doc in CURATED_OWASP_KNOWLEDGE:
        doc_id = doc.get("document_id", "")
        assert doc_id.startswith("knowledge_cwe_"), f"Invalid ID format: {doc_id}"


# ---------------------------------------------------------------------------
# TEST 4: Every Document Has Valid Required Metadata
# ---------------------------------------------------------------------------
def test_4_valid_required_metadata():
    required_meta = [
        "schema_version", "language", "document_type", "title",
        "source", "category", "security_topic", "source_type"
    ]
    for doc in CURATED_OWASP_KNOWLEDGE:
        meta = doc.get("metadata", {})
        for field in required_meta:
            assert field in meta, f"Missing metadata '{field}' in {doc.get('document_id')}"
            assert meta[field], f"Empty metadata '{field}' in {doc.get('document_id')}"
        assert meta["document_type"] == "security_knowledge"
        assert meta["source_type"] == "knowledge_base"
        assert meta["source"] == "owasp_curated"


# ---------------------------------------------------------------------------
# TEST 5: Every Document Has a Valid CWE ID
# ---------------------------------------------------------------------------
def test_5_every_document_has_cwe_id():
    found_cwes = set()
    for doc in CURATED_OWASP_KNOWLEDGE:
        meta = doc.get("metadata", {})
        cwe_id = meta.get("cwe_id")
        assert cwe_id is not None, f"Missing cwe_id in {doc.get('document_id')}"
        assert cwe_id.startswith("CWE-"), f"Malformed cwe_id in {doc.get('document_id')}: {cwe_id}"
        found_cwes.add(cwe_id)
    assert found_cwes == EXPECTED_CWES


# ---------------------------------------------------------------------------
# TEST 6: Every Document Has a Valid Severity
# ---------------------------------------------------------------------------
def test_6_every_document_has_severity():
    for doc in CURATED_OWASP_KNOWLEDGE:
        meta = doc.get("metadata", {})
        sev = meta.get("severity")
        assert sev is not None, f"Missing severity in {doc.get('document_id')}"
        assert sev.lower() in ALLOWED_SEVERITIES, f"Invalid severity '{sev}' in {doc.get('document_id')}"


# ---------------------------------------------------------------------------
# TEST 7: Every Document Has a Non-Empty Title
# ---------------------------------------------------------------------------
def test_7_every_document_has_title():
    for doc in CURATED_OWASP_KNOWLEDGE:
        title = doc.get("metadata", {}).get("title")
        assert title and len(title.strip()) > 5, f"Title missing or too short in {doc.get('document_id')}"


# ---------------------------------------------------------------------------
# TEST 8: Every Document Has Vulnerable-Pattern Content
# ---------------------------------------------------------------------------
def test_8_every_document_has_vulnerable_pattern():
    for doc in CURATED_OWASP_KNOWLEDGE:
        content = doc.get("content", "")
        assert "vulnerable pattern" in content.lower(), f"No vulnerable pattern in {doc.get('document_id')}"


# ---------------------------------------------------------------------------
# TEST 9: Every Document Has Remediation Content
# ---------------------------------------------------------------------------
def test_9_every_document_has_remediation_content():
    for doc in CURATED_OWASP_KNOWLEDGE:
        content = doc.get("content", "")
        has_remediation = "secure fix" in content.lower() or "remediation" in content.lower()
        assert has_remediation, f"No remediation guidance in {doc.get('document_id')}"


# ---------------------------------------------------------------------------
# TEST 10: Every Document Has a Normalized Security Topic
# ---------------------------------------------------------------------------
def test_10_every_document_has_security_topic():
    for doc in CURATED_OWASP_KNOWLEDGE:
        topic = doc.get("metadata", {}).get("security_topic")
        assert topic and isinstance(topic, str) and len(topic) > 0


# ---------------------------------------------------------------------------
# TEST 11: Curated Knowledge Can Be Loaded via load_security_knowledge()
# ---------------------------------------------------------------------------
def test_11_load_security_knowledge():
    validated = load_security_knowledge(CURATED_OWASP_KNOWLEDGE)
    assert len(validated) == 12
    for doc in validated:
        assert doc.get("document_id")
        assert doc.get("content")
        assert doc.get("metadata", {}).get("cwe_id")


# ---------------------------------------------------------------------------
# TEST 12: Ingest Curated Knowledge via ensure_curated_knowledge_ingested()
# ---------------------------------------------------------------------------
def test_12_ingest_curated_knowledge():
    res = ensure_curated_knowledge_ingested(force=True)
    assert res["status"] == "success"
    assert res["ingested_count"] >= 12
    assert res["collection_name"] == SECURITY_KNOWLEDGE_COLLECTION_NAME

    coll = get_security_knowledge_collection()
    assert coll.count() >= 12


# ---------------------------------------------------------------------------
# TEST 13: Repeated Ingestion is Idempotent
# ---------------------------------------------------------------------------
def test_13_repeated_ingestion_is_idempotent():
    coll = get_security_knowledge_collection()
    ensure_curated_knowledge_ingested(force=True)
    count_1 = coll.count()

    res_2 = ensure_curated_knowledge_ingested(force=False)
    count_2 = coll.count()

    assert count_1 == count_2
    assert res_2["status"] == "success"


# ---------------------------------------------------------------------------
# TEST 14: Security Knowledge Isolated from AST Evidence Collection
# ---------------------------------------------------------------------------
def test_14_collection_isolation():
    sec_coll = get_security_knowledge_collection()
    ast_coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)

    assert sec_coll.name == SECURITY_KNOWLEDGE_COLLECTION_NAME
    assert ast_coll.name == DEFAULT_COLLECTION_NAME
    assert sec_coll.name != ast_coll.name


# ---------------------------------------------------------------------------
# TEST 15: CWE-89 / SQL Injection Retrieval Works
# ---------------------------------------------------------------------------
def test_15_cwe_89_sql_injection_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["sql_injection parameterized query cursor.execute"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-89" in doc for doc in docs)
    assert matched, "CWE-89 not retrieved for SQL injection query"


# ---------------------------------------------------------------------------
# TEST 16: CWE-78 / Command Injection Retrieval Works
# ---------------------------------------------------------------------------
def test_16_cwe_78_command_injection_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["command_execution subprocess os.system shell=False"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-78" in doc for doc in docs)
    assert matched, "CWE-78 not retrieved for command injection query"


# ---------------------------------------------------------------------------
# TEST 17: CWE-798 / Credential Handling Retrieval Works
# ---------------------------------------------------------------------------
def test_17_cwe_798_credential_handling_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["credential_handling hardcoded API_KEY password env"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-798" in doc for doc in docs)
    assert matched, "CWE-798 not retrieved for credential handling query"


# ---------------------------------------------------------------------------
# TEST 18: CWE-327 / Weak Cryptography Retrieval Works
# ---------------------------------------------------------------------------
def test_18_cwe_327_weak_cryptography_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["weak_cryptography hashlib md5 sha1 bcrypt password hash"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-327" in doc for doc in docs)
    assert matched, "CWE-327 not retrieved for weak cryptography query"


# ---------------------------------------------------------------------------
# TEST 19: CWE-502 / Deserialization Retrieval Works
# ---------------------------------------------------------------------------
def test_19_cwe_502_deserialization_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["deserialization pickle.loads yaml.safe_load untrusted data"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-502" in doc for doc in docs)
    assert matched, "CWE-502 not retrieved for deserialization query"


# ---------------------------------------------------------------------------
# TEST 20: CWE-22 / Path Traversal Retrieval Works
# ---------------------------------------------------------------------------
def test_20_cwe_22_path_traversal_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["path_traversal directory traversal os.path.basename uploads"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-22" in doc for doc in docs)
    assert matched, "CWE-22 not retrieved for path traversal query"


# ---------------------------------------------------------------------------
# TEST 21: CWE-79 / XSS Retrieval Works
# ---------------------------------------------------------------------------
def test_21_cwe_79_xss_retrieval():
    coll = get_security_knowledge_collection()
    results = coll.query(query_texts=["xss cross-site scripting html.escape innerHTML template"], n_results=3)
    docs = results.get("documents", [[]])[0]
    matched = any("CWE-79" in doc for doc in docs)
    assert matched, "CWE-79 not retrieved for XSS query"


# ---------------------------------------------------------------------------
# TEST 22: Relevant Curated Context Reaches Enrichment Pipeline
# ---------------------------------------------------------------------------
def test_22_curated_context_reaches_enrichment_pipeline():
    finding = {
        "finding_id": "finding_1",
        "title": "SQL Injection Signal",
        "severity": "critical",
        "category": "Injection",
        "evidence": [{"signal_type": "unsafe_database_execution"}],
        "enriched_by": [],
    }

    result = enrich_findings([finding])
    assert len(result) == 1
    # RAG context must be successfully attached
    assert "rag" in result[0]["enriched_by"]


# ---------------------------------------------------------------------------
# TEST 23: Curated Knowledge Does Not Alter Deterministic Finding Severity
# ---------------------------------------------------------------------------
def test_23_curated_knowledge_does_not_alter_severity():
    critical_finding = {
        "finding_id": "finding_crit_1",
        "title": "Command Execution Risk",
        "severity": "critical",
        "evidence": [{"signal_type": "command_execution_call"}],
        "enriched_by": [],
    }

    result = enrich_findings([critical_finding])
    assert result[0]["severity"] == "critical"
    assert result[0]["title"] == "Command Execution Risk"


# ---------------------------------------------------------------------------
# TEST 24: Curated Knowledge Does Not Alter Security Gate Decisions
# ---------------------------------------------------------------------------
def test_24_security_gate_invariance():
    finding = {
        "finding_id": "finding_1",
        "title": "Command Execution Risk",
        "severity": "critical",
        "evidence": [{"signal_type": "command_execution_call"}],
        "enriched_by": [],
    }

    report = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }

    decision_before, exit_code_before, _ = evaluate_security_gate(report)
    assert decision_before == "BLOCK"
    assert exit_code_before == 1

    # Enrich finding via RAG
    enriched = enrich_findings([finding])
    assert len(enriched) == 1
    assert enriched[0]["severity"] == "critical"

    # Evaluate gate again on post-enrichment counts
    report_post = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "critical_count": sum(1 for f in enriched if f.get("severity") == "critical"),
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }
    decision_after, exit_code_after, _ = evaluate_security_gate(report_post)
    assert decision_after == decision_before
    assert exit_code_after == exit_code_before


# ---------------------------------------------------------------------------
# TEST 25: Bounded Context Constraints are Preserved
# ---------------------------------------------------------------------------
def test_25_bounded_context_constraints():
    context = build_security_analysis_context("sql_injection", top_k=10)
    assert context["status"] == "success"
    sec_knowledge_docs = context["context"]["security_knowledge"]
    assert len(sec_knowledge_docs) <= MAX_CONTEXT_DOCUMENTS
    assert context["security_knowledge_context_count"] > 0
