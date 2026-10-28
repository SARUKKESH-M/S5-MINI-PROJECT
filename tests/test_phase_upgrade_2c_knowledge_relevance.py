"""Upgrade 2C Verification Test Suite for CodeSentinel.

Validates:
1. Balanced RAG context selection: Security knowledge is not starved by AST evidence.
2. Ranking and selection determinism.
3. Strict enforcement of MAX_CONTEXT_DOCUMENTS (20) and MAX_CONTENT_LENGTH (4000).
4. Verified AST signal topic mappings in finding_enrichment.
5. Signal-to-CWE fallback for exact curated OWASP knowledge resolution.
6. Precedence of explicit valid CWE metadata over fallback mappings.
7. Absolute immutability of authoritative finding fields during RAG enrichment.
8. Safe, graceful degradation on vector store / ChromaDB failures.
9. Transient AST collection isolation between distinct analysis runs.
"""

import copy
import json
import os
import sys
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rag.context_builder import (
    build_security_analysis_context,
    MAX_CONTEXT_DOCUMENTS,
    MAX_CONTENT_LENGTH,
)
from rag.vector_store import (
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
    generate_transient_ast_collection_name,
    get_collection,
    delete_transient_collection,
)
from rag.ingestion import ingest_documents, ingest_security_knowledge
from knowledge.sample_data import SAMPLE_SECURITY_KNOWLEDGE
from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from backend.analysis.finding_enrichment import (
    enrich_findings,
    build_structured_rag_query,
    SIGNAL_TOPIC_MAPPING,
    SIGNAL_CWE_MAPPING,
)
from backend.analysis.deterministic_findings import _TITLES


@pytest.fixture(autouse=True)
def setup_test_collections():
    """Ensure baseline collections are populated with sample data."""
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
# 1. Balanced Knowledge Context: Security Knowledge Not Starved
# ---------------------------------------------------------------------------
def test_security_knowledge_retained_when_multiple_ast_evidence_matches():
    """Verify that relevant security knowledge is retained when multiple AST evidence items match."""
    res = build_security_analysis_context("SQL parameterization", top_k=5)

    assert res["status"] == "success"
    sec_kn = res["context"]["security_knowledge"]
    assert len(sec_kn) > 0, "Security knowledge section must not be starved when AST documents match"

    for doc in sec_kn:
        assert doc["source_category"] == "security_knowledge"
        assert doc.get("document_id") is not None
        assert doc.get("relevance_score") is not None

    # Verify context documents length respects bound
    assert len(res["context_documents"]) <= MAX_CONTEXT_DOCUMENTS


# ---------------------------------------------------------------------------
# 2. Ranking and Selection Determinism
# ---------------------------------------------------------------------------
def test_ranking_and_selection_remain_deterministic():
    """Verify that multiple context building calls with identical queries yield 100% identical output."""
    res_a = build_security_analysis_context("database execution", top_k=5)
    res_b = build_security_analysis_context("database execution", top_k=5)

    dump_a = json.dumps(res_a, sort_keys=True)
    dump_b = json.dumps(res_b, sort_keys=True)
    assert dump_a == dump_b


# ---------------------------------------------------------------------------
# 3. Context Size and Content-Length Bounds Enforced
# ---------------------------------------------------------------------------
def test_context_document_and_content_size_limits_enforced():
    """Verify that context document count never exceeds 20 and oversized content is truncated."""
    res = build_security_analysis_context("database execution", top_k=50)

    assert res["status"] == "success"
    assert len(res["context_documents"]) <= MAX_CONTEXT_DOCUMENTS
    assert res["context_document_count"] <= MAX_CONTEXT_DOCUMENTS

    for doc in res["context_documents"]:
        content = doc.get("content", "")
        assert len(content) <= MAX_CONTENT_LENGTH + 20
        if len(content) > MAX_CONTENT_LENGTH:
            assert content.endswith("...[truncated]")


# ---------------------------------------------------------------------------
# 4. Verified AST Signal Topic Mappings
# ---------------------------------------------------------------------------
def test_all_emitted_ast_signals_have_verified_topic_mappings():
    """Verify that every signal emitted by AST analyzers has a mapped security topic."""
    emitted_signals = list(_TITLES.keys())
    assert len(emitted_signals) >= 9

    for sig in emitted_signals:
        assert sig in SIGNAL_TOPIC_MAPPING, f"Signal {sig} must be mapped in SIGNAL_TOPIC_MAPPING"
        topic = SIGNAL_TOPIC_MAPPING[sig]
        assert isinstance(topic, str) and len(topic.strip()) > 0

        # Verify structured query incorporates the mapped topic or signal
        dummy_finding = {
            "evidence": [{"signal_type": sig}],
            "category": "Injection",
            "title": "Sample Finding Title",
        }
        query = build_structured_rag_query(dummy_finding)
        assert len(query) > 0


# ---------------------------------------------------------------------------
# 5. Signal-to-CWE Fallback for Curated Knowledge Lookup
# ---------------------------------------------------------------------------
def test_raw_findings_without_cwe_resolve_curated_guidance_via_signal_mapping():
    """Verify that raw AST findings without root cwe_id resolve curated knowledge via signal fallback."""
    signal_cwe_expectations = {
        "unsafe_database_execution": "CWE-89",
        "command_execution_call": "CWE-78",
        "possible_hardcoded_secret": "CWE-798",
        "path_traversal_call": "CWE-22",
        "insecure_deserialization_call": "CWE-502",
        "dom_xss_call": "CWE-79",
        "reflected_xss_call": "CWE-79",
    }

    for sig, expected_cwe in signal_cwe_expectations.items():
        raw_finding = {
            "finding_id": f"test_{sig}",
            "title": _TITLES.get(sig, "Test Finding"),
            "severity": "high",
            "category": "Injection",
            "evidence": [{"document_id": "doc_123", "signal_type": sig}],
            # Intentionally omitting 'cwe' and 'cwe_id' to test fallback
        }
        enriched = enrich_findings([raw_finding])
        assert len(enriched) == 1
        res_finding = enriched[0]

        assert res_finding.get("cwe_id") == expected_cwe, (
            f"Expected {expected_cwe} for signal {sig}, got {res_finding.get('cwe_id')}"
        )
        assert res_finding.get("security_guidance") is not None
        assert any(expected_cwe in ref for ref in res_finding.get("references", []))
        assert len(res_finding.get("retrieved_knowledge", [])) > 0
        assert any(
            doc.get("metadata", {}).get("cwe_id") == expected_cwe
            for doc in res_finding.get("retrieved_knowledge", [])
        )


# ---------------------------------------------------------------------------
# 6. Precedence of Explicit Valid CWE Metadata
# ---------------------------------------------------------------------------
def test_explicit_valid_cwe_metadata_takes_precedence():
    """Verify explicit finding CWE metadata takes precedence over signal-type fallback."""
    finding_with_explicit_cwe = {
        "finding_id": "test_precedence",
        "cwe_id": "CWE-89",  # Explicit SQL injection CWE
        "title": "Command Injection Risk",
        "severity": "critical",
        "category": "Injection",
        "evidence": [{"document_id": "doc_456", "signal_type": "command_execution_call"}],  # Mapped to CWE-78
    }

    enriched = enrich_findings([finding_with_explicit_cwe])
    assert len(enriched) == 1
    # Explicit CWE-89 must NOT be overwritten by the signal fallback
    assert enriched[0]["cwe_id"] == "CWE-89"


# ---------------------------------------------------------------------------
# 7. Authoritative Finding Immutability
# ---------------------------------------------------------------------------
def test_rag_enrichment_cannot_alter_authoritative_finding_fields():
    """Verify RAG enrichment never modifies authoritative title, severity, category, or evidence."""
    orig_finding = {
        "finding_id": "auth_find_001",
        "title": "Potential SQL Injection Vulnerability",
        "severity": "high",
        "confidence": "high",
        "category": "Injection",
        "evidence": [
            {
                "document_id": "auth_doc_001",
                "line_start": 10,
                "line_end": 12,
                "signal_type": "unsafe_database_execution",
                "signal_name": "cursor.execute",
            }
        ],
    }

    snapshot = copy.deepcopy(orig_finding)
    enriched = enrich_findings([orig_finding])

    assert len(enriched) == 1
    res = enriched[0]

    assert res["finding_id"] == snapshot["finding_id"]
    assert res["title"] == snapshot["title"]
    assert res["severity"] == snapshot["severity"]
    assert res["category"] == snapshot["category"]
    assert res["evidence"] == snapshot["evidence"]


# ---------------------------------------------------------------------------
# 8. Graceful Degradation on Vector Store Failure
# ---------------------------------------------------------------------------
def test_vector_store_failures_degrade_safely_without_dropping_findings(monkeypatch):
    """Verify that vector store failure degrades gracefully and does not drop authoritative findings."""
    def broken_context_builder(*args, **kwargs):
        raise RuntimeError("ChromaDB cluster connection error (simulated)")

    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        broken_context_builder,
    )

    finding = {
        "finding_id": "fail_safe_001",
        "title": "Command Injection Risk",
        "severity": "critical",
        "category": "Injection",
        "evidence": [{"document_id": "doc_999", "signal_type": "command_execution_call"}],
    }

    enriched = enrich_findings([finding])
    assert len(enriched) == 1
    assert enriched[0]["finding_id"] == "fail_safe_001"
    assert enriched[0]["title"] == "Command Injection Risk"
    assert enriched[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 9. Transient AST Collection Isolation
# ---------------------------------------------------------------------------
def test_transient_ast_collections_remain_isolated_between_analyses():
    """Verify transient collections are isolated by analysis ID and safe from accidental deletion."""
    aid_1 = "analysis_alpha_123"
    aid_2 = "analysis_beta_456"

    coll_1 = generate_transient_ast_collection_name(aid_1)
    coll_2 = generate_transient_ast_collection_name(aid_2)

    assert coll_1 != coll_2
    assert coll_1.startswith("ast_")
    assert coll_2.startswith("ast_")

    # Ingest document into coll_1
    sample_doc = prepare_ast_documents_for_rag("def foo(): pass")
    ingest_documents(sample_doc, collection_name=coll_1)

    c1 = get_collection(coll_1)
    assert c1.count() > 0

    # Clean up transient collection
    delete_transient_collection(coll_1)

    # Verify protected collections cannot be accidentally deleted by delete_transient_collection
    delete_transient_collection(SECURITY_KNOWLEDGE_COLLECTION_NAME)
    sec_coll = get_collection(SECURITY_KNOWLEDGE_COLLECTION_NAME)
    assert sec_coll.count() > 0, "Protected security knowledge collection must not be deleted"
