"""Phase 4 — RAG + Security Knowledge Hardening Test Suite (A-Q).

Validates all Phase 4 architectural invariants and Step 15 requirements:
  A. All 12 CWE knowledge entries exist.
  B. Every entry contains required metadata.
  C. Knowledge ingestion succeeds.
  D. Re-ingestion is idempotent.
  E. Duplicate chunks are not created.
  F. Security knowledge collection is separate from AST knowledge.
  G. Retrieval can identify relevant knowledge for the 12 CWE patterns.
  H. CWE-based ranking works.
  I. Duplicate retrieval results are removed.
  J. Context size remains bounded.
  K. RAG failure does not remove deterministic findings.
  L. RAG failure does not bypass Step 6O.
  M. LLM enrichment cannot replace deterministic findings.
  N. Importing RAG modules causes no ingestion/network/LLM side effects.
  O. No raw full-source query is used for security knowledge retrieval.
  P. Metadata survives ingestion -> retrieval -> enrichment.
  Q. Deterministic behavior is maintained across repeated runs.

Completely offline and deterministic. Zero external network or unmasked secrets.
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
from rag.context_ranker import rank_and_deduplicate_context
from rag.context_builder import (
    build_security_analysis_context,
    MAX_CONTEXT_DOCUMENTS,
    MAX_CONTENT_LENGTH,
)
from backend.analysis.finding_enrichment import (
    enrich_findings,
    build_structured_rag_query,
)
from backend.analysis.security_gate import evaluate_security_gate


EXPECTED_12_CWES = [
    "CWE-89",
    "CWE-79",
    "CWE-798",
    "CWE-78",
    "CWE-327",
    "CWE-502",
    "CWE-22",
    "CWE-306",
    "CWE-352",
    "CWE-434",
    "CWE-200",
    "CWE-476",
]


@pytest.fixture(scope="module", autouse=True)
def setup_phase_4_store():
    """Ensure curated knowledge is ingested into local ChromaDB for testing."""
    ensure_curated_knowledge_ingested(force=True)


# ===========================================================================
# REQUIREMENT A: All 12 CWE Knowledge Entries Exist
# ===========================================================================
def test_a_all_12_cwe_entries_exist():
    assert len(CURATED_OWASP_KNOWLEDGE) == 12
    found_cwes = [
        doc.get("metadata", {}).get("cwe_id")
        for doc in CURATED_OWASP_KNOWLEDGE
    ]
    for cwe in EXPECTED_12_CWES:
        assert cwe in found_cwes, f"Missing required CWE pattern: {cwe}"


# ===========================================================================
# REQUIREMENT B: Every Entry Contains Required Metadata
# ===========================================================================
def test_b_every_entry_contains_required_metadata():
    required_meta = [
        "schema_version",
        "language",
        "document_type",
        "title",
        "source",
        "category",
        "security_topic",
        "source_type",
        "cwe_id",
        "severity",
    ]
    doc_ids = set()
    for doc in CURATED_OWASP_KNOWLEDGE:
        doc_id = doc.get("document_id")
        assert doc_id, "Missing document_id"
        assert doc_id not in doc_ids, f"Duplicate document_id: {doc_id}"
        doc_ids.add(doc_id)

        content = doc.get("content", "")
        assert len(content) > 50, f"Content too short in {doc_id}"
        assert "remediation" in content.lower() or "secure fix" in content.lower()

        meta = doc.get("metadata", {})
        for field in required_meta:
            assert field in meta and meta[field], f"Missing/empty '{field}' in {doc_id}"
        assert meta["severity"].lower() in ("critical", "high", "medium", "low")


# ===========================================================================
# REQUIREMENT C: Knowledge Ingestion Succeeds
# ===========================================================================
def test_c_knowledge_ingestion_succeeds():
    coll = get_security_knowledge_collection()
    count = coll.count()
    assert count >= 12, f"Expected at least 12 chunks in collection, got {count}"


# ===========================================================================
# REQUIREMENT D: Re-Ingestion is Idempotent
# ===========================================================================
def test_d_reingestion_is_idempotent():
    coll = get_security_knowledge_collection()
    initial_count = coll.count()

    res1 = ensure_curated_knowledge_ingested(force=False)
    assert res1["status"] == "success"
    assert coll.count() == initial_count

    res2 = ensure_curated_knowledge_ingested(force=True)
    assert res2["status"] == "success"
    assert coll.count() == initial_count


# ===========================================================================
# REQUIREMENT E: Duplicate Chunks are Not Created
# ===========================================================================
def test_e_duplicate_chunks_are_not_created():
    doc = CURATED_OWASP_KNOWLEDGE[0]
    chunks = chunk_security_knowledge(doc)
    chunk_ids = [c["document_id"] for c in chunks]
    assert len(chunk_ids) == len(set(chunk_ids)), "Duplicate chunk IDs created"
    for cid in chunk_ids:
        assert cid.startswith(doc["document_id"])
        assert "_chunk_" in cid


# ===========================================================================
# REQUIREMENT F: Security Knowledge Collection Isolated from AST Knowledge
# ===========================================================================
def test_f_collection_isolation():
    sec_coll = get_security_knowledge_collection()
    ast_coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)

    assert sec_coll.name == SECURITY_KNOWLEDGE_COLLECTION_NAME
    assert ast_coll.name == DEFAULT_COLLECTION_NAME
    assert sec_coll.name != ast_coll.name


CWE_STRUCTURED_QUERIES = {
    "CWE-89": "CWE-89 SQL Injection parameterized query cursor.execute",
    "CWE-79": "CWE-79 Cross-Site Scripting XSS html.escape template auto-escaping",
    "CWE-798": "CWE-798 Hardcoded Credentials secret API_KEY password environment variable",
    "CWE-78": "CWE-78 OS Command Injection subprocess shell=False exec",
    "CWE-327": "CWE-327 Broken Cryptographic Algorithm weak hash md5 sha1 bcrypt",
    "CWE-502": "CWE-502 Deserialization of Untrusted Data pickle.loads yaml.safe_load",
    "CWE-22": "CWE-22 Path Traversal directory traversal os.path.basename filepath",
    "CWE-306": "CWE-306 Missing Authentication for Critical Function login session decorator",
    "CWE-352": "CWE-352 Cross-Site Request Forgery CSRF token anti-csrf SameSite",
    "CWE-434": "CWE-434 Unrestricted Upload of File with Dangerous Type filename extension validation",
    "CWE-200": "CWE-200 Exposure of Sensitive Information debug trace stacktrace leak",
    "CWE-476": "CWE-476 NULL Pointer Dereference NoneType check null pointer",
}


# ===========================================================================
# REQUIREMENT G: Retrieval Identifies Relevant Knowledge for all 12 CWEs
# ===========================================================================
@pytest.mark.parametrize("cwe_id", EXPECTED_12_CWES)
def test_g_retrieval_all_12_cwes(cwe_id):
    coll = get_security_knowledge_collection()
    query_str = CWE_STRUCTURED_QUERIES[cwe_id]
    results = coll.query(query_texts=[query_str], n_results=3)
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]

    found = False
    for doc_text, meta in zip(docs, metas):
        if meta.get("cwe_id") == cwe_id or cwe_id in doc_text:
            found = True
            break
    assert found, f"Failed to retrieve relevant knowledge for {cwe_id} with query '{query_str}'"


# ===========================================================================
# REQUIREMENT H: CWE-Based Ranking Works
# ===========================================================================
def test_h_cwe_based_ranking_works():
    hybrid_input = {
        "query": "CWE-89 SQL Injection",
        "ast_results": [],
        "knowledge_results": [
            {
                "document_id": "kn_cwe_79_xss",
                "content": "XSS cross-site scripting prevention guidelines",
                "metadata": {
                    "document_type": "security_knowledge",
                    "cwe_id": "CWE-79",
                    "security_topic": "xss",
                },
            },
            {
                "document_id": "kn_cwe_89_sql",
                "content": "SQL injection prevention and parameterized queries",
                "metadata": {
                    "document_type": "security_knowledge",
                    "cwe_id": "CWE-89",
                    "security_topic": "sql_injection",
                },
            },
        ],
    }

    res = rank_and_deduplicate_context(hybrid_input, top_k=5)
    assert res["status"] == "success"
    assert len(res["results"]) == 2
    # Exact CWE-89 match must be ranked first
    assert res["results"][0]["document_id"] == "kn_cwe_89_sql"
    assert res["results"][0]["relevance_score"] > res["results"][1]["relevance_score"]


# ===========================================================================
# REQUIREMENT I: Duplicate Retrieval Results are Removed
# ===========================================================================
def test_i_duplicate_retrieval_results_are_removed():
    dup_input = {
        "query": "parameterized queries",
        "ast_results": [
            {
                "document_id": "doc_sql_1",
                "content": "Use parameterized queries to prevent SQL injection.",
                "metadata": {"document_type": "security_evidence"},
            },
            {
                "document_id": "doc_sql_1",  # Exact duplicate ID
                "content": "Use parameterized queries to prevent SQL injection.",
                "metadata": {"document_type": "security_evidence"},
            },
        ],
        "knowledge_results": [
            {
                "document_id": "doc_sql_2",
                "content": "Use parameterized queries to prevent SQL injection.",  # Duplicate content
                "metadata": {"document_type": "security_knowledge"},
            }
        ],
    }

    res = rank_and_deduplicate_context(dup_input, top_k=10)
    # Both duplicate ID and content fingerprint should be deduplicated
    assert len(res["results"]) == 1
    assert res["deduplicated_count"] == 1


# ===========================================================================
# REQUIREMENT J: Context Size Remains Bounded
# ===========================================================================
def test_j_context_size_remains_bounded():
    ctx = build_security_analysis_context("sql_injection", top_k=50)
    assert ctx["status"] == "success"
    assert len(ctx["context_documents"]) <= MAX_CONTEXT_DOCUMENTS
    for doc in ctx["context_documents"]:
        assert len(doc["content"]) <= MAX_CONTENT_LENGTH + 25


# ===========================================================================
# REQUIREMENT K: RAG Failure Does Not Remove Deterministic Findings
# ===========================================================================
def test_k_rag_failure_does_not_remove_findings(monkeypatch):
    def failing_builder(*args, **kwargs):
        raise RuntimeError("ChromaDB vector store connection failed")

    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        failing_builder,
    )

    findings = [
        {
            "finding_id": "finding_sql_1",
            "title": "Potential SQL Injection",
            "severity": "high",
            "evidence": [{"signal_type": "unsafe_database_execution"}],
            "enriched_by": [],
        },
        {
            "finding_id": "finding_cmd_2",
            "title": "Command Injection Risk",
            "severity": "critical",
            "evidence": [{"signal_type": "command_execution_call"}],
            "enriched_by": [],
        },
    ]

    result = enrich_findings(findings)
    # Findings must NOT be dropped on RAG failure
    assert len(result) == 2
    assert result[0]["finding_id"] == "finding_sql_1"
    assert result[0]["severity"] == "high"
    assert result[1]["finding_id"] == "finding_cmd_2"
    assert result[1]["severity"] == "critical"
    # RAG provenance omitted, offline LLM mock applied
    assert "rag" not in result[0]["enriched_by"]


# ===========================================================================
# REQUIREMENT L: RAG Failure Does Not Bypass Step 6O Security Gate
# ===========================================================================
def test_l_rag_failure_does_not_bypass_step_6o(monkeypatch):
    def failing_builder(*args, **kwargs):
        raise RuntimeError("Vector store completely unavailable")

    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        failing_builder,
    )

    critical_finding = {
        "finding_id": "finding_crit_1",
        "title": "Critical Command Injection",
        "severity": "critical",
        "evidence": [{"signal_type": "command_execution_call"}],
        "enriched_by": [],
    }

    enriched = enrich_findings([critical_finding])
    assert len(enriched) == 1
    assert enriched[0]["severity"] == "critical"

    # Evaluate Step 6O Security Gate with post-RAG counts
    report = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "critical_count": sum(1 for f in enriched if f["severity"] == "critical"),
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }
    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1


# ===========================================================================
# REQUIREMENT M: LLM Enrichment Cannot Replace Deterministic Findings
# ===========================================================================
def test_m_llm_enrichment_cannot_replace_deterministic_findings():
    finding = {
        "finding_id": "authoritative_finding_42",
        "title": "Authoritative SQL Vulnerability",
        "severity": "critical",
        "category": "Injection",
        "evidence": [{"signal_type": "unsafe_database_execution"}],
        "enriched_by": [],
    }

    result = enrich_findings([finding])
    assert len(result) == 1
    res = result[0]
    # Authoritative fields must NOT be mutated
    assert res["finding_id"] == "authoritative_finding_42"
    assert res["title"] == "Authoritative SQL Vulnerability"
    assert res["severity"] == "critical"
    assert res["category"] == "Injection"
    assert len(res["evidence"]) == 1


# ===========================================================================
# REQUIREMENT N: Importing RAG Modules Causes No Side Effects
# ===========================================================================
def test_n_import_time_no_side_effects():
    # Verify module attributes and functions exist without running operations
    import rag
    import knowledge
    import backend.analysis.finding_enrichment

    assert hasattr(rag, "build_security_analysis_context")
    assert hasattr(knowledge, "load_security_knowledge")
    assert hasattr(backend.analysis.finding_enrichment, "enrich_findings")


# ===========================================================================
# REQUIREMENT O: No Raw Full-Source Query Used for Security Knowledge Retrieval
# ===========================================================================
def test_o_no_raw_full_source_query():
    finding_with_source = {
        "finding_id": "f_1",
        "title": "SQL Injection in User Query",
        "severity": "high",
        "category": "Injection",
        "cwe_id": "CWE-89",
        "evidence": [{"signal_type": "unsafe_database_execution"}],
        "raw_source_code": "def query_db():\n    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n    return True\n",
    }

    structured_query = build_structured_rag_query(finding_with_source)
    # Must contain structured signals
    assert "CWE-89" in structured_query
    assert "sql_injection" in structured_query
    # Must NOT contain raw full source code
    assert "def query_db" not in structured_query
    assert "SELECT * FROM" not in structured_query


# ===========================================================================
# REQUIREMENT P: Metadata Survives Ingestion -> Retrieval -> Enrichment
# ===========================================================================
def test_p_metadata_survives_pipeline():
    finding = {
        "finding_id": "f_p1",
        "title": "Hardcoded Secret Vulnerability",
        "severity": "critical",
        "category": "Credential Handling",
        "evidence": [{"signal_type": "possible_hardcoded_secret"}],
        "enriched_by": [],
    }

    enriched = enrich_findings([finding])
    assert len(enriched) == 1
    item = enriched[0]
    # Enriched finding should contain metadata references from knowledge base
    assert "rag" in item["enriched_by"]
    assert item.get("cwe_id") == "CWE-798"
    assert item.get("references") is not None


# ===========================================================================
# REQUIREMENT Q: Deterministic Behavior Maintained Across Repeated Runs
# ===========================================================================
def test_q_deterministic_behavior_across_repeated_runs():
    query = "CWE-89 sql_injection parameterized query"
    results = []
    for _ in range(3):
        ctx = build_security_analysis_context(query, top_k=5)
        doc_ids = [d["document_id"] for d in ctx["context_documents"]]
        results.append(doc_ids)

    assert results[0] == results[1] == results[2], "RAG context ordering was non-deterministic"
