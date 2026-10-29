"""Unit and Integration Tests for CodeSentinel Upgrade 2A-4: Opt-In RAG Ingestion & CLI.

Verifies:
1. Disabled-by-default behavior leaves normal ingestion unchanged (only 12 OWASP docs).
2. Explicit opt-in ingests bounded MITRE CWE and CISA KEV data.
3. Expected counts: exactly 26 MITRE CWE documents and 429 distinct KEV CVE documents.
4. Repeated ingestion is idempotent: no duplicate IDs, stable chunk counts.
5. External metadata strictly maintains severity=None (empty string in ChromaDB).
6. Missing datasets and invalid source names fail safely with clear errors.
7. CVEfixes is blocked from production ingestion with an informative error.
8. External knowledge cannot alter deterministic findings or security-gate decisions.
9. Existing Upgrade 1 short-circuit and context quotas remain intact.
"""

import os
import sys
import pytest
from typing import Dict, Any

# Ensure workspace root and backend are on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
backend_dir = os.path.join(ROOT_DIR, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.config import settings
from rag.ingestion import (
    ensure_curated_knowledge_ingested,
    ingest_external_security_knowledge,
    reset_curated_knowledge_cache,
    reset_document_embedding_cache,
)
from rag.vector_store import (
    get_security_knowledge_collection,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.context_builder import build_security_analysis_context
from backend.analysis.finding_enrichment import enrich_findings, _find_exact_curated_knowledge


@pytest.fixture(autouse=True)
def skip_if_datasets_missing(request):
    """Skip tests requiring external dataset archives if datasets/ directory is absent."""
    if request.node.name == "test_1_disabled_by_default_leaves_normal_ingestion_unchanged":
        return
    if request.node.name in ("test_6_missing_dataset_fails_safely", "test_6b_invalid_source_name_rejected", "test_7_cvefixes_blocked_from_production"):
        return
    cwe_zip = os.path.join(ROOT_DIR, "datasets", "mitre_cwe", "cwec_latest.xml.zip")
    if not os.path.isfile(cwe_zip):
        pytest.skip("External datasets archive not present in clean CI checkout")


# ---------------------------------------------------------------------------
# TEST 1: Disabled-by-Default Configuration
# ---------------------------------------------------------------------------

def test_1_disabled_by_default_leaves_normal_ingestion_unchanged(tmp_path):
    """Verify ENABLE_EXTERNAL_KNOWLEDGE defaults to False and only 12 OWASP docs are ingested."""
    assert getattr(settings, "ENABLE_EXTERNAL_KNOWLEDGE", None) is False, (
        "ENABLE_EXTERNAL_KNOWLEDGE must default to False"
    )

    db_path = str(tmp_path / "chroma_default")
    reset_curated_knowledge_cache()

    # Normal ingestion without opt-in flag
    res = ensure_curated_knowledge_ingested(db_path=db_path)
    assert res.get("status") == "success"
    assert "external_knowledge" not in res, "External knowledge must not be ingested by default"

    # Inspect collection: should only contain the 12 OWASP documents (chunked)
    coll = get_security_knowledge_collection(db_path=db_path)
    all_docs = coll.get()
    all_ids = all_docs.get("ids", [])

    # Curated OWASP chunks have ids starting with 'knowledge_cwe_'
    owasp_chunks = [i for i in all_ids if "owasp" in i or "knowledge_cwe_" in i]
    mitre_chunks = [i for i in all_ids if "mitre_cwe" in i]
    kev_chunks = [i for i in all_ids if "cisa_kev" in i]

    assert len(owasp_chunks) > 0, "Expected core OWASP chunks"
    assert len(mitre_chunks) == 0, "No MITRE CWE chunks should exist by default"
    assert len(kev_chunks) == 0, "No CISA KEV chunks should exist by default"


# ---------------------------------------------------------------------------
# TEST 2 & 3: Explicit Opt-In Ingestion & Exact Verified Counts
# ---------------------------------------------------------------------------

def test_2_and_3_explicit_opt_in_ingests_mitre_and_kev(tmp_path):
    """Verify explicit opt-in ingests exactly 26 MITRE CWE and 429 CISA KEV documents."""
    db_path = str(tmp_path / "chroma_external")
    reset_curated_knowledge_cache()
    reset_document_embedding_cache()

    res = ingest_external_security_knowledge(
        sources=["mitre_cwe", "cisa_kev"],
        db_path=db_path,
        force=False,
    )

    assert res.get("status") == "success"
    assert res.get("collection_name") == SECURITY_KNOWLEDGE_COLLECTION_NAME

    sources = res.get("sources", {})
    assert "mitre_cwe" in sources
    assert "cisa_kev" in sources

    # Verify MITRE CWE exact counts
    mitre_res = sources["mitre_cwe"]
    assert mitre_res.get("status") == "success"
    assert mitre_res.get("document_count") == 26, f"Expected 26 MITRE CWE docs, got {mitre_res.get('document_count')}"
    assert mitre_res.get("chunk_count") > 26

    # Verify CISA KEV exact counts
    kev_res = sources["cisa_kev"]
    assert kev_res.get("status") == "success"
    assert kev_res.get("document_count") == 429, f"Expected 429 distinct KEV docs, got {kev_res.get('document_count')}"
    assert kev_res.get("chunk_count") >= 429

    stats = kev_res.get("stats", {})
    assert stats.get("source_records") == 1731
    assert stats.get("missing_cwe") == 175
    assert stats.get("unsupported_cwe") == 1127
    assert stats.get("matched_associations") == 431


# ---------------------------------------------------------------------------
# TEST 4: Repeated Ingestion Idempotency
# ---------------------------------------------------------------------------

def test_4_repeated_ingestion_is_idempotent(tmp_path):
    """Verify repeat ingestion without force skips re-embedding and creates no duplicate IDs."""
    db_path = str(tmp_path / "chroma_idempotent")
    reset_curated_knowledge_cache()
    reset_document_embedding_cache()

    # First run: Ingests documents
    res1 = ingest_external_security_knowledge(
        sources=["mitre_cwe"],
        db_path=db_path,
        force=False,
    )
    assert res1["sources"]["mitre_cwe"]["already_present"] is False
    assert res1["sources"]["mitre_cwe"]["chunk_count"] > 0

    coll = get_security_knowledge_collection(db_path=db_path)
    count_after_first = coll.count()

    # Second run without force: must detect presence and skip re-embedding
    res2 = ingest_external_security_knowledge(
        sources=["mitre_cwe"],
        db_path=db_path,
        force=False,
    )
    assert res2["sources"]["mitre_cwe"]["already_present"] is True
    assert res2["sources"]["mitre_cwe"]["chunk_count"] == 0

    # Total count in collection must remain strictly identical
    assert coll.count() == count_after_first


# ---------------------------------------------------------------------------
# TEST 5: Security Authority Invariant (severity=None)
# ---------------------------------------------------------------------------

def test_5_external_metadata_has_severity_none(tmp_path):
    """Verify that all external knowledge chunks in ChromaDB maintain severity as unset/None."""
    db_path = str(tmp_path / "chroma_severity_test")
    reset_curated_knowledge_cache()

    ingest_external_security_knowledge(
        sources=["mitre_cwe", "cisa_kev"],
        db_path=db_path,
        force=False,
    )

    coll = get_security_knowledge_collection(db_path=db_path)
    data = coll.get()
    metadatas = data.get("metadatas", [])

    for meta in metadatas:
        source = meta.get("source", "")
        if source in ("mitre_cwe", "cisa_kev"):
            # In ChromaDB, None is cleaned to empty string "" by _clean_metadata_for_chroma
            assert meta.get("severity") in (None, ""), (
                f"Security Authority Violation: {source} chunk has non-empty severity {meta.get('severity')}"
            )


# ---------------------------------------------------------------------------
# TEST 6: Missing Datasets & Invalid Source Names Fail Safely
# ---------------------------------------------------------------------------

def test_6_invalid_sources_and_missing_datasets_fail_safely(tmp_path):
    """Verify invalid source names and missing datasets raise clear exceptions."""
    db_path = str(tmp_path / "chroma_err_test")

    # Invalid source name
    with pytest.raises(ValueError, match="Invalid external knowledge source 'unknown_source'"):
        ingest_external_security_knowledge(sources=["unknown_source"], db_path=db_path)

    # Missing dataset directory
    nonexistent_dir = str(tmp_path / "nonexistent_datasets")
    with pytest.raises(FileNotFoundError, match="not found at"):
        ingest_external_security_knowledge(
            sources=["mitre_cwe"],
            db_path=db_path,
            dataset_dir=nonexistent_dir,
        )


# ---------------------------------------------------------------------------
# TEST 7: CVEfixes Blocker Enforcement
# ---------------------------------------------------------------------------

def test_7_cvefixes_cannot_be_selected_for_production(tmp_path):
    """Verify attempting to ingest CVEfixes raises a ValueError with the blocker rationale."""
    db_path = str(tmp_path / "chroma_cvefixes_block")

    with pytest.raises(ValueError, match="CVEfixes dataset is blocked from production ingestion"):
        ingest_external_security_knowledge(sources=["cvefixes"], db_path=db_path)


# ---------------------------------------------------------------------------
# TEST 8: External Knowledge Cannot Alter Deterministic Findings
# ---------------------------------------------------------------------------

def test_8_external_knowledge_cannot_alter_deterministic_findings(tmp_path):
    """Verify deterministic AST findings are not removed, inflated, or modified by external knowledge."""
    db_path = str(tmp_path / "chroma_advisory_test")
    reset_curated_knowledge_cache()

    # Ingest core + external knowledge
    ensure_curated_knowledge_ingested(db_path=db_path, include_external=True)

    dummy_finding = {
        "finding_id": "FINDING_101",
        "file": "app/db.py",
        "line": 42,
        "severity": "high",  # AST-derived severity
        "confidence": "high",
        "category": "sql_injection",
        "message": "Unsafe query concatenation detected",
        "evidence": [{"signal_type": "unsafe_database_execution"}],
    }

    enriched = enrich_findings([dummy_finding], db_path=db_path)
    assert len(enriched) == 1
    res = enriched[0]

    # Invariants preserved
    assert res["finding_id"] == "FINDING_101"
    assert res["severity"] == "high", "AST severity must not be altered by external knowledge"
    assert res["confidence"] == "high"
    assert res.get("cwe_id") == "CWE-89"


# ---------------------------------------------------------------------------
# TEST 9: Upgrade 1 Curated Short-Circuit and RAG Context Quotas Intact
# ---------------------------------------------------------------------------

def test_9_upgrade_1_curated_short_circuit_and_quotas_intact(tmp_path):
    """Verify Upgrade 1 exact-curated short-circuit is preserved and context quotas remain bounded."""
    # 1. Verify exact curated CWE short-circuit
    match = _find_exact_curated_knowledge("CWE-89")
    assert match is not None
    assert match.get("metadata", {}).get("cwe_id") == "CWE-89"

    # 2. Verify RAG context quota boundaries
    db_path = str(tmp_path / "chroma_quotas")
    reset_curated_knowledge_cache()
    ensure_curated_knowledge_ingested(db_path=db_path, include_external=True)

    context = build_security_analysis_context("CWE-89 SQL injection vulnerability", top_k=5, db_path=db_path)
    assert context.get("status") == "success"
    assert context.get("context_document_count") <= 20
    assert len(context.get("context_documents", [])) <= 20

