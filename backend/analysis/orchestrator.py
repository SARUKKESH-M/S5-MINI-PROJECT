"""CodeSentinel Backend Security Analysis Orchestrator.

Orchestrates full AST Engine, RAG Ingestion & Hybrid Retrieval, Context Ranking,
LLM Context Building, LLM Security Analyzer execution, and persistent storage
of analysis results into a unified workflow.
"""

from typing import Any, Dict, Optional
from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from ast_engine.evidence_normalizer import normalize_security_evidence
from rag.ingestion import ingest_documents
from rag.vector_store import DEFAULT_COLLECTION_NAME
from backend.analysis.storage.store import AnalysisStore
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.finding_enrichment import enrich_findings
from backend.analysis.finding_normalizer import normalize_findings
from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings

MAX_SOURCE_LENGTH = 100000  # 100KB input limit protection

_analysis_counter = 0


def reset_analysis_counter() -> None:
    """Reset deterministic analysis ID counter for test suite isolation."""
    global _analysis_counter
    _analysis_counter = 0


def _get_next_analysis_id() -> str:
    """Generate next deterministic analysis ID (e.g. analysis_1, analysis_2)."""
    global _analysis_counter
    _analysis_counter += 1
    return f"analysis_{_analysis_counter}"


def analyze_source_code(
    source_code: Optional[str] = "",
    query: Optional[str] = "security analysis",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete security analysis pipeline on target source code.

    Pipeline:
      1. Validate input source code and length limits.
      2. Normalize search query (defaults to 'security analysis' if empty).
      3. Parse and produce deterministic AST security evidence.
      4. Generate findings directly from that evidence.
      5. Ingest AST documents and enrich findings with optional RAG context.
      6. Normalize, aggregate, persist, and return findings.
    """
    analysis_id = _get_next_analysis_id()

    # Normalize Query
    clean_query = (query or "").strip()
    if not clean_query:
        clean_query = "security analysis"

    # 1. Input Validation: Null or Empty / Whitespace-Only Source
    clean_source = source_code if source_code is not None else ""
    if not clean_source.strip():
        res = {
            "status": "success",
            "analysis_id": analysis_id,
            "query": clean_query,
            "summary": {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [],
            "context": {
                "ast_context_count": 0,
                "security_knowledge_context_count": 0,
            },
            "provider": "mock",
            "analysis_version": "1.0",
            "finding_count": 0,
        }
        _safely_persist_analysis(res, db_path=db_path)
        return res

    # 2. Input Validation: Maximum Source Size Limit
    if len(clean_source) > MAX_SOURCE_LENGTH:
        return {
            "status": "error",
            "analysis_id": analysis_id,
            "error_message": f"Source code exceeds maximum allowed size limit of {MAX_SOURCE_LENGTH:,} characters.",
            "query": clean_query,
            "summary": {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [],
            "context": {
                "ast_context_count": 0,
                "security_knowledge_context_count": 0,
            },
            "provider": "mock",
            "analysis_version": "1.0",
            "finding_count": 0,
        }

    try:
        normalized_evidence = normalize_security_evidence(clean_source, file_path="<source>")
        security_evidence = normalized_evidence.get("security_evidence", [])
        ast_docs = prepare_ast_documents_for_rag(clean_source, file_path="<source>")

        # Step 6B: Ingest AST Documents into ChromaDB
        if ast_docs:
            ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)

        raw_findings = generate_deterministic_findings(security_evidence)
        enriched_findings = enrich_findings(raw_findings, db_path=db_path)
        evidence_ids = {str(item.get("evidence_id")) for item in security_evidence if item.get("evidence_id")}
        normalized_findings = normalize_findings(enriched_findings, valid_document_ids=evidence_ids)
        aggregated = aggregate_and_deduplicate_findings(normalized_findings)

        # Format Final Controlled Response Schema
        res = {
            "status": "success",
            "analysis_id": analysis_id,
            "query": clean_query,
            "summary": aggregated["summary"],
            "findings": aggregated["findings"],
            "context": {
                "ast_context_count": len(security_evidence),
                "security_knowledge_context_count": sum("rag" in finding.get("enriched_by", []) for finding in enriched_findings),
            },
            "provider": "mock",
            "analysis_version": "1.0",
            "finding_count": len(aggregated["findings"]),
        }

        # Step 6J: Persist analysis result to SQLite store
        _safely_persist_analysis(res, db_path=db_path)
        return res

    except Exception:
        # Controlled Error Handling (Sanitize internal stack traces)
        return {
            "status": "error",
            "analysis_id": analysis_id,
            "error_message": "An internal error occurred during security analysis orchestration.",
            "query": clean_query,
            "summary": {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [],
            "context": {
                "ast_context_count": 0,
                "security_knowledge_context_count": 0,
            },
            "provider": "mock",
            "analysis_version": "1.0",
            "finding_count": 0,
        }


def _safely_persist_analysis(res: Dict[str, Any], db_path: Optional[str] = None) -> None:
    """Safely persist analysis result without exposing database exceptions to caller."""
    try:
        store = AnalysisStore(db_path=db_path)
        store.save_analysis(res)
    except Exception:
        pass
