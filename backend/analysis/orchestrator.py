"""CodeSentinel Backend Security Analysis Orchestrator.

Orchestrates full AST Engine, RAG Ingestion & Hybrid Retrieval, Context Ranking,
LLM Context Building, LLM Security Analyzer execution, and persistent storage
of analysis results into a unified workflow.
"""

from typing import Any, Dict, Optional
from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from rag.ingestion import ingest_documents
from rag.vector_store import DEFAULT_COLLECTION_NAME
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.context_ranker import rank_and_deduplicate_context
from rag.context_builder import build_security_analysis_context
from llm.analyzer import analyze_security_context
from backend.analysis.storage.store import AnalysisStore

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
      3. Parse & prepare AST RAG documents via ast_engine.
      4. Ingest AST documents into ChromaDB vector store.
      5. Perform hybrid retrieval from AST evidence + Security Knowledge base.
      6. Rank & deduplicate retrieved context.
      7. Construct LLM-ready security analysis context.
      8. Execute LLM security finding analysis (Step 6H).
      9. Persist analysis result to SQLite store (Step 6J).
      10. Return sanitized structured findings with analysis_id and context stats.
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
        # Step 5F: Prepare AST RAG Documents
        ast_docs = prepare_ast_documents_for_rag(clean_source)

        # Step 6B: Ingest AST Documents into ChromaDB
        if ast_docs:
            ingest_documents(ast_docs, collection_name=DEFAULT_COLLECTION_NAME)

        # Step 6E: Hybrid RAG Retrieval
        hybrid_result = retrieve_hybrid_context(clean_query, top_k_ast=5, top_k_knowledge=5)

        # Step 6F: Post-Retrieval Ranking & Deduplication
        ranked_result = rank_and_deduplicate_context(hybrid_result, top_k=10)

        # Step 6G: Build LLM-Ready Security Analysis Context
        llm_context = build_security_analysis_context(clean_query, top_k=5)

        # Step 6H: Execute LLM Security Analysis
        analyzer_response = analyze_security_context(llm_context)

        # Extract Context Statistics
        ast_cnt = llm_context.get("ast_context_count", 0)
        kn_cnt = llm_context.get("security_knowledge_context_count", 0)

        # Format Final Controlled Response Schema
        res = {
            "status": "success",
            "analysis_id": analysis_id,
            "query": clean_query,
            "summary": analyzer_response.get("summary", {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            }),
            "findings": analyzer_response.get("findings", []),
            "context": {
                "ast_context_count": ast_cnt,
                "security_knowledge_context_count": kn_cnt,
            },
            "provider": analyzer_response.get("provider", "mock"),
            "analysis_version": "1.0",
            "finding_count": len(analyzer_response.get("findings", [])),
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
