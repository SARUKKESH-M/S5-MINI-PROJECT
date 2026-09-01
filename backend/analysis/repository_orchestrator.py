"""
CodeSentinel — Step 6M: Repository Analysis Orchestrator

Orchestrates multi-file repository security analysis by connecting Step 6L repository
acquisition workspaces to AST parsing, RAG ingestion/retrieval, LLM context building,
Step 6H security analyzer execution, finding aggregation, and Step 6J analysis persistence.
"""

import uuid
from typing import Any, Dict, List, Optional

from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from rag.ingestion import ingest_documents
from rag.vector_store import DEFAULT_COLLECTION_NAME
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.context_ranker import rank_and_deduplicate_context
from rag.context_builder import build_security_analysis_context
from llm.analyzer import analyze_security_context
from backend.analysis.storage.store import AnalysisStore

try:
    from backend.repository.analyzer import prepare_repository_analysis_files
except ImportError:
    from repository.analyzer import prepare_repository_analysis_files


def analyze_repository(
    acquisition_id: str,
    query: Optional[str] = "security analysis",
    db_path: Optional[str] = None,
    workspace_root: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes repository-level static security analysis pipeline.

    Args:
        acquisition_id: Validated acquisition workspace identifier.
        query: Security analysis query string.
        db_path: Optional SQLite database path.
        workspace_root: Optional custom workspace root directory.

    Returns:
        Sanitized repository analysis response dictionary.

    Raises:
        ValueError: If acquisition_id is invalid or workspace missing/escaped.
    """
    clean_query = (query or "").strip()
    if not clean_query:
        clean_query = "security analysis"

    analysis_id = f"repo_ana_{uuid.uuid4().hex[:12]}"

    # 1. Prepare repository files & validate workspace boundaries
    meta, read_files, file_stats = prepare_repository_analysis_files(
        acquisition_id=acquisition_id,
        workspace_root=workspace_root
    )

    repo_info = meta["repository"]

    try:
        from backend.analysis.report_service import build_repository_report
    except ImportError:
        from analysis.report_service import build_repository_report

    # Handle Empty Repository case
    if not read_files or file_stats["analyzed_files"] == 0:
        res = {
            "status": "success",
            "analysis_id": analysis_id,
            "repository": repo_info,
            "summary": {
                "total_files": file_stats["total_files"],
                "analyzed_files": file_stats["analyzed_files"],
                "skipped_files": file_stats["skipped_files"],
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [],
            "analysis_version": "1.0"
        }
        report = build_repository_report(res)
        _safely_persist_repository_analysis(report, db_path=db_path)
        return report

    # 2. Extract AST documents across all readable source files
    all_ast_docs: List[Dict[str, Any]] = []

    for f_item in read_files:
        if f_item["skipped"] or not f_item["source_code"]:
            continue

        # Pass Python source files to AST engine
        if f_item["language"] == "python":
            try:
                ast_docs = prepare_ast_documents_for_rag(f_item["source_code"])
                all_ast_docs.extend(ast_docs)
            except Exception:
                # Malformed Python source must not crash the entire repository analysis
                pass

    # 3. Ingest AST documents into RAG vector store
    if all_ast_docs:
        try:
            ingest_documents(all_ast_docs, collection_name=DEFAULT_COLLECTION_NAME)
        except Exception:
            pass

    # 4. Execute RAG Retrieval, Ranking, and LLM Analysis
    hybrid_result = retrieve_hybrid_context(clean_query, top_k_ast=5, top_k_knowledge=5)
    ranked_result = rank_and_deduplicate_context(hybrid_result, top_k=10)
    llm_context = build_security_analysis_context(clean_query, top_k=5)
    analyzer_response = analyze_security_context(llm_context)

    raw_findings = analyzer_response.get("findings", [])

    # 5. Extract valid document IDs from context for evidence grounding
    valid_doc_ids = set()
    ctx = llm_context.get("context", {})
    if isinstance(ctx, dict):
        for sec in ("security_evidence", "code_structure", "security_knowledge"):
            for doc_item in ctx.get(sec, []):
                if isinstance(doc_item, dict) and doc_item.get("document_id"):
                    valid_doc_ids.add(str(doc_item["document_id"]))

    for doc_item in llm_context.get("context_documents", []):
        if isinstance(doc_item, dict) and doc_item.get("document_id"):
            valid_doc_ids.add(str(doc_item["document_id"]))

    # Step 6N: Normalize, Ground, Deduplicate & Aggregate Findings
    try:
        from backend.analysis.finding_normalizer import normalize_findings
        from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings
    except ImportError:
        from analysis.finding_normalizer import normalize_findings
        from analysis.finding_aggregator import aggregate_and_deduplicate_findings

    normalized_raw = normalize_findings(raw_findings, valid_document_ids=valid_doc_ids)
    agg_res = aggregate_and_deduplicate_findings(normalized_raw, file_stats=file_stats)

    res = {
        "status": "success",
        "analysis_id": analysis_id,
        "repository": repo_info,
        "summary": agg_res["summary"],
        "findings": agg_res["findings"],
        "analysis_version": "1.0"
    }

    report = build_repository_report(res)

    # 6. Persist repository analysis record into SQLite store
    _safely_persist_repository_analysis(report, db_path=db_path)

    return report


def _safely_persist_repository_analysis(res: Dict[str, Any], db_path: Optional[str] = None) -> None:
    """Safely persist repository analysis record without exposing exceptions."""
    try:
        store = AnalysisStore(db_path=db_path)
        repo_name = res.get("repository", {}).get("repository", "") if isinstance(res.get("repository"), dict) else ""
        record_payload = {
            "status": res.get("status", "completed"),
            "analysis_id": res["analysis_id"],
            "query": f"Repository Analysis: {repo_name}",
            "summary": res["summary"],
            "findings": res["findings"],
            "repository": res.get("repository"),
            "review_status": res.get("review_status", "allow")
        }
        store.save_analysis(record_payload)
    except Exception:
        pass
