"""
CodeSentinel — Step 6M & 6T: Repository Analysis Orchestrator

Orchestrates multi-file repository security analysis by connecting Step 6L repository
acquisition workspaces to AST parsing, RAG ingestion/retrieval, LLM context building,
Step 6H security analyzer execution, finding aggregation, Step 6J analysis persistence,
and Step 6T platform capabilities (Policy profiles, Scope exclusion, Incremental analysis, Cache, Metrics).
"""

import gc
import time
import uuid
from typing import Any, Dict, List, Optional

from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from ast_engine.evidence_normalizer import normalize_security_evidence
from rag.ingestion import ingest_documents
from rag.vector_store import (
    DEFAULT_COLLECTION_NAME,
    generate_transient_ast_collection_name,
    delete_transient_collection,
)
try:
    from rag.context_builder import MAX_CONTEXT_DOCUMENTS
except ImportError:
    MAX_CONTEXT_DOCUMENTS = 20
from backend.analysis.storage.store import AnalysisStore
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.finding_enrichment import enrich_findings

try:
    from backend.repository.analyzer import prepare_repository_analysis_files
    from backend.analysis.policy import get_policy_profile
    from backend.analysis.scope import should_exclude_path
    from backend.analysis.incremental import process_incremental_files
    from backend.analysis.cache import analysis_cache
    from backend.analysis.metadata import build_analysis_traceability_metadata
    from backend.app.core.metrics import metrics_collector
except ImportError:
    from repository.analyzer import prepare_repository_analysis_files
    from analysis.policy import get_policy_profile
    from analysis.scope import should_exclude_path
    from analysis.incremental import process_incremental_files
    from analysis.cache import analysis_cache
    from analysis.metadata import build_analysis_traceability_metadata
    from app.core.metrics import metrics_collector


def analyze_repository(
    acquisition_id: str,
    query: Optional[str] = "security analysis",
    db_path: Optional[str] = None,
    workspace_root: Optional[str] = None,
    policy_name: Optional[str] = "default",
    changed_files: Optional[List[str]] = None,
    custom_exclude_patterns: Optional[List[str]] = None,
    strict_incremental: bool = False,
    enable_cache: bool = True,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes repository-level static security analysis pipeline with 6T platform capabilities.

    Args:
        acquisition_id: Validated acquisition workspace identifier.
        query: Security analysis query string.
        db_path: Optional SQLite database path.
        workspace_root: Optional custom workspace root directory.
        policy_name: Name of analysis policy profile ('default', 'strict', 'ci', 'developer').
        changed_files: Optional list of changed files for incremental analysis.
        custom_exclude_patterns: Optional list of glob patterns to exclude from analysis.
        strict_incremental: If True, requires valid changed_files input.
        enable_cache: If True, uses deterministic analysis caching.

    Returns:
        Sanitized repository analysis response dictionary.

    Raises:
        ValueError: If acquisition_id is invalid or workspace missing/escaped.
    """
    start_time = time.time()
    metrics_collector.increment("analysis_requests_total")

    # Load & validate analysis policy profile
    policy = get_policy_profile(policy_name)

    clean_query = (query or "").strip()
    if not clean_query:
        clean_query = "security analysis"

    analysis_id = f"repo_ana_{uuid.uuid4().hex[:12]}"

    # 1. Prepare repository files with path-first filtering & validate workspace boundaries
    meta, final_files, raw_file_stats = prepare_repository_analysis_files(
        acquisition_id=acquisition_id,
        workspace_root=workspace_root,
        custom_exclude_patterns=custom_exclude_patterns,
        changed_files=changed_files,
        strict_incremental=strict_incremental,
        max_files=policy.max_files,
    )

    repo_info = meta["repository"]
    repo_dest_path = str(meta["acquisition"]["repo_path"])
    is_incremental = raw_file_stats.get("is_incremental", False)
    excluded_count = raw_file_stats.get("files_excluded", 0)
    analyzed_count = raw_file_stats.get("analyzed_files", 0)
    skipped_count = raw_file_stats.get("skipped_files", 0)

    file_stats = {
        "total_files": raw_file_stats.get("total_files", len(final_files)),
        "analyzed_files": analyzed_count,
        "skipped_files": skipped_count
    }

    try:
        from backend.analysis.report_service import build_repository_report
    except ImportError:
        from analysis.report_service import build_repository_report

    # Handle Empty Repository case
    if not final_files or analyzed_count == 0:
        duration_ms = (time.time() - start_time) * 1000.0
        metrics_collector.record_duration(duration_ms)
        metrics_collector.increment("analysis_success_total")
        metrics_collector.record_decision("ALLOW")

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

    # 4. Extract AST documents across readable source files & apply Caching
    all_ast_docs: List[Dict[str, Any]] = []
    all_security_evidence: List[Dict[str, Any]] = []
    cache_hits = 0
    cache_misses = 0

    for f_item in final_files:
        if f_item["skipped"] or not f_item["source_code"]:
            continue

        src = f_item["source_code"]
        path_str = f_item["path"]

        try:
            # Cache check
            if enable_cache:
                content_hash = analysis_cache.compute_file_hash(src)
                cache_key = analysis_cache.generate_cache_key(path_str, content_hash, policy.name)
                cached_ast = analysis_cache.get(cache_key)
                if cached_ast and "ast_docs" in cached_ast and "security_evidence" in cached_ast:
                    all_ast_docs.extend(cached_ast["ast_docs"])
                    all_security_evidence.extend(cached_ast["security_evidence"])
                    cache_hits += 1
                    metrics_collector.increment("cache_hits_total")
                    continue
                else:
                    cache_misses += 1
                    metrics_collector.increment("cache_misses_total")

            # Pass Python source files to AST engine
            if f_item["language"] == "python":
                try:
                    normalized_evidence = normalize_security_evidence(src, file_path=path_str)
                    security_evidence = normalized_evidence.get("security_evidence", [])
                    ast_docs = prepare_ast_documents_for_rag(src, file_path=path_str, normalized_evidence=normalized_evidence)
                    all_ast_docs.extend(ast_docs)
                    all_security_evidence.extend(security_evidence)

                    if enable_cache:
                        content_hash = analysis_cache.compute_file_hash(src)
                        cache_key = analysis_cache.generate_cache_key(path_str, content_hash, policy.name)
                        analysis_cache.set(cache_key, {"file_path": path_str, "ast_docs": ast_docs, "security_evidence": security_evidence})
                except Exception:
                    # Malformed Python source must not crash the entire repository analysis
                    pass
            elif f_item["language"] == "javascript":
                try:
                    # Process JavaScript via Tree-Sitter structural analyzer
                    from ast_engine.structural_analyzer import analyze_javascript_structure
                    analyze_javascript_structure(src)

                    # Process JavaScript via Tree-Sitter security analyzer
                    from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
                    sec_data = analyze_javascript_security_structure(src, file_path=path_str)
                    js_security_evidence = sec_data.get("security_signals", [])
                    all_security_evidence.extend(js_security_evidence)
                except Exception:
                    # Malformed JavaScript source must not crash the entire repository analysis
                    pass
        finally:
            # Mandatory requirement 6: release source_code immediately on cache hits, parse success, and exceptions
            f_item["source_code"] = None

    # 5. Generate deterministic findings from all extracted AST security evidence FIRST
    # Deterministic AST rules are strictly authoritative; RAG and LLM operate advisory only.
    raw_findings = generate_deterministic_findings(all_security_evidence)

    # Explicitly release final_files collection when no longer needed
    del final_files
    gc.collect()

    # 6. Filter transient repository AST documents to only evidence-associated documents
    actionable_evidence_ids = {
        str(f.get("evidence_id")) for f in raw_findings if f.get("evidence_id")
    }

    filtered_ast_docs: List[Dict[str, Any]] = [
        doc for doc in all_ast_docs
        if str(doc.get("metadata", {}).get("evidence_id", "")) in actionable_evidence_ids
    ]

    # Bounded transient RAG safety cap: aligned with MAX_CONTEXT_DOCUMENTS (20).
    # Governs advisory RAG vector enrichment context only; deterministic findings remain 100% authoritative and uncapped.
    if len(filtered_ast_docs) > MAX_CONTEXT_DOCUMENTS:
        filtered_ast_docs = filtered_ast_docs[:MAX_CONTEXT_DOCUMENTS]

    # Explicitly release full AST documents list
    del all_ast_docs
    gc.collect()

    # 7. Generate isolated transient AST collection name for this analysis run
    transient_ast_collection = generate_transient_ast_collection_name(analysis_id)

    try:
        # Ingest only relevant AST documents into transient RAG collection
        if filtered_ast_docs:
            try:
                ingest_documents(filtered_ast_docs, collection_name=transient_ast_collection, db_path=db_path)
            except Exception:
                pass

        # Explicitly release filtered AST documents once ingested
        del filtered_ast_docs
        gc.collect()

        # 8. Enrich deterministic findings (Curated OWASP + RAG context + LLM explanation)
        enriched_findings = enrich_findings(
            raw_findings,
            db_path=db_path,
            ast_collection_name=transient_ast_collection,
        )
        valid_doc_ids = {str(item.get("evidence_id")) for item in all_security_evidence if item.get("evidence_id")}

        # Step 6N: Normalize, Ground, Deduplicate & Aggregate Findings
        try:
            from backend.analysis.finding_normalizer import normalize_findings
            from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings
        except ImportError:
            from analysis.finding_normalizer import normalize_findings
            from analysis.finding_aggregator import aggregate_and_deduplicate_findings

        normalized_raw = normalize_findings(enriched_findings, valid_document_ids=valid_doc_ids)
        agg_res = aggregate_and_deduplicate_findings(normalized_raw, file_stats=file_stats)

        duration_ms = (time.time() - start_time) * 1000.0
        metrics_collector.record_duration(duration_ms)
        metrics_collector.increment("analysis_success_total")

        # Build internal traceability metadata
        trace_meta = build_analysis_traceability_metadata(
            policy_name=policy.name,
            is_incremental=is_incremental,
            files_considered=raw_file_stats.get("files_considered", raw_file_stats.get("total_files", 0)),
            files_analyzed=analyzed_count,
            files_excluded=excluded_count,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            duration_ms=duration_ms
        )

        res = {
            "status": "success",
            "analysis_id": analysis_id,
            "repository": repo_info,
            "summary": agg_res["summary"],
            "findings": agg_res["findings"],
            "analysis_version": "1.0"
        }

        report = build_repository_report(res)

        # Attach internal traceability metadata to report dictionary (does not break Step 6O contract)
        report["traceability"] = trace_meta

        metrics_collector.record_decision(report.get("review_status", "allow"))

        # 8. Persist repository analysis record into SQLite store
        _safely_persist_repository_analysis(report, db_path=db_path, user_id=user_id)

        return report
    finally:
        # Guarantee transient collection cleanup under all conditions
        delete_transient_collection(transient_ast_collection, db_path=db_path)


def _safely_persist_repository_analysis(
    res: Dict[str, Any],
    db_path: Optional[str] = None,
    user_id: Optional[str] = None,
) -> None:
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
            "review_status": res.get("review_status", "allow"),
            "user_id": user_id,
        }
        store.save_analysis(record_payload)
    except Exception:
        pass
