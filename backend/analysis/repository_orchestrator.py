"""
CodeSentinel — Step 6M & 6T: Repository Analysis Orchestrator

Orchestrates multi-file repository security analysis by connecting Step 6L repository
acquisition workspaces to AST parsing, RAG ingestion/retrieval, LLM context building,
Step 6H security analyzer execution, finding aggregation, Step 6J analysis persistence,
and Step 6T platform capabilities (Policy profiles, Scope exclusion, Incremental analysis, Cache, Metrics).
"""

import time
import uuid
from typing import Any, Dict, List, Optional

from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from ast_engine.evidence_normalizer import normalize_security_evidence
from rag.ingestion import ingest_documents
from rag.vector_store import DEFAULT_COLLECTION_NAME
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
    enable_cache: bool = True
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

    # 1. Prepare repository files & validate workspace boundaries
    meta, raw_read_files, raw_file_stats = prepare_repository_analysis_files(
        acquisition_id=acquisition_id,
        workspace_root=workspace_root
    )

    repo_info = meta["repository"]
    repo_dest_path = str(meta["acquisition"]["repo_path"])

    # 2. Apply Scope Exclusion Rules
    scope_included_files: List[Dict[str, Any]] = []
    excluded_count = 0

    for f_item in raw_read_files:
        rel_p = f_item["path"]
        if should_exclude_path(rel_p, custom_exclude_patterns=custom_exclude_patterns):
            excluded_count += 1
        else:
            scope_included_files.append(f_item)

    # 3. Apply Incremental Analysis Filtering
    inc_included, inc_excluded, is_incremental = process_incremental_files(
        changed_files=changed_files,
        repo_root=repo_dest_path,
        custom_exclude_patterns=custom_exclude_patterns,
        strict_incremental=strict_incremental
    )

    if is_incremental:
        inc_set = set(inc_included)
        final_files = [f for f in scope_included_files if f["path"] in inc_set]
    else:
        final_files = scope_included_files

    # Enforce policy max_files limit
    if len(final_files) > policy.max_files:
        final_files = final_files[:policy.max_files]

    analyzed_count = sum(1 for f in final_files if not f["skipped"] and f["source_code"])
    skipped_count = len(final_files) - analyzed_count

    file_stats = {
        "total_files": len(final_files),
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

    # 5. Clear stale AST evidence & Ingest fresh repository AST documents into RAG vector store
    try:
        from rag.vector_store import initialize_vector_store
        v_client = initialize_vector_store()
        try:
            v_client.delete_collection(DEFAULT_COLLECTION_NAME)
        except Exception:
            pass
    except Exception:
        pass

    if all_ast_docs:
        try:
            ingest_documents(all_ast_docs, collection_name=DEFAULT_COLLECTION_NAME)
        except Exception:
            pass

    # 6. Deterministic findings precede optional per-category RAG enrichment.
    raw_findings = generate_deterministic_findings(all_security_evidence)
    enriched_findings = enrich_findings(raw_findings, db_path=db_path)
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
        files_considered=raw_file_stats["total_files"],
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
