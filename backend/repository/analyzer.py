"""
CodeSentinel — Step 6M: Repository Security Analyzer

Provides repository inspection, file reading, AST document collection, and file stats
summarization for acquired repository workspaces.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from backend.repository.acquirer import resolve_acquisition_metadata, _is_subpath
    from backend.repository.discovery import discover_source_files
    from backend.repository.reader import read_source_file
    from backend.analysis.scope import should_exclude_path
    from backend.analysis.incremental import process_incremental_files
except ImportError:
    from repository.acquirer import resolve_acquisition_metadata, _is_subpath
    from repository.discovery import discover_source_files
    from repository.reader import read_source_file
    from analysis.scope import should_exclude_path
    from analysis.incremental import process_incremental_files


def prepare_repository_analysis_files(
    acquisition_id: str,
    workspace_root: Optional[str] = None,
    custom_exclude_patterns: Optional[List[str]] = None,
    changed_files: Optional[List[str]] = None,
    strict_incremental: bool = False,
    max_files: Optional[int] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Validates acquisition workspace, discovers supported source files, and reads in-scope
    candidate files as static UTF-8 text using path-first filtering.

    Args:
        acquisition_id: Unique acquisition workspace identifier.
        workspace_root: Optional workspace root directory override.
        custom_exclude_patterns: Optional list of glob patterns to exclude.
        changed_files: Optional list of changed files for incremental analysis.
        strict_incremental: If True, requires valid changed_files input.
        max_files: Optional maximum number of candidate files to read/analyze.

    Returns:
        Tuple containing:
            - Acquisition metadata dictionary
            - List of read file dictionaries (with relative path, language, size_bytes, source_code, skipped, reason)
            - File statistics summary (total_files, analyzed_files, skipped_files, files_considered, files_excluded, is_incremental)

    Raises:
        ValueError: If acquisition_id is invalid, workspace missing, or path traversal detected.
    """
    meta = resolve_acquisition_metadata(acquisition_id, workspace_root=workspace_root)
    workspace_dir = Path(meta["acquisition"]["workspace"]).resolve()
    repo_dest = Path(meta["acquisition"]["repo_path"]).resolve()

    if not _is_subpath(repo_dest, workspace_dir):
        raise ValueError("Security boundary violation: Repository path escapes workspace boundary")

    if not repo_dest.exists() or not repo_dest.is_dir():
        raise ValueError(f"Repository directory does not exist or is missing: {repo_dest}")

    clean_subpath = meta["repository"].get("path", "")

    # 1. Discover supported source files enforcing repository intake limits
    discovered = discover_source_files(str(repo_dest), clean_subpath)
    discovered_count = len(discovered)

    # 2. Path-first Scope Exclusion: filter out excluded files before disk reads
    scope_candidates: List[Dict[str, Any]] = []
    excluded_count = 0

    for item in discovered:
        rel_p = item["path"]
        if should_exclude_path(rel_p, custom_exclude_patterns=custom_exclude_patterns):
            excluded_count += 1
        else:
            scope_candidates.append(item)

    # 3. Path-first Incremental Analysis Filtering
    inc_included, inc_excluded, is_incremental = process_incremental_files(
        changed_files=changed_files,
        repo_root=str(repo_dest),
        custom_exclude_patterns=custom_exclude_patterns,
        strict_incremental=strict_incremental
    )

    if is_incremental:
        inc_set = set(inc_included)
        target_candidates = [item for item in scope_candidates if item["path"] in inc_set]
    else:
        target_candidates = scope_candidates

    # 4. Path-first Policy Max Files Limit
    if max_files is not None and len(target_candidates) > max_files:
        target_candidates = target_candidates[:max_files]

    # 5. Deferred Safe File Content Reading: ONLY for selected candidate files
    read_files: List[Dict[str, Any]] = []
    analyzed_count = 0
    skipped_count = 0

    for item in target_candidates:
        rel_path = item["path"]
        read_res = read_source_file(rel_path, str(repo_dest))

        file_entry = {
            "path": rel_path,
            "language": read_res["language"],
            "size_bytes": read_res["size_bytes"],
            "skipped": read_res["skipped"],
            "reason": read_res.get("reason"),
            "source_code": read_res["source_code"]
        }

        read_files.append(file_entry)

        if read_res["skipped"]:
            skipped_count += 1
        else:
            analyzed_count += 1

    file_stats = {
        "total_files": len(read_files),
        "analyzed_files": analyzed_count,
        "skipped_files": skipped_count,
        "files_considered": discovered_count,
        "files_excluded": excluded_count,
        "is_incremental": is_incremental
    }

    return meta, read_files, file_stats
