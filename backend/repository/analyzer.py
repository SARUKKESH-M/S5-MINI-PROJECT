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
except ImportError:
    from repository.acquirer import resolve_acquisition_metadata, _is_subpath
    from repository.discovery import discover_source_files
    from repository.reader import read_source_file


def prepare_repository_analysis_files(
    acquisition_id: str,
    workspace_root: Optional[str] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, int]]:
    """
    Validates acquisition workspace, discovers supported source files, and reads them as static UTF-8 text.

    Args:
        acquisition_id: Unique acquisition workspace identifier.
        workspace_root: Optional workspace root directory override.

    Returns:
        Tuple containing:
            - Acquisition metadata dictionary
            - List of read file dictionaries (with relative path, language, size_bytes, source_code, skipped, reason)
            - File statistics summary (total_files, analyzed_files, skipped_files)

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

    # Discover supported source files
    discovered = discover_source_files(str(repo_dest), clean_subpath)

    read_files: List[Dict[str, Any]] = []
    analyzed_count = 0
    skipped_count = 0

    for item in discovered:
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
        "total_files": len(discovered),
        "analyzed_files": analyzed_count,
        "skipped_files": skipped_count
    }

    return meta, read_files, file_stats
