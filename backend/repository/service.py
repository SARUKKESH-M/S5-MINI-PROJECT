"""
CodeSentinel — Step 6K: Local Repository Intake Service

Orchestrates input validation, directory traversal, file discovery, size limit enforcement,
and safe source code reading for local repository checkouts.
"""

import os
from typing import Any, Dict, List
from repository.validator import validate_github_url, validate_branch, validate_repo_path
from repository.discovery import discover_source_files
from repository.reader import read_source_file
from repository.models import create_repository_metadata


def prepare_repository_for_analysis(
    repository_path: str,
    repository_url: str,
    branch: str = "main",
    path: str = ""
) -> Dict[str, Any]:
    """
    Validates repository reference and processes local repository intake.

    Returns internal dictionary containing repository metadata and source files for pipeline consumption.
    """
    if not isinstance(repository_path, str) or not repository_path.strip():
        raise ValueError("repository_path must be a non-empty string")

    abs_repo_path = os.path.abspath(repository_path.strip())
    if not os.path.exists(abs_repo_path) or not os.path.isdir(abs_repo_path):
        raise ValueError(f"Local repository path does not exist or is not a directory: {repository_path}")

    # Validate inputs
    url_info = validate_github_url(repository_url)
    clean_branch = validate_branch(branch)
    clean_subpath = validate_repo_path(path)

    owner = url_info["owner"]
    repo_name = url_info["repository"]

    # Discover supported source files
    discovered = discover_source_files(abs_repo_path, clean_subpath)

    files_internal: List[Dict[str, Any]] = []
    files_summary: List[Dict[str, Any]] = []
    total_bytes = 0
    extensions_set = set()

    for item in discovered:
        rel_path = item["path"]
        ext = item["extension"]
        extensions_set.add(ext)

        read_res = read_source_file(rel_path, abs_repo_path)
        
        file_entry = {
            "path": rel_path,
            "language": read_res["language"],
            "size_bytes": read_res["size_bytes"],
            "skipped": read_res["skipped"],
            "reason": read_res.get("reason"),
            "source_code": read_res["source_code"]
        }
        files_internal.append(file_entry)

        files_summary.append({
            "path": rel_path,
            "language": read_res["language"],
            "size_bytes": read_res["size_bytes"]
        })

        total_bytes += read_res["size_bytes"]

    # Public metadata dictionary
    public_metadata = create_repository_metadata(
        owner=owner,
        repository=repo_name,
        branch=clean_branch,
        path=clean_subpath,
        source_file_count=len(files_internal),
        source_extensions=sorted(list(extensions_set)),
        total_source_bytes=total_bytes,
        files_summary=files_summary
    )

    return {
        "status": "success",
        "repository": public_metadata["repository"],
        "file_count": len(files_internal),
        "source_extensions": public_metadata["source_extensions"],
        "total_source_bytes": total_bytes,
        "files_internal": files_internal,
        "public_metadata": public_metadata
    }
