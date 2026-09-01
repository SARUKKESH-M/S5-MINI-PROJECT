"""
CodeSentinel — Step 6K: Repository Data Models & Helpers

Provides deterministic data structures and sanitization functions for repository
intake requests and metadata responses. Public API models strictly omit raw source code.
"""

from typing import Any, Dict, List, Optional


def create_repository_request(
    repository_url: str,
    branch: str = "main",
    path: str = ""
) -> Dict[str, str]:
    """
    Creates a normalized repository request object.

    Raises ValueError if input parameters are invalid or contain non-string values.
    """
    if not isinstance(repository_url, str):
        raise ValueError("repository_url must be a string")
    if not isinstance(branch, str):
        raise ValueError("branch must be a string")
    if not isinstance(path, str):
        raise ValueError("path must be a string")

    clean_url = repository_url.strip()
    clean_branch = branch.strip() if branch and branch.strip() else "main"
    clean_path = path.strip()

    if not clean_url:
        raise ValueError("repository_url cannot be empty")

    return {
        "repository_url": clean_url,
        "branch": clean_branch,
        "path": clean_path
    }


def create_repository_metadata(
    owner: str,
    repository: str,
    branch: str,
    path: str,
    source_file_count: int,
    source_extensions: List[str],
    total_source_bytes: int,
    files_summary: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Creates a safe public repository metadata structure.
    Strictly excludes raw source code fields (source_code, raw_source, etc.).
    """
    clean_files = []
    if files_summary:
        for item in files_summary:
            clean_files.append({
                "path": str(item.get("path", "")),
                "language": str(item.get("language", "unknown")),
                "size_bytes": int(item.get("size_bytes", 0))
            })

    # Sort files deterministically by relative path
    clean_files.sort(key=lambda x: x["path"])

    # Sort extensions deterministically
    sorted_extensions = sorted(list(set(source_extensions)))

    return {
        "status": "success",
        "repository": {
            "owner": str(owner),
            "repository": str(repository),
            "branch": str(branch),
            "path": str(path)
        },
        "file_count": int(source_file_count),
        "source_extensions": sorted_extensions,
        "total_source_bytes": int(total_source_bytes),
        "files": clean_files
    }
