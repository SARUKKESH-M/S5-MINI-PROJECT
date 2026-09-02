"""
CodeSentinel — Step 6T-3: Incremental & Changed-File Analysis Engine

Provides path-validated incremental analysis for trusted PR/CI changed-file lists.
Validates all paths against repository root boundaries and gracefully falls back
to full analysis when incremental input is unavailable or invalid.
"""

import os
from pathlib import Path
from typing import List, Optional, Tuple, Set

try:
    from backend.analysis.scope import normalize_and_validate_repository_path, should_exclude_path
except ImportError:
    from analysis.scope import normalize_and_validate_repository_path, should_exclude_path


def process_incremental_files(
    changed_files: Optional[List[str]],
    repo_root: str,
    custom_exclude_patterns: Optional[List[str]] = None,
    strict_incremental: bool = False
) -> Tuple[List[str], List[str], bool]:
    """
    Validates and filters changed files for incremental analysis.

    Args:
        changed_files: List of relative file paths changed in PR or CI commit.
        repo_root: Resolved absolute repository root path string.
        custom_exclude_patterns: Optional fnmatch exclusion patterns.
        strict_incremental: If True, requires valid changed_files input and forbids fallback.

    Returns:
        Tuple of (valid_included_files: List[str], excluded_files: List[str], is_incremental: bool)

    Raises:
        ValueError: If strict_incremental is True and changed_files is invalid/empty,
                    or if any path escapes repo_root.
    """
    if not isinstance(repo_root, str) or not repo_root.strip():
        raise ValueError("Repository root must be a non-empty string")

    abs_root = Path(repo_root).resolve()
    if not abs_root.exists():
        raise ValueError(f"Repository root does not exist: {repo_root}")

    # Fallback to full analysis if changed_files is missing/empty and strict_incremental is False
    if changed_files is None or not isinstance(changed_files, list) or len(changed_files) == 0:
        if strict_incremental:
            raise ValueError("Strict incremental mode requested but changed_files list is empty or missing")
        return [], [], False

    included: Set[str] = set()
    excluded: Set[str] = set()

    for item in changed_files:
        if not item or not isinstance(item, str) or not item.strip():
            continue

        clean_item = item.strip().replace("\\", "/").strip("/")

        # Validate path against repository root
        target_path = normalize_and_validate_repository_path(clean_item, repo_root)

        # Check exclusion rules
        if should_exclude_path(clean_item, custom_exclude_patterns=custom_exclude_patterns):
            excluded.add(clean_item)
        else:
            if target_path.is_file():
                included.add(clean_item)

    if not included and strict_incremental:
        raise ValueError("Strict incremental mode requested but zero valid target files remained after validation")

    is_incremental = len(included) > 0
    return sorted(list(included)), sorted(list(excluded)), is_incremental
