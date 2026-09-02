"""
CodeSentinel — Step 6T-2: Scope Controls & Path Exclusion Engine

Provides safe repository scope boundaries and path exclusion rules.
Prevents directory traversal, root escapes, and symlink escapes while preserving
static non-execution guarantees.
"""

import fnmatch
import os
from pathlib import Path
from typing import List, Optional, Set

DEFAULT_EXCLUDED_DIRECTORIES: Set[str] = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    ".env",
    ".ds_store",
    "coverage",
    ".idea",
    ".vscode",
}

DEFAULT_EXCLUDED_PATTERNS: List[str] = [
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dll",
    "*.exe",
    "*.dylib",
    "*.min.js",
    "*.min.css",
    "*.map",
]


def normalize_and_validate_repository_path(rel_path: str, repo_root: str) -> Path:
    """
    Normalizes a relative path and verifies it strictly resides within the repository root directory.

    Args:
        rel_path: Relative file or directory path string.
        repo_root: Resolved absolute repository root directory path.

    Returns:
        Resolved absolute Path object inside repo_root.

    Raises:
        ValueError: If rel_path escapes repo_root via path traversal ('..') or symlink escape.
    """
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise ValueError("Path must be a non-empty string")

    if not isinstance(repo_root, str) or not repo_root.strip():
        raise ValueError("Repository root must be a non-empty string")

    # Check for raw path traversal markers
    clean_rel = rel_path.strip().replace("\\", "/")

    abs_root = Path(repo_root).resolve()
    if not abs_root.exists():
        raise ValueError(f"Repository root does not exist: {repo_root}")

    target_path = (abs_root / clean_rel).resolve()

    # Verify target_path is relative to abs_root (no root escape)
    try:
        target_path.relative_to(abs_root)
    except ValueError:
        raise ValueError(f"Path traversal or repository root escape attempt detected: '{rel_path}'")

    return target_path


def should_exclude_path(
    rel_path: str,
    custom_exclude_patterns: Optional[List[str]] = None
) -> bool:
    """
    Determines whether a relative file path should be excluded from analysis.

    Args:
        rel_path: Relative path string.
        custom_exclude_patterns: Optional list of fnmatch exclude glob patterns.

    Returns:
        True if path matches exclusion rules, False otherwise.
    """
    if not isinstance(rel_path, str) or not rel_path.strip():
        return False

    clean_path = rel_path.strip().replace("\\", "/").strip("/")
    parts = [p.lower() for p in clean_path.split("/") if p]

    # Check directory components against default excluded directories
    for part in parts:
        if part in DEFAULT_EXCLUDED_DIRECTORIES:
            return True

    file_name = parts[-1] if parts else clean_path.lower()

    # Check filename against default glob patterns
    for pattern in DEFAULT_EXCLUDED_PATTERNS:
        if fnmatch.fnmatch(file_name, pattern):
            return True

    # Check custom glob patterns if provided
    if custom_exclude_patterns:
        for pattern in custom_exclude_patterns:
            if not pattern or not isinstance(pattern, str):
                continue
            clean_pattern = pattern.strip()
            if fnmatch.fnmatch(clean_path, clean_pattern) or fnmatch.fnmatch(file_name, clean_pattern):
                return True

    return False
