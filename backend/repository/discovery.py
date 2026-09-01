"""
CodeSentinel — Step 6K: Source File Discovery & Extension Manager

Recursively discovers supported source code files within a local repository directory,
enforces exclusion sets, language mapping, file count limits (500), and total size limits (25MB).
"""

import os
from typing import Any, Dict, List, Optional, Set


SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c_cpp",
    ".h": "c_cpp",
    ".cpp": "c_cpp",
    ".hpp": "c_cpp",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby"
}

EXCLUDED_DIRECTORIES: Set[str] = {
    ".git",
    ".github",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    "target",
    "coverage",
    ".idea",
    ".vscode"
}

MAX_SOURCE_FILES: int = 500
MAX_TOTAL_SOURCE_BYTES: int = 25_000_000  # 25 MB


def get_language_for_extension(ext: str) -> Optional[str]:
    """Returns normalized language identifier for a file extension, or None if unsupported."""
    if not ext:
        return None
    return SUPPORTED_EXTENSIONS.get(ext.lower())


def discover_source_files(root_path: str, subpath: str = "") -> List[Dict[str, Any]]:
    """
    Recursively discovers supported source files in root_path / subpath.

    Raises ValueError if repository directory is invalid, escapes boundary, or exceeds limit thresholds.
    """
    if not os.path.exists(root_path) or not os.path.isdir(root_path):
        raise ValueError(f"Repository root directory does not exist: {root_path}")

    abs_root = os.path.abspath(root_path)

    if subpath:
        target_dir = os.path.abspath(os.path.join(abs_root, subpath))
    else:
        target_dir = abs_root

    # Path traversal check: verify target_dir is inside abs_root
    if not target_dir.startswith(abs_root):
        raise ValueError("Subpath escapes repository boundary")

    if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
        raise ValueError(f"Repository subpath directory does not exist: {subpath}")

    discovered_files: List[Dict[str, Any]] = []
    total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(target_dir):
        # Filter excluded directories in-place
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRECTORIES and not d.startswith(".git")]

        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                full_file_path = os.path.join(dirpath, filename)
                try:
                    size_bytes = os.path.getsize(full_file_path)
                except OSError:
                    continue

                rel_path = os.path.relpath(full_file_path, abs_root).replace("\\", "/")
                lang = SUPPORTED_EXTENSIONS[ext]

                discovered_files.append({
                    "path": rel_path,
                    "abs_path": full_file_path,
                    "language": lang,
                    "extension": ext,
                    "size_bytes": size_bytes
                })

                total_bytes += size_bytes

                if len(discovered_files) > MAX_SOURCE_FILES:
                    raise ValueError(
                        f"Repository exceeds maximum allowed source file count ({MAX_SOURCE_FILES} files)"
                    )

                if total_bytes > MAX_TOTAL_SOURCE_BYTES:
                    raise ValueError(
                        f"Repository exceeds maximum allowed total source content size ({MAX_TOTAL_SOURCE_BYTES} bytes)"
                    )

    # Sort deterministically by relative path
    discovered_files.sort(key=lambda x: x["path"])

    return discovered_files
