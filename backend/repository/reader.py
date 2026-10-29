"""
CodeSentinel — Step 6K: Safe Source Reader & Binary Detector

Reads source code files as UTF-8 static text while protecting against path traversal,
individual file size limits (1MB), and binary file content. Target source code is
never imported, evaluated, or executed.
"""

import os
import stat
from typing import Any, Dict, Optional
from repository.discovery import get_language_for_extension


MAX_FILE_SIZE: int = 1_000_000  # 1 MB
_TEXT_BYTES: bytes = bytes(range(32, 127)) + b"\t\n\r"


def is_binary_content(chunk: bytes) -> bool:
    """
    Performs a lightweight binary check on an initial byte chunk.
    Returns True if null bytes or excessive non-printable bytes are found.
    """
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    return (len(chunk.translate(None, _TEXT_BYTES)) / len(chunk)) > 0.30


def read_source_file(
    file_rel_path: str,
    repository_root: str,
    abs_root_cached: Optional[str] = None,
    known_abs_path: Optional[str] = None,
    known_lang: Optional[str] = None,
    is_regular: bool = False,
) -> Dict[str, Any]:
    """
    Safely reads a repository source file as static text.

    Raises ValueError if path escapes repository root boundary or file is inaccessible.
    Returns metadata dictionary with source_code or skipped status.
    """
    abs_root = abs_root_cached or os.path.abspath(repository_root)
    full_path = known_abs_path or os.path.abspath(os.path.join(abs_root, file_rel_path))

    # Path traversal protection
    if not full_path.startswith(abs_root):
        raise ValueError(f"File path escapes repository boundary: {file_rel_path}")

    language = known_lang or get_language_for_extension(os.path.splitext(full_path)[1].lower()) or "unknown"

    # Open descriptor directly to avoid redundant stat calls and eliminate TOCTOU races
    try:
        f = open(full_path, "rb")
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as exc:
        raise ValueError(f"Source file not found: {file_rel_path}") from exc

    with f:
        if not is_regular:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"Source file not found: {file_rel_path}")
            size_bytes = st.st_size
            if size_bytes > MAX_FILE_SIZE:
                return {
                    "path": file_rel_path.replace("\\", "/"),
                    "language": language,
                    "size_bytes": size_bytes,
                    "skipped": True,
                    "reason": "exceeds MAX_FILE_SIZE",
                    "source_code": ""
                }

        raw_bytes = f.read(MAX_FILE_SIZE + 1)
        size_bytes = len(raw_bytes)

        # Individual file size limit check
        if size_bytes > MAX_FILE_SIZE:
            return {
                "path": file_rel_path.replace("\\", "/"),
                "language": language,
                "size_bytes": size_bytes,
                "skipped": True,
                "reason": "exceeds MAX_FILE_SIZE",
                "source_code": ""
            }

        # Binary check and text reading
        initial_chunk = raw_bytes[:4096]
        if is_binary_content(initial_chunk):
            return {
                "path": file_rel_path.replace("\\", "/"),
                "language": language,
                "size_bytes": size_bytes,
                "skipped": True,
                "reason": "binary_content",
                "source_code": ""
            }

    try:
        content = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        content = raw_bytes.decode("latin-1", errors="replace")

    return {
        "path": file_rel_path.replace("\\", "/"),
        "language": language,
        "size_bytes": size_bytes,
        "skipped": False,
        "reason": None,
        "source_code": content
    }
