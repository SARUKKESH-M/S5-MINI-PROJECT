"""
CodeSentinel — Step 6K: Safe Source Reader & Binary Detector

Reads source code files as UTF-8 static text while protecting against path traversal,
individual file size limits (1MB), and binary file content. Target source code is
never imported, evaluated, or executed.
"""

import os
from typing import Any, Dict
from repository.discovery import get_language_for_extension


MAX_FILE_SIZE: int = 1_000_000  # 1 MB


def is_binary_content(chunk: bytes) -> bool:
    """
    Performs a lightweight binary check on an initial byte chunk.
    Returns True if null bytes or excessive non-printable bytes are found.
    """
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    # Count non-ASCII control characters (excluding tab, LF, CR)
    text_characters = bytes(range(32, 127)) + b"\t\n\r"
    non_text = sum(1 for byte in chunk if byte not in text_characters)
    return (non_text / len(chunk)) > 0.30


def read_source_file(file_rel_path: str, repository_root: str) -> Dict[str, Any]:
    """
    Safely reads a repository source file as static text.

    Raises ValueError if path escapes repository root boundary or file is inaccessible.
    Returns metadata dictionary with source_code or skipped status.
    """
    abs_root = os.path.abspath(repository_root)
    full_path = os.path.abspath(os.path.join(abs_root, file_rel_path))

    # Path traversal protection
    if not full_path.startswith(abs_root):
        raise ValueError(f"File path escapes repository boundary: {file_rel_path}")

    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        raise ValueError(f"Source file not found: {file_rel_path}")

    ext = os.path.splitext(full_path)[1].lower()
    language = get_language_for_extension(ext) or "unknown"

    size_bytes = os.path.getsize(full_path)

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
    with open(full_path, "rb") as f:
        initial_chunk = f.read(4096)
        if is_binary_content(initial_chunk):
            return {
                "path": file_rel_path.replace("\\", "/"),
                "language": language,
                "size_bytes": size_bytes,
                "skipped": True,
                "reason": "binary_content",
                "source_code": ""
            }
        
        remaining_chunk = f.read()
        full_raw_bytes = initial_chunk + remaining_chunk

    try:
        content = full_raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        content = full_raw_bytes.decode("latin-1", errors="replace")

    return {
        "path": file_rel_path.replace("\\", "/"),
        "language": language,
        "size_bytes": size_bytes,
        "skipped": False,
        "source_code": content
    }
