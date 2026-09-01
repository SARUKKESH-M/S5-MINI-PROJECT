"""
CodeSentinel — Step 6L: Repository Acquisition Foundation

Implements a secure repository acquisition layer that takes a validated GitHub HTTPS
repository reference and prepares a controlled local repository workspace.
"""

import os
import shutil
import uuid
import tempfile
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from backend.repository.validator import (
        validate_github_url,
        validate_branch,
        validate_repo_path
    )
    from backend.repository.discovery import (
        discover_source_files,
        MAX_SOURCE_FILES,
        MAX_TOTAL_SOURCE_BYTES
    )
except ImportError:
    from repository.validator import (
        validate_github_url,
        validate_branch,
        validate_repo_path
    )
    from repository.discovery import (
        discover_source_files,
        MAX_SOURCE_FILES,
        MAX_TOTAL_SOURCE_BYTES
    )


# Acquisition Constants
MAX_ACQUISITION_TIMEOUT_SECONDS: int = 30
MAX_REPOSITORY_SIZE_BYTES: int = MAX_TOTAL_SOURCE_BYTES  # 25 MB
MAX_ACQUISITION_FILES: int = MAX_SOURCE_FILES  # 500 files
ACQUISITION_SCHEMA_VERSION: str = "1.0"


def get_default_workspace_root() -> Path:
    """Returns the base directory where isolated repository workspaces are managed."""
    base_dir = Path(tempfile.gettempdir()) / "codesentinel_workspaces"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir.resolve()


def _is_subpath(path: Path, parent: Path) -> bool:
    """Verifies that path is strictly contained within parent directory."""
    try:
        path_resolved = path.resolve()
        parent_resolved = parent.resolve()
        return path_resolved == parent_resolved or parent_resolved in path_resolved.parents
    except Exception:
        return False


def acquire_repository(
    repository_url: str,
    branch: str = "main",
    path: str = "",
    local_path: Optional[str] = None,
    workspace_root: Optional[str] = None
) -> Dict[str, Any]:
    """
    Acquires a GitHub repository into an isolated local workspace directory.

    Args:
        repository_url: Validated GitHub HTTPS URL.
        branch: Target Git branch name.
        path: Target relative subpath inside repository.
        local_path: Optional local directory path (for testing or pre-cloned source).
        workspace_root: Optional custom workspace root directory.

    Returns:
        Structured acquisition metadata dictionary. Strictly omits source code content.

    Raises:
        ValueError: If input validation fails, limits are exceeded, or path traversal detected.
        RuntimeError: If Git execution or workspace setup fails.
    """
    # 1. Validate inputs using Step 6K validator logic
    url_info = validate_github_url(repository_url)
    clean_branch = validate_branch(branch)
    clean_subpath = validate_repo_path(path)

    owner = url_info["owner"]
    repo_name = url_info["repository"]
    normalized_url = url_info["normalized_url"]

    # 2. Setup isolated workspace directory
    base_root = Path(workspace_root).resolve() if workspace_root else get_default_workspace_root()
    base_root.mkdir(parents=True, exist_ok=True)

    acquisition_id = f"acq_{uuid.uuid4().hex[:12]}"
    workspace_dir = (base_root / acquisition_id).resolve()

    # Verify workspace directory is inside base_root to prevent traversal
    if not _is_subpath(workspace_dir, base_root):
        raise ValueError("Path traversal error: Workspace directory escapes workspace root")

    workspace_dir.mkdir(parents=True, exist_ok=True)
    repo_dest = (workspace_dir / repo_name).resolve()

    # Double check repository destination path containment
    if not _is_subpath(repo_dest, workspace_dir):
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise ValueError("Path traversal error: Repository destination escapes workspace boundary")

    method = "git"

    try:
        if local_path:
            method = "local"
            abs_local = Path(local_path).resolve()
            if not abs_local.exists() or not abs_local.is_dir():
                raise ValueError(f"Local repository path does not exist or is not a directory: {local_path}")
            
            # Copy contents securely into destination directory
            shutil.copytree(abs_local, repo_dest, dirs_exist_ok=True)
        else:
            # Check git availability
            git_bin = shutil.which("git")
            if not git_bin:
                raise RuntimeError("Git executable is not installed or available on PATH")

            # Execute git clone securely using argument list (no shell=True)
            cmd = [
                git_bin,
                "clone",
                "--depth", "1",
                "--branch", clean_branch,
                normalized_url,
                str(repo_dest)
            ]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=MAX_ACQUISITION_TIMEOUT_SECONDS
                )
            except subprocess.TimeoutExpired as te:
                raise RuntimeError(f"Repository acquisition timed out after {MAX_ACQUISITION_TIMEOUT_SECONDS}s") from te
            except subprocess.CalledProcessError as cpe:
                # Sanitize error output to prevent credential/path leak
                clean_err = "Git acquisition failed"
                if "Remote branch" in cpe.stderr or "not found" in cpe.stderr:
                    clean_err = f"Requested branch '{clean_branch}' or repository not found"
                raise RuntimeError(clean_err) from cpe

        # 3. Verify resulting repository directory and enforce limits
        if not repo_dest.exists() or not repo_dest.is_dir():
            raise RuntimeError("Repository acquisition resulted in invalid workspace directory")

        # Discover source files and enforce limits
        discovered = discover_source_files(str(repo_dest), clean_subpath)

        if len(discovered) > MAX_ACQUISITION_FILES:
            raise ValueError(
                f"Acquired repository contains {len(discovered)} files, exceeding limit of {MAX_ACQUISITION_FILES}"
            )

        total_bytes = sum(f["size_bytes"] for f in discovered)
        if total_bytes > MAX_REPOSITORY_SIZE_BYTES:
            raise ValueError(
                f"Acquired repository size {total_bytes} bytes exceeds limit of {MAX_REPOSITORY_SIZE_BYTES} bytes"
            )

        # Build clean output metadata
        meta = {
            "status": "success",
            "repository": {
                "owner": owner,
                "repository": repo_name,
                "branch": clean_branch,
                "path": clean_subpath
            },
            "acquisition": {
                "acquisition_id": acquisition_id,
                "workspace": str(workspace_dir),
                "repo_path": str(repo_dest),
                "source": "github",
                "method": method,
                "schema_version": ACQUISITION_SCHEMA_VERSION
            }
        }

        # Save metadata inside workspace for robust resolution
        try:
            import json
            meta_file = workspace_dir / "acquisition_meta.json"
            with open(meta_file, "w", encoding="utf-8") as mf:
                json.dump(meta, mf)
        except Exception:
            pass

        return meta

    except Exception:
        # Clean up failed or incomplete workspace directories
        shutil.rmtree(workspace_dir, ignore_errors=True)
        raise


def resolve_acquisition_metadata(
    acquisition_id: str,
    workspace_root: Optional[str] = None
) -> Dict[str, Any]:
    """
    Resolves acquisition metadata for a given acquisition_id and verifies workspace containment.

    Raises ValueError if acquisition_id is invalid, missing, or escapes workspace boundary.
    """
    if not acquisition_id or not isinstance(acquisition_id, str):
        raise ValueError("acquisition_id must be a non-empty string")

    clean_id = acquisition_id.strip()

    # Path traversal check on acquisition_id
    if ".." in clean_id or "/" in clean_id or "\\" in clean_id:
        raise ValueError(f"Invalid acquisition_id format: {acquisition_id}")

    base_root = Path(workspace_root).resolve() if workspace_root else get_default_workspace_root()
    workspace_dir = (base_root / clean_id).resolve()

    if not _is_subpath(workspace_dir, base_root):
        raise ValueError("Path traversal detected: Acquisition workspace escapes workspace root")

    if not workspace_dir.exists() or not workspace_dir.is_dir():
        raise ValueError(f"Acquisition workspace not found for ID: {clean_id}")

    meta_file = workspace_dir / "acquisition_meta.json"
    if meta_file.exists():
        try:
            import json
            with open(meta_file, "r", encoding="utf-8") as mf:
                meta = json.load(mf)
                repo_path = Path(meta["acquisition"]["repo_path"]).resolve()
                if _is_subpath(repo_path, workspace_dir) and repo_path.exists():
                    return meta
        except Exception:
            pass

    # Fallback resolution if metadata file missing but repo directory exists
    # Look for subdirectories inside workspace_dir
    subdirs = [d for d in workspace_dir.iterdir() if d.is_dir()]
    if not subdirs:
        raise ValueError(f"No repository directory found inside workspace for ID: {clean_id}")

    repo_dest = subdirs[0].resolve()
    if not _is_subpath(repo_dest, workspace_dir):
        raise ValueError("Path traversal detected: Repository path escapes workspace boundary")

    return {
        "status": "success",
        "repository": {
            "owner": "unknown",
            "repository": repo_dest.name,
            "branch": "main",
            "path": ""
        },
        "acquisition": {
            "acquisition_id": clean_id,
            "workspace": str(workspace_dir),
            "repo_path": str(repo_dest),
            "source": "github",
            "method": "local",
            "schema_version": ACQUISITION_SCHEMA_VERSION
        }
    }

