"""
CodeSentinel — Step 6Q-A: Webhook Input Validation Foundation

Provides independent input validation helpers for GitHub webhook payload data.
Strictly rejects shell metacharacters, path traversal, and malformed inputs.
"""

import re
from typing import Any


UNSAFE_CHARS_REGEX = re.compile(r"[\x00;&|$\`<>\"\']")
OWNER_REPO_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+$")
COMMIT_SHA_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")


def validate_webhook_owner(owner: str) -> str:
    """
    Validates GitHub repository owner identifier.

    Raises ValueError if owner is empty, invalid, contains path traversal, or shell metacharacters.
    """
    if not isinstance(owner, str) or not owner.strip():
        raise ValueError("Webhook owner must be a non-empty string")

    clean_owner = owner.strip()

    if UNSAFE_CHARS_REGEX.search(clean_owner):
        raise ValueError("Webhook owner contains prohibited characters or commands")

    if ".." in clean_owner or "/" in clean_owner or "\\" in clean_owner:
        raise ValueError("Webhook owner contains invalid path traversal characters")

    if not OWNER_REPO_REGEX.match(clean_owner):
        raise ValueError(f"Invalid owner name format: {clean_owner}")

    return clean_owner


def validate_webhook_repo(repo: str) -> str:
    """
    Validates GitHub repository name.

    Raises ValueError if repository name is empty, invalid, contains path traversal, or shell metacharacters.
    """
    if not isinstance(repo, str) or not repo.strip():
        raise ValueError("Webhook repository must be a non-empty string")

    clean_repo = repo.strip()
    if clean_repo.lower().endswith(".git"):
        clean_repo = clean_repo[:-4]

    if UNSAFE_CHARS_REGEX.search(clean_repo):
        raise ValueError("Webhook repository contains prohibited characters or commands")

    if ".." in clean_repo or "/" in clean_repo or "\\" in clean_repo:
        raise ValueError("Webhook repository contains invalid path traversal characters")

    if not OWNER_REPO_REGEX.match(clean_repo):
        raise ValueError(f"Invalid repository name format: {clean_repo}")

    return clean_repo


def validate_pr_number(pr_number: Any) -> int:
    """
    Validates Pull Request number.

    Raises ValueError if PR number is not a positive integer.
    """
    if isinstance(pr_number, bool):
        raise ValueError("PR number cannot be a boolean")

    if isinstance(pr_number, str):
        if not pr_number.strip().isdigit():
            raise ValueError(f"Invalid PR number format: {pr_number}")
        val = int(pr_number.strip())
    elif isinstance(pr_number, int):
        val = pr_number
    else:
        raise ValueError("PR number must be an integer or digit string")

    if val <= 0 or val > 1_000_000_000:
        raise ValueError(f"PR number out of valid range: {val}")

    return val


def validate_commit_sha(sha: str) -> str:
    """
    Validates Git commit SHA (40-character hexadecimal string).

    Raises ValueError if commit SHA is invalid, malformed, or contains non-hex characters.
    """
    if not isinstance(sha, str) or not sha.strip():
        raise ValueError("Commit SHA must be a non-empty string")

    clean_sha = sha.strip()

    if UNSAFE_CHARS_REGEX.search(clean_sha):
        raise ValueError("Commit SHA contains prohibited characters or commands")

    if not COMMIT_SHA_REGEX.match(clean_sha):
        raise ValueError(f"Invalid 40-character commit SHA format: {clean_sha}")

    return clean_sha.lower()
