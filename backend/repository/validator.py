"""
CodeSentinel — Step 6K: GitHub Repository URL & Input Validator

Implements strict validation and extraction for GitHub repository URLs, owner/repo
names, branch names, and repository subpaths.
"""

import re
from urllib.parse import urlparse


UNSAFE_CHARS_REGEX = re.compile(r"[\x00;&|$\`<>\"\']")
OWNER_REPO_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+$")


def validate_github_url(url: str) -> dict:
    """
    Validates a GitHub repository URL and extracts owner and repository names.

    Raises ValueError if URL is invalid, malformed, contains credentials, or uses an unsupported scheme/domain.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("GitHub URL must be a non-empty string")

    clean_url = url.strip()

    if UNSAFE_CHARS_REGEX.search(clean_url):
        raise ValueError("GitHub URL contains prohibited characters or commands")

    # Parse URL
    try:
        parsed = urlparse(clean_url)
    except Exception as e:
        raise ValueError(f"Malformed URL: {e}")

    # Enforce https scheme and github.com domain
    if parsed.scheme.lower() != "https":
        raise ValueError("Invalid URL scheme: only https:// is supported")

    netloc = parsed.netloc.lower()

    # Reject embedded credentials (user:pass@github.com)
    if "@" in netloc:
        raise ValueError("Embedded credentials in GitHub URL are strictly forbidden")

    if netloc != "github.com" and not netloc.endswith(".github.com"):
        raise ValueError("Invalid domain: only github.com repository URLs are supported")

    # Normalize path segments
    path = parsed.path.strip("/")
    if not path:
        raise ValueError("GitHub URL missing owner and repository path")

    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include both owner and repository name")

    owner = parts[0]
    repo = parts[1]

    # Normalize trailing .git
    if repo.lower().endswith(".git"):
        repo = repo[:-4]

    if not repo:
        raise ValueError("Invalid repository name in GitHub URL")

    # Validate owner and repo names against safe characters
    if not OWNER_REPO_REGEX.match(owner):
        raise ValueError(f"Invalid characters in repository owner name: {owner}")

    if not OWNER_REPO_REGEX.match(repo):
        raise ValueError(f"Invalid characters in repository name: {repo}")

    normalized_url = f"https://github.com/{owner}/{repo}"

    return {
        "owner": owner,
        "repository": repo,
        "normalized_url": normalized_url
    }


def validate_branch(branch: str) -> str:
    """
    Validates a Git branch name.

    Raises ValueError if branch contains null bytes, path traversal, shell metacharacters, or is invalid.
    """
    if not isinstance(branch, str):
        raise ValueError("Branch must be a string")

    clean_branch = branch.strip()
    if not clean_branch:
        return "main"

    if UNSAFE_CHARS_REGEX.search(clean_branch):
        raise ValueError("Branch name contains prohibited characters or commands")

    if ".." in clean_branch or "\\" in clean_branch or clean_branch.startswith("/"):
        raise ValueError("Invalid branch name format")

    return clean_branch


def validate_repo_path(rel_path: str) -> str:
    """
    Validates a repository relative subpath.

    Raises ValueError if path contains path traversal, null bytes, or absolute path escape sequences.
    """
    if not isinstance(rel_path, str):
        raise ValueError("Path must be a string")

    clean_path = rel_path.strip().replace("\\", "/").strip("/")

    if not clean_path:
        return ""

    if UNSAFE_CHARS_REGEX.search(clean_path):
        raise ValueError("Path contains prohibited characters or commands")

    parts = clean_path.split("/")
    for part in parts:
        if part == "..":
            raise ValueError("Path traversal ('..') is strictly prohibited")
        if part == ".":
            continue

    return clean_path
