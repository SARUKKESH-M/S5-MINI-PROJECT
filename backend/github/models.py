"""
CodeSentinel — Step 6Q-B: GitHub PR & Commit Data Models

Defines typed dataclasses for Pull Request metadata, changed files, and acquisition snapshots.
Ensures zero credentials, tokens, or authorization details are included in model fields or string representations.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class GitHubPullRequest:
    """Read-only Pull Request metadata model."""
    owner: str
    repository: str
    pr_number: int
    title: str
    state: str
    base_branch: str
    base_sha: str
    head_branch: str
    head_sha: str
    html_url: str


@dataclass(frozen=True)
class GitHubChangedFile:
    """Read-only PR changed file model."""
    filename: str
    status: str  # e.g., 'added', 'modified', 'removed', 'renamed'
    additions: int
    deletions: int
    changes: int
    patch: Optional[str] = None
    sha: Optional[str] = None


@dataclass(frozen=True)
class GitHubPullRequestSnapshot:
    """Combined immutable snapshot of Pull Request metadata and changed files."""
    pull_request: GitHubPullRequest
    changed_files: List[GitHubChangedFile] = field(default_factory=list)
