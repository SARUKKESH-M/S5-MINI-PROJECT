"""
CodeSentinel — Step 6Q-B: Pull Request Acquisition Service

Provides read-only retrieval and normalization of GitHub Pull Request metadata
and changed-file lists. Strictly enforces input validation and commit SHA checks.
"""

from typing import List, Optional

try:
    from backend.github.client import GitHubClient
    from backend.github.models import (
        GitHubPullRequest,
        GitHubChangedFile,
        GitHubPullRequestSnapshot
    )
    from backend.github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
except ImportError:
    from github.client import GitHubClient
    from github.models import (
        GitHubPullRequest,
        GitHubChangedFile,
        GitHubPullRequestSnapshot
    )
    from github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )


def _validate_filename(filename: str) -> str:
    """Ensures file path in PR does not contain path traversal or null bytes."""
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Filename must be a non-empty string")
    clean_path = filename.strip().replace("\\", "/").strip("/")
    if "\x00" in clean_path:
        raise ValueError("Filename contains prohibited null bytes")
    parts = clean_path.split("/")
    for part in parts:
        if part == "..":
            raise ValueError("Filename contains prohibited path traversal ('..')")
    return clean_path


def get_pull_request(
    owner: str,
    repository: str,
    pr_number: int,
    client: Optional[GitHubClient] = None
) -> GitHubPullRequest:
    """
    Fetches and validates GitHub Pull Request metadata via GitHub REST API.

    Args:
        owner: Repository owner.
        repository: Repository name.
        pr_number: PR number.
        client: Optional pre-configured GitHubClient instance.

    Returns:
        Validated GitHubPullRequest object.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_pr_num = validate_pr_number(pr_number)

    api_client = client or GitHubClient()
    endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}"
    res = api_client.get(endpoint)

    if not isinstance(res, dict):
        raise ValueError("Malformed response received from GitHub API for Pull Request")

    # Extract base/head commit SHAs and validate
    head_obj = res.get("head") or {}
    base_obj = res.get("base") or {}

    head_sha = validate_commit_sha(str(head_obj.get("sha") or ""))
    base_sha = validate_commit_sha(str(base_obj.get("sha") or ""))

    title = str(res.get("title") or "").strip()
    state = str(res.get("state") or "open").strip().lower()
    base_branch = str(base_obj.get("ref") or "main").strip()
    head_branch = str(head_obj.get("ref") or "main").strip()
    html_url = str(res.get("html_url") or f"https://github.com/{clean_owner}/{clean_repo}/pull/{clean_pr_num}")

    return GitHubPullRequest(
        owner=clean_owner,
        repository=clean_repo,
        pr_number=clean_pr_num,
        title=title,
        state=state,
        base_branch=base_branch,
        base_sha=base_sha,
        head_branch=head_branch,
        head_sha=head_sha,
        html_url=html_url
    )


def get_pull_request_files(
    owner: str,
    repository: str,
    pr_number: int,
    client: Optional[GitHubClient] = None,
    max_files: int = 300
) -> List[GitHubChangedFile]:
    """
    Fetches and validates the list of changed files in a GitHub Pull Request with pagination support.

    Args:
        owner: Repository owner.
        repository: Repository name.
        pr_number: PR number.
        client: Optional pre-configured GitHubClient instance.
        max_files: Resource limit on total changed files returned.

    Returns:
        List of validated GitHubChangedFile objects.
    """
    clean_owner = validate_webhook_owner(owner)
    clean_repo = validate_webhook_repo(repository)
    clean_pr_num = validate_pr_number(pr_number)

    api_client = client or GitHubClient()
    changed_files: List[GitHubChangedFile] = []
    page = 1
    per_page = 100

    while len(changed_files) < max_files:
        endpoint = f"/repos/{clean_owner}/{clean_repo}/pulls/{clean_pr_num}/files"
        params = {"page": page, "per_page": per_page}
        res = api_client.get(endpoint, params=params)

        if not isinstance(res, list):
            break

        if not res:
            break

        for item in res:
            if not isinstance(item, dict):
                continue

            raw_filename = str(item.get("filename") or "")
            clean_filename = _validate_filename(raw_filename)

            status = str(item.get("status") or "modified").strip().lower()
            additions = int(item.get("additions", 0))
            deletions = int(item.get("deletions", 0))
            changes = int(item.get("changes", 0))
            patch = str(item["patch"]) if item.get("patch") is not None else None

            file_sha = None
            raw_sha = item.get("sha")
            if raw_sha and isinstance(raw_sha, str) and raw_sha.strip():
                try:
                    file_sha = validate_commit_sha(raw_sha.strip())
                except ValueError:
                    file_sha = None

            file_obj = GitHubChangedFile(
                filename=clean_filename,
                status=status,
                additions=additions,
                deletions=deletions,
                changes=changes,
                patch=patch,
                sha=file_sha
            )
            changed_files.append(file_obj)

            if len(changed_files) >= max_files:
                break

        if len(res) < per_page:
            break

        page += 1

    return changed_files


def acquire_pull_request(
    owner: str,
    repository: str,
    pr_number: int,
    client: Optional[GitHubClient] = None
) -> GitHubPullRequestSnapshot:
    """
    Acquires full Pull Request snapshot (metadata + changed files) into a structured read-only object.

    Args:
        owner: Repository owner.
        repository: Repository name.
        pr_number: PR number.
        client: Optional GitHubClient instance.

    Returns:
        GitHubPullRequestSnapshot object containing metadata and changed files list.
    """
    api_client = client or GitHubClient()
    pr_meta = get_pull_request(owner, repository, pr_number, client=api_client)
    pr_files = get_pull_request_files(owner, repository, pr_number, client=api_client)

    return GitHubPullRequestSnapshot(
        pull_request=pr_meta,
        changed_files=pr_files
    )
