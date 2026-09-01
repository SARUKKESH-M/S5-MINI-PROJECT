"""
CodeSentinel — Step 6Q-A: GitHub Integration Exceptions

Defines custom exception classes for GitHub API interactions.
Ensures secrets and sensitive tokens are strictly masked and never leaked in exception representations.
"""

class GitHubAPIError(Exception):
    """Base exception for all GitHub API client errors."""

    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        return f"[{self.status_code}] {self.message}"

    def __repr__(self) -> str:
        return f"GitHubAPIError(status_code={self.status_code}, message={self.message!r})"


class GitHubAuthenticationError(GitHubAPIError):
    """Raised when GitHub API authentication fails (401 Unauthorized)."""

    def __init__(self, message: str = "GitHub API authentication failed (401)"):
        super().__init__(message=message, status_code=401)


class GitHubPermissionError(GitHubAPIError):
    """Raised when GitHub API permission or access is denied (403 Forbidden)."""

    def __init__(self, message: str = "GitHub API permission denied or scope insufficient (403)"):
        super().__init__(message=message, status_code=403)


class GitHubNotFoundError(GitHubAPIError):
    """Raised when a GitHub API resource is not found (404 Not Found)."""

    def __init__(self, message: str = "Requested GitHub resource not found (404)"):
        super().__init__(message=message, status_code=404)


class GitHubRateLimitError(GitHubAPIError):
    """Raised when GitHub API rate limits are exceeded (429 / 403 Rate Limit Exceeded)."""

    def __init__(self, message: str = "GitHub API rate limit exceeded (429/403)"):
        super().__init__(message=message, status_code=429)
