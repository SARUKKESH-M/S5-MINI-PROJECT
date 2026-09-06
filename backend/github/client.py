"""
CodeSentinel — Step 6Q-A: GitHub REST API Client Foundation

Provides a secure, minimal HTTP client for communicating with GitHub REST API endpoints.
Ensures tokens are strictly masked and never exposed in logs, exceptions, or string outputs.
"""

from typing import Any, Dict, Optional
import httpx

try:
    from backend.app.core.config import settings
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
except ImportError:
    from app.core.config import settings
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )


class GitHubClient:
    """
    Secure GitHub REST API client handler.

    Never exposes GITHUB_TOKEN in exceptions, logs, or string representations.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        api_version: Optional[str] = None,
        timeout: float = 10.0
    ):
        self._token = token or getattr(settings, "GITHUB_TOKEN", None)
        self.base_url = (base_url or getattr(settings, "GITHUB_API_BASE_URL", "https://api.github.com")).rstrip("/")
        self.api_version = api_version or getattr(settings, "GITHUB_API_VERSION", "2022-11-28")
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        """Builds standard GitHub API headers."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.api_version,
            "User-Agent": "CodeSentinel-Security-OS/1.0"
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes a HTTP request against GitHub REST API with safe error mapping.

        Args:
            method: HTTP verb ('GET', 'POST', 'PATCH', etc.)
            endpoint: Relative API path (e.g. '/repos/owner/repo')
            params: Optional query parameters
            json_data: Optional JSON body payload

        Returns:
            Parsed JSON response dictionary or status indicator.

        Raises:
            GitHubAuthenticationError: For 401 response.
            GitHubPermissionError: For 403 response.
            GitHubNotFoundError: For 404 response.
            GitHubRateLimitError: For 429 response.
            GitHubAPIError: For 5xx or unhandled status codes.
        """
        clean_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        url = f"{self.base_url}{clean_endpoint}"
        headers = self._get_headers()

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data
                )
        except httpx.TimeoutException as te:
            raise GitHubAPIError("GitHub API request timed out", status_code=504) from te
        except Exception as e:
            # Mask any potential sensitive details in transport error
            raise GitHubAPIError(f"GitHub API transport error: {type(e).__name__}", status_code=500) from e

        # Handle response status codes
        status_code = resp.status_code

        if 200 <= status_code < 300:
            if status_code == 204 or not resp.content:
                return {"status": "success", "status_code": status_code}
            try:
                return resp.json()
            except Exception:
                return {"status": "success", "status_code": status_code}

        if status_code == 401:
            raise GitHubAuthenticationError()

        if status_code == 403:
            resp_text = resp.text.lower() if resp.text else ""
            if "rate limit" in resp_text or resp.headers.get("x-ratelimit-remaining") == "0":
                raise GitHubRateLimitError()
            raise GitHubPermissionError()

        if status_code == 404:
            raise GitHubNotFoundError()

        if status_code == 429:
            raise GitHubRateLimitError()

        raise GitHubAPIError(f"GitHub API returned error response ({status_code})", status_code=status_code)

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Executes GET request."""
        return self.request("GET", endpoint, params=params)

    def post(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Executes POST request."""
        return self.request("POST", endpoint, params=params, json_data=json_data)

    def patch(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Executes PATCH request."""
        return self.request("PATCH", endpoint, params=params, json_data=json_data)

    def __repr__(self) -> str:
        token_state = "SET" if self._token else "UNSET"
        return f"<GitHubClient base_url={self.base_url!r} token={token_state}>"
