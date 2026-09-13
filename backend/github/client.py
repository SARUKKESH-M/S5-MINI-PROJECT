"""
CodeSentinel — Step 6Q-A: GitHub REST API Client Foundation

Provides a secure, minimal HTTP client for communicating with GitHub REST API endpoints.
Ensures tokens are strictly masked and never exposed in logs, exceptions, or string outputs.
"""

import email.utils
import threading
import time
from typing import Any, Callable, Dict, Optional
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
    Maintains a reusable connection pool via httpx.Client with deterministic lifecycle management.
    Features bounded exponential backoff retry for transient failures and rate limits.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        api_version: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        max_backoff_seconds: float = 10.0,
        sleep_func: Optional[Callable[[float], None]] = None
    ):
        self._token = token or getattr(settings, "GITHUB_TOKEN", None)
        self.base_url = (base_url or getattr(settings, "GITHUB_API_BASE_URL", "https://api.github.com")).rstrip("/")
        self.api_version = api_version or getattr(settings, "GITHUB_API_VERSION", "2022-11-28")
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = max(0.0, float(backoff_factor))
        self.max_backoff_seconds = max(0.0, float(max_backoff_seconds))
        self._sleep_func = sleep_func or time.sleep

        self._client: Optional[httpx.Client] = None
        self._lock = threading.Lock()
        self._closed = False

    def _get_client(self) -> httpx.Client:
        """Lazily initialize or return the thread-safe reusable httpx.Client."""
        with self._lock:
            if self._closed:
                raise RuntimeError("GitHubClient instance has been closed")
            if self._client is None or self._client.is_closed:
                self._client = httpx.Client(timeout=self.timeout)
            return self._client

    def close(self) -> None:
        """Deterministic cleanup and resource release of the underlying HTTP client."""
        with self._lock:
            self._closed = True
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

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

    def _calculate_retry_delay(
        self,
        response: Optional[httpx.Response],
        attempt: int
    ) -> float:
        """
        Calculates deterministic retry delay bounded strictly by max_backoff_seconds.
        Prefers Retry-After, then X-RateLimit-Reset, then exponential backoff.
        """
        if response is not None:
            # 1. Inspect Retry-After header (seconds or HTTP date)
            retry_after = response.headers.get("retry-after")
            if retry_after:
                try:
                    val = float(retry_after.strip())
                    return max(0.0, min(val, self.max_backoff_seconds))
                except ValueError:
                    try:
                        parsed_dt = email.utils.parsedate_to_datetime(retry_after.strip())
                        diff = parsed_dt.timestamp() - time.time()
                        return max(0.0, min(diff, self.max_backoff_seconds))
                    except Exception:
                        pass

            # 2. Inspect X-RateLimit-Reset header (epoch timestamp)
            reset_header = response.headers.get("x-ratelimit-reset")
            if reset_header:
                try:
                    reset_ts = float(reset_header.strip())
                    diff = reset_ts - time.time()
                    return max(0.0, min(diff, self.max_backoff_seconds))
                except Exception:
                    pass

        # 3. Deterministic exponential backoff
        delay = self.backoff_factor * (2 ** attempt)
        return max(0.0, min(delay, self.max_backoff_seconds))

    def _is_retryable_status(self, status_code: int, response: httpx.Response) -> bool:
        """
        Determines whether an HTTP status code qualifies as a transient failure.
        Allows:
        - 502, 503, 504 (transient server errors)
        - 429 when retry information (Retry-After or X-RateLimit-Reset) indicates retry is appropriate
        - 403 when rate-limit headers or text indicate rate limiting AND retry information is present
        Never retries 400, 401, ordinary 403 permission failures, 404, or unhandled errors.
        """
        if status_code in (502, 503, 504):
            return True

        has_retry_info = bool(response.headers.get("retry-after") or response.headers.get("x-ratelimit-reset"))

        if status_code == 429:
            return has_retry_info

        if status_code == 403:
            resp_text = response.text.lower() if response.text else ""
            is_rate_limited = "rate limit" in resp_text or response.headers.get("x-ratelimit-remaining") == "0"
            return is_rate_limited and has_retry_info

        return False

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        allow_retry: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Executes an HTTP request against GitHub REST API with connection reuse and safe error mapping.

        Args:
            method: HTTP verb ('GET', 'POST', 'PATCH', etc.)
            endpoint: Relative API path (e.g. '/repos/owner/repo')
            params: Optional query parameters
            json_data: Optional JSON body payload
            allow_retry: Explicit retry override. Defaults to True for GET/HEAD, False for mutations.

        Returns:
            Parsed JSON response dictionary or status indicator.

        Raises:
            GitHubAuthenticationError: For 401 response.
            GitHubPermissionError: For 403 response.
            GitHubNotFoundError: For 404 response.
            GitHubRateLimitError: For 429 or rate-limited 403 response.
            GitHubAPIError: For 5xx or unhandled status codes.
        """
        clean_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        url = f"{self.base_url}{clean_endpoint}"
        headers = self._get_headers()
        client = self._get_client()

        # Idempotent methods (GET, HEAD) are safe to retry; mutations (POST, PATCH, DELETE) are not retried by default
        can_retry = allow_retry if allow_retry is not None else (method.upper() in ("GET", "HEAD"))
        attempts_limit = self.max_retries if can_retry else 0

        attempt = 0
        last_resp: Optional[httpx.Response] = None

        while True:
            try:
                resp = client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data
                )
                last_resp = resp
                status_code = resp.status_code

                if 200 <= status_code < 300:
                    if status_code == 204 or not resp.content:
                        return {"status": "success", "status_code": status_code}
                    try:
                        return resp.json()
                    except Exception:
                        return {"status": "success", "status_code": status_code}

                # Check if eligible for retry
                if can_retry and attempt < attempts_limit and self._is_retryable_status(status_code, resp):
                    delay = self._calculate_retry_delay(resp, attempt)
                    if delay > 0:
                        self._sleep_func(delay)
                    attempt += 1
                    continue

                break

            except httpx.TimeoutException as te:
                if can_retry and attempt < attempts_limit:
                    delay = self._calculate_retry_delay(None, attempt)
                    if delay > 0:
                        self._sleep_func(delay)
                    attempt += 1
                    continue
                raise GitHubAPIError("GitHub API request timed out", status_code=504) from te
            except Exception as e:
                if can_retry and attempt < attempts_limit and isinstance(e, (httpx.TransportError, httpx.NetworkError)):
                    delay = self._calculate_retry_delay(None, attempt)
                    if delay > 0:
                        self._sleep_func(delay)
                    attempt += 1
                    continue
                raise GitHubAPIError(f"GitHub API transport error: {type(e).__name__}", status_code=500) from e

        # Handle final status codes
        status_code = last_resp.status_code

        if status_code == 401:
            raise GitHubAuthenticationError()

        if status_code == 403:
            resp_text = last_resp.text.lower() if last_resp.text else ""
            if "rate limit" in resp_text or last_resp.headers.get("x-ratelimit-remaining") == "0":
                raise GitHubRateLimitError()
            raise GitHubPermissionError()

        if status_code == 404:
            raise GitHubNotFoundError()

        if status_code == 429:
            raise GitHubRateLimitError()

        raise GitHubAPIError(f"GitHub API returned error response ({status_code})", status_code=status_code)

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None, allow_retry: Optional[bool] = None) -> Dict[str, Any]:
        """Executes GET request."""
        return self.request("GET", endpoint, params=params, allow_retry=allow_retry)

    def post(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        allow_retry: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Executes POST request."""
        return self.request("POST", endpoint, params=params, json_data=json_data, allow_retry=allow_retry)

    def patch(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        allow_retry: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Executes PATCH request."""
        return self.request("PATCH", endpoint, params=params, json_data=json_data, allow_retry=allow_retry)

    def __repr__(self) -> str:
        token_state = "SET" if self._token else "UNSET"
        return f"<GitHubClient base_url={self.base_url!r} token={token_state}>"
