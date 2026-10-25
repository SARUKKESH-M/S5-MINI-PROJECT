"""
CodeSentinel — Step 6S-A: Application Security Hardening Foundation

Implements defensive backend security controls:
1. Request size limit middleware (enforces MAX_REQUEST_SIZE_BYTES).
2. HTTP Security headers middleware (nosniff, DENY, no-referrer, CSP, XSS protection).
3. Global unhandled exception handler (prevents internal stack trace / secret leaks).
4. Log secret sanitizer (redacts tokens, webhook secrets, auth headers, and API keys).
"""

import logging
import re
import sys
from typing import Any, Dict, Optional
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from backend.app.core.config import settings
except ImportError:
    from app.core.config import settings

# Patterns for secret redaction in logs/errors
TOKEN_LITERAL_REGEX = re.compile(
    r"(ghp_[a-zA-Z0-9_]{16,255}|gho_[a-zA-Z0-9_]{16,255}|github_pat_[a-zA-Z0-9_]{16,255}|gsk_[a-zA-Z0-9_]{16,255}|bearer\s+[a-zA-Z0-9._\-]+|secret_[a-zA-Z0-9_]{4,}|sess_[a-fA-F0-9]{16,}|session_[a-zA-Z0-9_]{16,})",
    re.IGNORECASE
)


class PayloadTooLargeError(StarletteHTTPException):
    """
    Raised when an incoming request payload exceeds max allowed size in bytes.
    Inherits from StarletteHTTPException so FastAPI error handling automatically
    maps it to an HTTP 413 response.
    """
    def __init__(self, detail: str = "Request payload exceeds allowed limit"):
        super().__init__(
            status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
            detail=detail
        )


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces a maximum payload size limit (MAX_REQUEST_SIZE_BYTES)
    on incoming request bodies to prevent DoS via memory exhaustion.

    Enforces limits via two complementary mechanisms:
    1. Fast-path check: Inspects Content-Length header and immediately rejects requests
       exceeding max_size_bytes with HTTP 413 before reading body bytes.
    2. Streaming ASGI check: Wraps the ASGI receive callable to meter cumulative incoming
       bytes in real time for chunked or length-unspecified requests, terminating with
       HTTP 413 if the actual payload size exceeds max_size_bytes without buffering
       an unbounded payload into memory.
    """

    def __init__(self, app, max_size_bytes: Optional[int] = None):
        super().__init__(app)
        self.max_size_bytes = max_size_bytes if max_size_bytes is not None else getattr(settings, "MAX_REQUEST_SIZE_BYTES", 10 * 1024 * 1024)

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # 1. Fast-path: Check declared Content-Length header
        content_lengths = []
        for header_pair in scope.get("headers", []):
            if len(header_pair) == 2 and header_pair[0].lower() == b"content-length":
                content_lengths.append(header_pair[1])

        if content_lengths:
            try:
                cl_values = set(int(cl.decode("latin-1")) for cl in content_lengths)
                if len(cl_values) > 1:
                    response = JSONResponse(
                        status_code=getattr(status, "HTTP_400_BAD_REQUEST", 400),
                        content={"detail": "Conflicting Content-Length headers"}
                    )
                    await response(scope, receive, send)
                    return
                cl_int = next(iter(cl_values))
                if cl_int > self.max_size_bytes:
                    response = JSONResponse(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        content={"detail": f"Request payload exceeds maximum allowed size of {self.max_size_bytes} bytes"}
                    )
                    await response(scope, receive, send)
                    return
            except (ValueError, UnicodeDecodeError):
                pass

        # 2. Streaming ASGI check: Meter actual incoming bytes chunk-by-chunk
        received_bytes = 0
        response_started = False
        exceeded_limit = False

        async def send_wrapper(message: Dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        async def receive_wrapper() -> Dict[str, Any]:
            nonlocal received_bytes, exceeded_limit
            if exceeded_limit:
                return {"type": "http.disconnect"}

            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                received_bytes += len(chunk)
                if received_bytes > self.max_size_bytes:
                    exceeded_limit = True
                    raise PayloadTooLargeError(
                        f"Request payload exceeds maximum allowed size of {self.max_size_bytes} bytes"
                    )
            return message

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except (PayloadTooLargeError, StarletteHTTPException) as exc:
            if getattr(exc, "status_code", None) == 413:
                if not response_started:
                    detail = getattr(
                        exc,
                        "detail",
                        f"Request payload exceeds maximum allowed size of {self.max_size_bytes} bytes"
                    )
                    response = JSONResponse(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        content={"detail": detail}
                    )
                    await response(scope, receive, send)
                    return
            else:
                raise

    async def dispatch(self, request: Request, call_next):
        """
        Maintains backward compatibility for direct callers of dispatch.
        """
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl_int = int(content_length)
                if cl_int > self.max_size_bytes:
                    return JSONResponse(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        content={"detail": f"Request payload exceeds maximum allowed size of {self.max_size_bytes} bytes"}
                    )
            except ValueError:
                pass

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that appends defensive HTTP security headers to all API responses.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        return response


def sanitize_sensitive_text(text: str) -> str:
    """Masks known sensitive token literals from text messages."""
    if not text or not isinstance(text, str):
        return ""
    text = TOKEN_LITERAL_REGEX.sub("[REDACTED_SECRET]", text)
    return text


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global exception handler for FastAPI that catches unhandled exceptions,
    prevents stack traces and internal secrets from leaking to clients,
    and returns a clean, safe HTTP 500 error response.
    """

    # If exception is already a Starlette/FastAPI HTTPException, pass its detail safely
    if isinstance(exc, StarletteHTTPException):
        clean_detail = sanitize_sensitive_text(str(exc.detail))
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": clean_detail},
            headers=getattr(exc, "headers", None)
        )

    # For unexpected internal server errors, log error safely and return generic 500
    safe_err_msg = sanitize_sensitive_text(str(exc))
    logging.error("Unhandled exception processing request path %s: %s", request.url.path, safe_err_msg)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."}
    )


class SecurityLogFilter(logging.Filter):
    """
    Python logging filter that sanitizes log records to prevent sensitive credentials
    or authorization headers from appearing in backend logs.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (sanitize_sensitive_text(v) if isinstance(v, str) else v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_sensitive_text(a) if isinstance(a, str) else a for a in record.args)
        return True
