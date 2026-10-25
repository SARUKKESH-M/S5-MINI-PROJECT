"""
CodeSentinel — Phase 3C: Ingress Security Hardening Regression Tests

Validates:
1. Normal request within configured limit.
2. Declared Content-Length exceeding limit.
3. Body exceeding limit without declared length (chunked / streaming).
4. Actual body exceeding limit despite misleading/smaller declared length.
5. Streaming enforcement that aborts immediately without buffering an unlimited body.
6. Correctly signed webhook.
7. Invalid webhook signature.
8. Missing secret in production fails closed with 500.
9. Missing secret outside production with no signature preserves dev/test behavior.
10. Missing secret outside production with supplied signature is rejected with 401.
11. Webhook delivery idempotency behavior remains intact.
"""

import asyncio
import hashlib
import hmac
import json
import uuid
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.core.security import RequestSizeLimitMiddleware, PayloadTooLargeError
from backend.app.main import app


# Helper ASGI app to test low-level ASGI streaming and lifecycle
def make_test_asgi_app(max_size_bytes: int):
    inner_app = FastAPI()

    @inner_app.post("/test-limit")
    async def limit_endpoint(payload: dict):
        return {"status": "ok", "keys": list(payload.keys())}

    inner_app.add_middleware(RequestSizeLimitMiddleware, max_size_bytes=max_size_bytes)
    return inner_app


# =====================================================================
# TASK A: REQUEST SIZE ENFORCEMENT TESTS
# =====================================================================

def test_1_normal_request_within_configured_limit():
    """1. Verifies that normal requests within the limit succeed with 200 OK."""
    test_app = make_test_asgi_app(max_size_bytes=1000)
    client = TestClient(test_app)

    res = client.post("/test-limit", json={"hello": "world", "status": "active"})
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "keys": ["hello", "status"]}


def test_2_declared_content_length_exceeding_limit():
    """2. Verifies fast-path early rejection when declared Content-Length exceeds limit."""
    test_app = make_test_asgi_app(max_size_bytes=100)
    client = TestClient(test_app)

    headers = {"Content-Length": "1000"}
    res = client.post("/test-limit", json={"data": "x" * 50}, headers=headers)
    assert res.status_code == 413
    assert "exceeds maximum allowed size" in res.json().get("detail", "")


def test_3_body_exceeding_limit_without_declared_length():
    """3. Verifies chunked/streaming requests without Content-Length are rejected with 413."""
    test_app = make_test_asgi_app(max_size_bytes=100)
    client = TestClient(test_app)

    # Stream chunks totaling 160 bytes without explicit content-length header
    def chunk_generator():
        yield b'{"data": "'
        yield b"a" * 140
        yield b'"}'

    res = client.post("/test-limit", content=chunk_generator(), headers={"Content-Type": "application/json"})
    assert res.status_code == 413
    assert "exceeds maximum allowed size" in res.json().get("detail", "")


def test_4_actual_body_exceeding_limit_despite_misleading_declared_length():
    """4. Verifies actual body exceeding limit is rejected even if Content-Length was smaller/misleading."""
    async def run_test():
        limit = 100
        middleware = RequestSizeLimitMiddleware(app=None, max_size_bytes=limit)

        # Scope claims Content-Length is only 20 bytes (well within 100 byte limit)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/test-limit",
            "headers": [(b"content-length", b"20"), (b"content-type", b"application/json")],
        }

        # But receive yields two chunks totaling 150 bytes
        messages = [
            {"type": "http.request", "body": b"x" * 50, "more_body": True},
            {"type": "http.request", "body": b"y" * 100, "more_body": False},
        ]

        async def mock_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        sent_messages = []

        async def mock_send(msg):
            sent_messages.append(msg)

        async def dummy_app(scope, receive, send):
            # Reads the body using receive
            while True:
                m = await receive()
                if not m.get("more_body", False):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"status":"ok"}'})

        middleware.app = dummy_app
        await middleware(scope, mock_receive, mock_send)

        # Must send 413 response
        assert len(sent_messages) >= 2
        assert sent_messages[0]["type"] == "http.response.start"
        assert sent_messages[0]["status"] == 413
        body_json = json.loads(sent_messages[1]["body"].decode("utf-8"))
        assert "exceeds maximum allowed size" in body_json.get("detail", "")

    asyncio.run(run_test())


def test_5_streaming_enforcement_aborts_without_buffering_unlimited_body():
    """5. Verifies that streaming enforcement aborts immediately once threshold is exceeded, without reading subsequent chunks."""
    async def run_test():
        limit = 50
        middleware = RequestSizeLimitMiddleware(app=None, max_size_bytes=limit)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/stream-test",
            "headers": [(b"content-type", b"application/octet-stream")],
        }

        chunk3_called = False

        async def streaming_receive():
            nonlocal chunk3_called
            # Chunk 1: 30 bytes (cumulative: 30 <= 50)
            yield {"type": "http.request", "body": b"A" * 30, "more_body": True}
            # Chunk 2: 30 bytes (cumulative: 60 > 50 -> must trigger 413 here!)
            yield {"type": "http.request", "body": b"B" * 30, "more_body": True}
            # Chunk 3: Should NEVER be consumed!
            chunk3_called = True
            yield {"type": "http.request", "body": b"C" * 1000000, "more_body": False}

        gen = streaming_receive()

        async def mock_receive():
            return await anext(gen)

        sent_messages = []

        async def mock_send(msg):
            sent_messages.append(msg)

        async def dummy_app(scope, receive, send):
            while True:
                m = await receive()
                if not m.get("more_body", False):
                    break

        middleware.app = dummy_app
        await middleware(scope, mock_receive, mock_send)

        # Chunk 3 must NOT have been called/buffered
        assert chunk3_called is False
        # Response must be HTTP 413
        assert sent_messages[0]["type"] == "http.response.start"
        assert sent_messages[0]["status"] == 413

    asyncio.run(run_test())


# =====================================================================
# TASK B: WEBHOOK SIGNATURE HARDENING TESTS
# =====================================================================

def test_6_correctly_signed_webhook(monkeypatch):
    """6. Verifies correctly signed webhook is accepted."""
    client = TestClient(app)
    secret = "phase_3c_test_secret_key"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)
    monkeypatch.setattr(settings, "APP_ENV", "production")

    payload_bytes = json.dumps({"action": "opened", "number": 101}).encode("utf-8")
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    response = client.post(
        "/github/webhook",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-3c-valid-1"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "acknowledged"
    assert data["event"] == "pull_request"
    assert data["delivery"] == "delivery-3c-valid-1"


def test_7_invalid_webhook_signature(monkeypatch):
    """7. Verifies invalid signature is rejected with 401 Unauthorized."""
    client = TestClient(app)
    secret = "phase_3c_test_secret_key"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)

    payload_bytes = json.dumps({"action": "opened", "number": 102}).encode("utf-8")

    response = client.post(
        "/github/webhook",
        content=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-3c-invalid-1"
        }
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook signature"


def test_8_missing_secret_in_production(monkeypatch):
    """8. Verifies missing secret in production fails closed with 500 Internal Server Error."""
    client = TestClient(app)
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)

    response = client.post(
        "/github/webhook",
        json={"action": "opened"},
        headers={"X-GitHub-Event": "pull_request"}
    )
    assert response.status_code == 500
    assert "Production webhook secret is not configured" in response.json()["detail"]


def test_9_missing_secret_outside_production_with_no_signature(monkeypatch):
    """9. Verifies missing secret outside production with no signature preserves dev/test behavior."""
    client = TestClient(app)
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)

    response = client.post(
        "/github/webhook",
        json={"action": "opened", "number": 103},
        headers={
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-3c-dev-unsigned"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "acknowledged"
    assert data["delivery"] == "delivery-3c-dev-unsigned"


def test_10_missing_secret_outside_production_with_supplied_signature(monkeypatch):
    """10. Verifies missing secret outside production with a supplied signature is rejected with 401."""
    client = TestClient(app)
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", None)

    response = client.post(
        "/github/webhook",
        json={"action": "opened", "number": 104},
        headers={
            "X-Hub-Signature-256": "sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-3c-dev-forged"
        }
    )
    assert response.status_code == 401
    assert "Cannot verify signature" in response.json()["detail"]


def test_11_existing_delivery_idempotency_remains_intact(monkeypatch):
    """11. Verifies delivery idempotency rejects duplicate delivery IDs as duplicate."""
    client = TestClient(app)
    secret = "phase_3c_test_secret_key"
    monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", secret)
    monkeypatch.setattr(settings, "APP_ENV", "production")

    delivery_id = f"delivery-3c-idempotent-{uuid.uuid4()}"
    payload_bytes = json.dumps({"ref": "refs/heads/main", "after": "a" * 40}).encode("utf-8")
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": delivery_id
    }

    # First delivery
    res1 = client.post("/github/webhook", content=payload_bytes, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["status"] == "acknowledged"

    # Second delivery with identical delivery ID
    res2 = client.post("/github/webhook", content=payload_bytes, headers=headers)
    assert res2.status_code == 200
    assert res2.json()["status"] == "duplicate"
