"""
FastAPI Router for CodeSentinel GitHub Webhook Ingress Endpoint.
"""

import json
from typing import Optional
from fastapi import APIRouter, Request, Header, HTTPException, status

try:
    from backend.app.core.config import settings
    from backend.github.webhook import verify_github_webhook_signature
except ImportError:
    from app.core.config import settings
    from github.webhook import verify_github_webhook_signature

router = APIRouter(tags=["GitHub Webhooks"])


@router.post("/github/webhook")
async def github_webhook_endpoint(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery")
):
    """
    Ingress endpoint for GitHub webhooks.

    Verifies HMAC-SHA256 signature against raw request body bytes before parsing JSON payload.
    Acknowledges receipt of supported event types ('pull_request', 'push') without executing pipeline analysis.
    """
    raw_body = await request.body()
    webhook_secret = getattr(settings, "GITHUB_WEBHOOK_SECRET", None)

    # 1. Enforce signature verification if webhook secret is configured
    if webhook_secret and webhook_secret.strip():
        if not x_hub_signature_256:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Hub-Signature-256 header"
            )

        is_valid = verify_github_webhook_signature(
            payload=raw_body,
            signature_header=x_hub_signature_256,
            secret=webhook_secret
        )
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature"
            )

    # 2. Parse JSON payload safely after signature verification
    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON webhook payload"
        )

    event_type = (x_github_event or "unknown").strip().lower()
    delivery_id = (x_github_delivery or "none").strip()

    # 3. Handle event types safely (acknowledgement only for Step 6Q-A)
    if event_type in ("pull_request", "push"):
        return {
            "status": "acknowledged",
            "event": event_type,
            "delivery": delivery_id
        }

    return {
        "status": "ignored",
        "event": event_type,
        "delivery": delivery_id
    }
