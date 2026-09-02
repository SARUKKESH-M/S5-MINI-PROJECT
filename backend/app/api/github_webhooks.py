"""
FastAPI Router for CodeSentinel GitHub Webhook Ingress Endpoint.
"""

import json
from typing import Optional
from fastapi import APIRouter, Request, Header, HTTPException, status

try:
    from backend.app.core.config import settings
    from backend.github.webhook import verify_github_webhook_signature
    from backend.github.orchestrator import orchestrate_webhook_event
    from backend.github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )
except ImportError:
    from app.core.config import settings
    from github.webhook import verify_github_webhook_signature
    from github.orchestrator import orchestrate_webhook_event
    from github.exceptions import (
        GitHubAPIError,
        GitHubAuthenticationError,
        GitHubPermissionError,
        GitHubNotFoundError,
        GitHubRateLimitError
    )

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

    1. Reads raw request body bytes.
    2. Enforces HMAC-SHA256 signature verification against X-Hub-Signature-256 header.
    3. Safely parses JSON payload after signature verification.
    4. Passes payload to end-to-end webhook orchestrator.
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

    # 3. Delegate to end-to-end webhook orchestrator
    try:
        res = orchestrate_webhook_event(
            event_type=event_type,
            delivery_id=delivery_id,
            payload=payload
        )
        return res
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook Validation Error: {str(val_err)}"
        )
    except GitHubAuthenticationError as auth_err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub Authentication Failure"
        )
    except GitHubPermissionError as perm_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GitHub Permission Failure"
        )
    except GitHubNotFoundError as nf_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="GitHub Resource Not Found"
        )
    except GitHubRateLimitError as rl_err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="GitHub API Rate Limit Exceeded"
        )
    except GitHubAPIError as api_err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub API Error"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Webhook Orchestration Failure"
        )
