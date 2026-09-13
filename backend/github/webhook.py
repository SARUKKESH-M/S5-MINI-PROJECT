"""
CodeSentinel — Step 6Q-A: Webhook Signature Verification

Implements constant-time HMAC-SHA256 verification for GitHub webhook notifications.
Follows secure practices:
- Verifies signature against raw bytes before any JSON parsing.
- Uses hmac.compare_digest for constant-time comparison to prevent timing attacks.
- Never logs or exposes secret keys or expected signatures.
"""

import hmac
import hashlib
from typing import Optional


def verify_github_webhook_signature(
    payload: bytes,
    signature_header: Optional[str],
    secret: Optional[str]
) -> bool:
    """
    Verifies GitHub webhook HMAC-SHA256 signature against raw request body bytes.

    Args:
        payload: Raw request payload bytes.
        signature_header: Value of X-Hub-Signature-256 header (format: 'sha256=<hex>').
        secret: Configured GITHUB_WEBHOOK_SECRET string.

    Returns:
        True if signature is valid, False otherwise.
    """
    if not secret or not isinstance(secret, str) or not secret.strip():
        return False

    if not isinstance(payload, bytes):
        return False

    if not signature_header or not isinstance(signature_header, str):
        return False

    clean_header = signature_header.strip()
    if not clean_header.startswith("sha256="):
        return False

    received_sig = clean_header[7:].strip()
    if not received_sig:
        return False

    try:
        secret_bytes = secret.encode("utf-8")
        expected_sig = hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig.lower(), received_sig.lower())
    except Exception:
        return False


def claim_webhook_delivery(
    delivery_id: str,
    event_type: str,
    now_iso: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    db_path: Optional[str] = None
) -> bool:
    """
    Atomically claims a webhook delivery ID via AnalysisStore.
    Returns True if successfully claimed, False if already claimed (unexpired duplicate).
    """
    clean_id = str(delivery_id or "").strip()
    if not clean_id or clean_id.lower() in ("none", "unknown"):
        return True

    try:
        from backend.analysis.storage.store import AnalysisStore
    except ImportError:
        try:
            from analysis.storage.store import AnalysisStore
        except ImportError:
            return True

    try:
        store = AnalysisStore(db_path=db_path)
        return store.claim_delivery(
            delivery_id=clean_id,
            event_type=event_type,
            now_iso=now_iso,
            ttl_seconds=ttl_seconds
        )
    except Exception:
        return True


def release_webhook_delivery(delivery_id: str, db_path: Optional[str] = None) -> bool:
    """
    Releases a claimed webhook delivery ID in case an unhandled error occurs during processing.
    """
    clean_id = str(delivery_id or "").strip()
    if not clean_id or clean_id.lower() in ("none", "unknown"):
        return False

    try:
        from backend.analysis.storage.store import AnalysisStore
    except ImportError:
        try:
            from analysis.storage.store import AnalysisStore
        except ImportError:
            return False

    try:
        store = AnalysisStore(db_path=db_path)
        return store.release_delivery(delivery_id=clean_id)
    except Exception:
        return False


def release_pr_commit_reservation(
    owner: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    db_path: Optional[str] = None
) -> bool:
    """
    Releases an in-progress PR commit reservation if an unhandled error occurs during analysis.
    """
    try:
        from backend.analysis.storage.store import AnalysisStore
    except ImportError:
        try:
            from analysis.storage.store import AnalysisStore
        except ImportError:
            return False

    try:
        store = AnalysisStore(db_path=db_path)
        return store.release_pr_commit_reservation(
            owner=owner,
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha
        )
    except Exception:
        return False

