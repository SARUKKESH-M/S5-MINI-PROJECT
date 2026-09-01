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
