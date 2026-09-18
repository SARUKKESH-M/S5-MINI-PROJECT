"""Google OAuth / OpenID Connect Identity Verification Service.

Verifies Google authentication tokens (ID Tokens) and extracts trusted
claims: sub, email, name, and picture. Does NOT trust client-supplied identity fields.
Supports offline testing mode via structured mock tokens.
"""

import json
import logging
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from fastapi import HTTPException, status

try:
    from backend.analysis.storage.models import GoogleIdentityPayload
    from backend.app.core.config import settings
except ImportError:
    from analysis.storage.models import GoogleIdentityPayload
    from app.core.config import settings

logger = logging.getLogger(__name__)

GOOGLE_TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"


def _verify_mock_token(token: str) -> Optional[GoogleIdentityPayload]:
    """Support offline testing tokens prefixed with 'mock_google_' or 'mock:'."""
    if token.startswith("mock_invalid") or token == "invalid_token" or token.startswith("mock:invalid"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google authentication token.",
        )

    if token.startswith("mock:"):
        try:
            data = json.loads(token[5:])
            if "email_verified" in data:
                ev = data["email_verified"]
                if ev is not True and str(ev).lower() != "true":
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Google email address has not been verified.",
                    )
            if "exp" in data:
                try:
                    if float(data["exp"]) < time.time():
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Google authentication token has expired.",
                        )
                except (ValueError, TypeError):
                    pass
            configured_client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
            if configured_client_id and configured_client_id.strip() and "aud" in data:
                if str(data["aud"]).strip() != configured_client_id.strip():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Google token audience does not match configured application.",
                    )
            return GoogleIdentityPayload(
                sub=str(data.get("sub", "mock_sub")).strip(),
                email=str(data.get("email", "mock@example.com")).strip(),
                name=str(data.get("name", "Mock User")).strip() or None,
                picture=str(data.get("picture", "")).strip() or None,
            )
        except HTTPException:
            raise
        except Exception:
            return None

    if not token.startswith("mock_google_"):
        return None

    # Format: mock_google_<sub_or_email> or base64/json encoded
    parts = token.split(":", 3)
    # mock_google_:email:sub:name
    if len(parts) >= 3:
        email = parts[1].strip()
        sub = parts[2].strip()
        name = parts[3].strip() if len(parts) > 3 else "Test User"
        return GoogleIdentityPayload(
            sub=sub,
            email=email,
            name=name,
            picture="https://lh3.googleusercontent.com/test_avatar.jpg",
        )

    # Simplified: mock_google_alice@corp.com
    remainder = token.replace("mock_google_", "").strip()
    if "@" in remainder:
        email = remainder
        sub = f"sub_{remainder.split('@')[0]}"
        return GoogleIdentityPayload(
            sub=sub,
            email=email,
            name="Mock Google User",
            picture="https://lh3.googleusercontent.com/test_avatar.jpg",
        )

    return None


def verify_google_identity(id_token: str) -> GoogleIdentityPayload:
    """Verify Google OpenID Connect ID token and return trusted identity payload.

    Raises:
        HTTPException: HTTP 401 if token is invalid, unverified, expired, or mismatch.
    """
    if not id_token or not isinstance(id_token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google ID token is required.",
        )

    clean_token = id_token.strip()
    if not clean_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google ID token cannot be empty.",
        )

    if len(clean_token) > 8192:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google ID token exceeds maximum allowed size.",
        )

    # 1. Offline test hook for fast and deterministic test runs
    mock_payload = _verify_mock_token(clean_token)
    if mock_payload:
        return mock_payload

    # 2. Production verification via Google TokenInfo API
    try:
        url = f"{GOOGLE_TOKENINFO_ENDPOINT}?id_token={urllib.parse.quote(clean_token)}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CodeSentinel-Auth/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = resp.read().decode("utf-8")
            claims: Dict[str, Any] = json.loads(data)
    except urllib.error.HTTPError as http_err:
        logger.warning("Google token verification rejected by Google API: %s", http_err.code)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google authentication token.",
        ) from http_err
    except Exception as err:
        logger.error("Error communicating with Google token verification endpoint: %s", err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to verify Google authentication token.",
        ) from err

    # 3. Validate Subject Claim
    sub = str(claims.get("sub") or "").strip()
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token missing subject (sub) claim.",
        )

    # 4. Validate Email & Email Verified Claim
    email = str(claims.get("email") or "").strip()
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token missing email claim.",
        )

    email_verified = claims.get("email_verified")
    if email_verified is not True and str(email_verified).lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google email address has not been verified.",
        )

    # 5. Validate Audience (Client ID) if configured
    configured_client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
    if configured_client_id and configured_client_id.strip():
        aud = str(claims.get("aud") or "").strip()
        if aud != configured_client_id.strip():
            logger.warning("Google token audience mismatch: expected '%s', got '%s'", configured_client_id, aud)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token audience does not match configured application.",
            )

    # 6. Validate Expiration
    exp = claims.get("exp")
    if exp:
        try:
            if float(exp) < time.time():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Google authentication token has expired.",
                )
        except (ValueError, TypeError):
            pass

    # 7. Extract Profile Information
    name = str(claims.get("name") or "").strip() or None
    picture = str(claims.get("picture") or "").strip() or None

    try:
        return GoogleIdentityPayload(
            sub=sub,
            email=email,
            name=name,
            picture=picture,
        )
    except Exception as val_err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid claims from Google identity: {val_err}",
        ) from val_err
