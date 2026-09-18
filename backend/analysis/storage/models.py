"""Analysis Storage Models and Formatting Helpers for CodeSentinel.

Ensures persistent records strictly adhere to Step 6H finding schema and schema_version '1.0'.
Explicitly excludes raw source code, raw source fields, and raw secrets.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, field_validator

ANALYSIS_SCHEMA_VERSION = "1.0"

PROHIBITED_SOURCE_FIELDS = {
    "source_code",
    "raw_source",
    "full_source",
    "original_source",
    "raw_code",
    "code",
}


def get_utc_now_iso() -> str:
    """Return current ISO 8601 formatted UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def validate_utc_iso_timestamp(timestamp_str: Optional[str], must_be_future: bool = True) -> Optional[str]:
    """Validate that a string is a valid ISO 8601 UTC timestamp and optionally strictly in the future.

    Returns normalized ISO 8601 UTC string or raises ValueError.
    """
    if not timestamp_str:
        return None

    val = str(timestamp_str).strip()
    if not val:
        return None

    try:
        # Normalize Z to +00:00 for fromisoformat compatibility in all Python 3.10+
        norm_ts = val.replace("Z", "+00:00")
        dt = datetime.fromisoformat(norm_ts)
    except Exception as e:
        raise ValueError(f"Invalid ISO 8601 timestamp format: '{val}'") from e

    # Require timezone awareness
    if dt.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware (preferably UTC).")

    # Convert to UTC
    dt_utc = dt.astimezone(timezone.utc)

    if must_be_future:
        now_utc = datetime.now(timezone.utc)
        if dt_utc <= now_utc:
            raise ValueError("Expiration timestamp must be strictly later than current server UTC time.")

    return dt_utc.isoformat()


def create_analysis_record(
    analysis_id: str,
    status: str,
    query: str,
    summary: Dict[str, Any],
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a standardized analysis summary record for persistent storage.

    Excludes raw source code, raw source fields, and raw secrets.
    """
    total_findings = summary.get("total_findings", 0) if isinstance(summary, dict) else 0
    return {
        "analysis_id": str(analysis_id),
        "status": str(status),
        "query": str(query),
        "created_at": created_at or get_utc_now_iso(),
        "finding_count": total_findings,
        "summary": summary if isinstance(summary, dict) else {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
        "schema_version": ANALYSIS_SCHEMA_VERSION,
    }


def sanitize_finding_record(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize finding object to preserve exact Step 6H finding contract."""
    if not isinstance(finding, dict):
        return {}

    evidence_list = []
    raw_ev = finding.get("evidence", [])
    if isinstance(raw_ev, list):
        for ev in raw_ev:
            if isinstance(ev, dict):
                ev_item = {
                    "document_id": str(ev.get("document_id", "")),
                    "line_start": ev.get("line_start") if isinstance(ev.get("line_start"), int) else None,
                    "line_end": ev.get("line_end") if isinstance(ev.get("line_end"), int) else None,
                    "signal_type": str(ev.get("signal_type", "unknown")),
                    "signal_name": str(ev.get("signal_name", "unknown")),
                }
                if "scope" in ev:
                    ev_item["scope"] = ev["scope"]
                if "call_name" in ev:
                    ev_item["call_name"] = ev["call_name"]
                if "occurrence_index" in ev:
                    ev_item["occurrence_index"] = ev["occurrence_index"]
                evidence_list.append(ev_item)

    return {
        "finding_id": str(finding.get("finding_id", "")),
        "title": str(finding.get("title", "Security Finding")),
        "description": str(finding.get("description", "")),
        "severity": str(finding.get("severity", "unknown")).lower(),
        "confidence": str(finding.get("confidence", "low")).lower(),
        "category": str(finding.get("category", "General Security")),
        "evidence": evidence_list,
    }


VALID_REASON_CODES = {
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "TEST_OR_MOCK",
    "EXTERNAL_SANITIZATION",
    "OTHER",
}

REASON_CODES_REQUIRING_COMMENT = {
    "ACCEPTED_RISK",
    "EXTERNAL_SANITIZATION",
    "OTHER",
}


def validate_reason_payload(reason_code: Optional[str], reason: Optional[str]) -> Tuple[str, str]:
    """Validate and normalize reason code and comment according to Phase 31 taxonomy.

    Raises:
        ValueError: If reason_code is unrecognized or required comment is missing/invalid.
    """
    code = str(reason_code or "FALSE_POSITIVE").strip()
    if code not in VALID_REASON_CODES:
        raise ValueError(f"Invalid reason_code '{code}'. Must be one of: {sorted(VALID_REASON_CODES)}")

    comment = str(reason or "").strip()
    if len(comment) > 1000:
        raise ValueError("Reason comment exceeds maximum allowed length of 1000 characters.")

    if code in REASON_CODES_REQUIRING_COMMENT:
        if len(comment) < 5:
            raise ValueError(f"Reason code '{code}' requires an explanatory comment of at least 5 non-whitespace characters.")

    return code, comment


def create_suppression_record(
    suppression_id: str,
    analysis_id: str,
    finding_id: str,
    repository_id: str,
    finding_fingerprint: str,
    rule_signal: str,
    file_path: str,
    cwe_id: Optional[str] = None,
    line_number: Optional[int] = None,
    status: str = "ACTIVE",
    reason: Optional[str] = None,
    created_at: Optional[str] = None,
    updated_at: Optional[str] = None,
    fingerprint_version: int = 1,
    finding_fingerprint_v2: Optional[str] = None,
    reason_code: str = "FALSE_POSITIVE",
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a standardized false-positive suppression audit record."""
    now = get_utc_now_iso()
    return {
        "suppression_id": str(suppression_id),
        "analysis_id": str(analysis_id),
        "finding_id": str(finding_id),
        "repository_id": str(repository_id),
        "finding_fingerprint": str(finding_fingerprint),
        "cwe_id": str(cwe_id) if cwe_id else None,
        "rule_signal": str(rule_signal),
        "file_path": str(file_path),
        "line_number": int(line_number) if line_number is not None else None,
        "status": str(status).upper(),
        "reason": str(reason).strip() if reason else "",
        "created_at": created_at or now,
        "updated_at": updated_at or now,
        "fingerprint_version": int(fingerprint_version),
        "finding_fingerprint_v2": str(finding_fingerprint_v2) if finding_fingerprint_v2 else None,
        "reason_code": str(reason_code).strip() if reason_code else "FALSE_POSITIVE",
        "expires_at": str(expires_at).strip() if expires_at else None,
    }


# ============================================================================
# Phase 32: Security Analytics V2 Contracts and Time-Window Helpers
# ============================================================================

VALID_TIME_WINDOWS = {"7d", "30d", "90d", "all"}
DEFAULT_TIME_WINDOW = "30d"


def parse_time_window(
    time_window: Optional[str] = DEFAULT_TIME_WINDOW,
    default: str = DEFAULT_TIME_WINDOW,
) -> Tuple[str, Optional[str]]:
    """Validate and resolve time window into (normalized_window, utc_cutoff_iso_or_none).

    Supported windows: '7d', '30d', '90d', 'all'.
    Defaults to '30d'.
    Returns:
        (window_name, cutoff_timestamp_iso) where cutoff_timestamp_iso is None for 'all'.
    Raises:
        ValueError: If time_window is invalid.
    """
    raw = str(time_window if time_window is not None else default).strip().lower()
    if not raw:
        raw = default

    if raw not in VALID_TIME_WINDOWS:
        raise ValueError(
            f"Invalid time_window '{raw}'. Supported values: {sorted(list(VALID_TIME_WINDOWS))}."
        )

    if raw == "all":
        return "all", None

    days_map = {"7d": 7, "30d": 30, "90d": 90}
    days = days_map[raw]
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return raw, cutoff.isoformat()


# ============================================================================
# Phase 33B: Webhook Idempotency Contracts
# ============================================================================
DEFAULT_DELIVERY_TTL_SECONDS = 86400  # 24 hours


# ============================================================================
# Phase 33C: Commit-Level Analysis Idempotency & PR Persistence Contracts
# ============================================================================
DEFAULT_COMMIT_RESERVATION_TTL_SECONDS = 300  # 5 minutes bounded recovery


# ============================================================================
# Phase A3: User & Access-Control Storage Models
# ============================================================================

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"


class UserStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


def normalize_email(email: Optional[str]) -> str:
    """Normalize email address to lowercase and trimmed string.
    
    Raises:
        ValueError: If email is empty, not a string, or contains invalid characters.
    """
    if not email or not isinstance(email, str):
        raise ValueError("Email address must be a non-empty string.")
    cleaned = email.strip().lower()
    if not cleaned or "@" not in cleaned or cleaned.startswith("@") or cleaned.endswith("@"):
        raise ValueError(f"Invalid email address format: '{email}'")
    return cleaned


@dataclass(frozen=True)
class UserRecord:
    """Internal immutable storage representation of a CodeSentinel user."""
    user_id: str
    google_sub: Optional[str]
    email: str
    full_name: Optional[str]
    profile_picture: Optional[str]
    role: str
    status: str
    created_at: str
    updated_at: str
    last_login: Optional[str] = None
    created_by: Optional[str] = None

    def is_active(self) -> bool:
        """Return True if account is in ACTIVE status."""
        return self.status == UserStatus.ACTIVE.value

    def is_admin(self) -> bool:
        """Return True if account has ADMIN role."""
        return self.role == UserRole.ADMIN.value


# ============================================================================
# Phase A3 & A4: Pydantic Validation & API Schemas
# ============================================================================

class GoogleIdentityPayload(BaseModel):
    """Verified identity claims received from Google OpenID Connect."""
    sub: str = Field(..., description="Google unique subject identifier")
    email: str = Field(..., description="User primary Google email")
    name: Optional[str] = Field(None, description="User full name from Google profile")
    picture: Optional[str] = Field(None, description="Profile picture avatar URL")

    @field_validator("email")
    @classmethod
    def validate_and_normalize_email(cls, v: str) -> str:
        return normalize_email(v)


class UserPublicResponse(BaseModel):
    """Public representation of an authenticated user for UI/session state."""
    user_id: str
    email: str
    full_name: Optional[str] = None
    profile_picture: Optional[str] = None
    role: str
    status: str
    created_at: str
    last_login: Optional[str] = None


class UserPreAuthorizeRequest(BaseModel):
    """Payload for Admin pre-authorizing an email address."""
    email: str = Field(..., description="Corporate or personal Google email to authorize")
    role: str = Field(default=UserRole.USER.value, description="Initial assigned role")
    full_name: Optional[str] = Field(None, description="Optional anticipated display name")

    @field_validator("email")
    @classmethod
    def validate_and_normalize_email(cls, v: str) -> str:
        return normalize_email(v)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        clean = str(v).strip().upper()
        if clean not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role '{v}'. Must be ADMIN or USER.")
        return clean


class UserStatusUpdateRequest(BaseModel):
    """Payload for activating or disabling an account."""
    status: str = Field(..., description="New operational account status")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        clean = str(v).strip().upper()
        if clean not in (UserStatus.ACTIVE.value, UserStatus.DISABLED.value):
            raise ValueError(f"Invalid status '{v}'. Must be ACTIVE or DISABLED.")
        return clean


class UserRoleUpdateRequest(BaseModel):
    """Payload for promoting or demoting an account."""
    role: str = Field(..., description="New assigned role")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        clean = str(v).strip().upper()
        if clean not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role '{v}'. Must be ADMIN or USER.")
        return clean


class UserAdminDetailResponse(BaseModel):
    """Detailed user view for Admin user management dashboard."""
    user_id: str
    google_sub: Optional[str] = None
    email: str
    full_name: Optional[str] = None
    profile_picture: Optional[str] = None
    role: str
    status: str
    created_at: str
    updated_at: str
    last_login: Optional[str] = None
    created_by: Optional[str] = None


class UserListResponse(BaseModel):
    """Paginated user listing for Admin workspace."""
    users: List[UserAdminDetailResponse]
    total_count: int


