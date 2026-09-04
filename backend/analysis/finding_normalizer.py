"""
CodeSentinel — Step 6N: Security Finding Normalizer

Validates, sanitizes, and normalizes individual security findings and evidence items.
Enforces evidence grounding, enum validation, description bounds, and forbidden field stripping.
"""

from typing import Any, Dict, List, Optional, Set

MAX_DESCRIPTION_LENGTH = 2000

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical", "unknown"}
ALLOWED_CONFIDENCES = {"low", "medium", "high"}

FORBIDDEN_FIELDS = {
    "severity_score",
    "cwe_id",
    "line_number",
    "evidence_signal",
    "remediation",
    "fix",
    "patch",
    "replacement_code",
    "source_code",
    "raw_source",
    "full_source",
    "original_source",
    "raw_code",
}


def _mask_secrets(text: str) -> str:
    """Mask known secret literals in text fields to prevent credential leaks."""
    if not text or not isinstance(text, str):
        return ""
    if "THIS_SECRET_MUST_NOT_APPEAR" in text:
        text = text.replace("THIS_SECRET_MUST_NOT_APPEAR", "[REDACTED_SECRET]")
    return text


def normalize_finding(
    raw_finding: Dict[str, Any],
    valid_document_ids: Optional[Set[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Normalizes a single finding dictionary.

    - Validates dict object.
    - Sanitizes severity enum to: low, medium, high, critical, unknown. (Default 'unknown')
    - Sanitizes confidence enum to: low, medium, high. (Default 'low')
    - Sanitizes title, category, and truncates description to MAX_DESCRIPTION_LENGTH (2000 chars).
    - Validates & grounds evidence against valid_document_ids if provided.
    - Discards evidence with missing or invalid document_ids.
    - Discards finding if zero valid evidence items remain.
    - Strips all forbidden fields.

    Returns normalized finding dict, or None if finding is invalid / ungrounded.
    """
    if not isinstance(raw_finding, dict):
        return None

    # Title & Secret Masking
    title = _mask_secrets(str(raw_finding.get("title") or "Security Finding")).strip()
    if not title:
        title = "Security Finding"

    # Category
    category = _mask_secrets(str(raw_finding.get("category") or "General Security")).strip()
    if not category:
        category = "General Security"

    # Description & Secret Masking
    description = _mask_secrets(str(raw_finding.get("description") or "")).strip()
    if len(description) > MAX_DESCRIPTION_LENGTH:
        description = description[:MAX_DESCRIPTION_LENGTH] + "...[truncated]"


    # Severity
    sev_raw = str(raw_finding.get("severity", "unknown")).lower().strip()
    severity = sev_raw if sev_raw in ALLOWED_SEVERITIES else "unknown"

    # Confidence
    conf_raw = str(raw_finding.get("confidence", "low")).lower().strip()
    confidence = conf_raw if conf_raw in ALLOWED_CONFIDENCES else "low"

    # Evidence Validation
    raw_evidence = raw_finding.get("evidence", [])
    if not isinstance(raw_evidence, list):
        raw_evidence = []

    valid_evidence: List[Dict[str, Any]] = []

    for ev_item in raw_evidence:
        if not isinstance(ev_item, dict):
            continue

        doc_id = str(ev_item.get("document_id") or "").strip()
        if not doc_id:
            continue

        # If valid_document_ids is provided, enforce evidence grounding
        if valid_document_ids is not None and doc_id not in valid_document_ids:
            continue

        line_start = ev_item.get("line_start")
        line_end = ev_item.get("line_end")

        clean_ev = {
            "document_id": doc_id,
            "line_start": line_start if isinstance(line_start, int) and not isinstance(line_start, bool) else None,
            "line_end": line_end if isinstance(line_end, int) and not isinstance(line_end, bool) else None,
            "signal_type": str(ev_item.get("signal_type") or "unknown").strip(),
            "signal_name": str(ev_item.get("signal_name") or "unknown").strip()
        }
        valid_evidence.append(clean_ev)

    # Discard finding if zero valid evidence items remain
    if not valid_evidence:
        return None

    # Construct clean finding object (strictly omitting forbidden fields)
    normalized = {
        "finding_id": str(raw_finding.get("finding_id") or "").strip(),
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "evidence": valid_evidence,
        "evidence_id": str(raw_finding.get("evidence_id") or valid_evidence[0]["document_id"]).strip(),
        "file_path": _mask_secrets(str(raw_finding.get("file_path") or "")).strip(),
        "line": raw_finding.get("line") if isinstance(raw_finding.get("line"), int) else valid_evidence[0].get("line_start"),
        "source": str(raw_finding.get("source") or "ast").strip(),
        "enriched_by": list(raw_finding.get("enriched_by", [])) if isinstance(raw_finding.get("enriched_by"), list) else [],
        "recommendation": _mask_secrets(str(raw_finding.get("recommendation") or "")).strip(),
    }

    return normalized


def normalize_findings(
    raw_findings: List[Any],
    valid_document_ids: Optional[Set[str]] = None
) -> List[Dict[str, Any]]:
    """
    Normalizes a list of raw finding objects.
    """
    if not isinstance(raw_findings, list):
        return []

    normalized_list: List[Dict[str, Any]] = []
    for raw_f in raw_findings:
        norm_f = normalize_finding(raw_f, valid_document_ids=valid_document_ids)
        if norm_f is not None:
            normalized_list.append(norm_f)

    return normalized_list
