"""
CodeSentinel — Step 6O: Production Finding / Report Service & Review Contract

Generates, formats, validates, and sanitizes Production Repository Security Reports
and computes automated review status ('allow', 'block', 'review').
"""

from typing import Any, Dict, List, Optional
try:
    from backend.analysis.finding_normalizer import (
        FORBIDDEN_FIELDS,
        MAX_DESCRIPTION_LENGTH,
        _mask_secrets,
    )
except ImportError:
    from analysis.finding_normalizer import (
        FORBIDDEN_FIELDS,
        MAX_DESCRIPTION_LENGTH,
        _mask_secrets,
    )


def compute_review_status(summary: Dict[str, Any]) -> str:
    """
    Computes the automated review status decision based on summary severity counts.

    Rules:
    - 'block': if critical_count > 0 or high_count > 0
    - 'review': if medium_count > 0
    - 'allow': if low_count >= 0, info_count >= 0, and no medium/high/critical findings
    """
    if not isinstance(summary, dict):
        return "allow"

    critical_count = int(summary.get("critical_count", 0))
    high_count = int(summary.get("high_count", 0))
    medium_count = int(summary.get("medium_count", 0))

    if critical_count > 0 or high_count > 0:
        return "block"
    elif medium_count > 0:
        return "review"
    else:
        return "allow"


def build_repository_report(
    analysis_record: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Constructs a production-safe repository security report dictionary adhering
    to the Step 6O Report Contract schema.

    - Computes review_status ('allow', 'block', 'review').
    - Normalizes status ('completed' for successful analyses, 'failed' for failed).
    - Preserves repository metadata (owner, repository, branch, path).
    - Preserves summary severity metrics.
    - Sanitizes findings (preserving deterministic IDs, evidence grounding, forbidden field stripping, secret masking).
    - Omits all raw source code, secrets, internal prompts, and provider internals.
    """
    if not isinstance(analysis_record, dict):
        raise ValueError("Invalid analysis record dictionary")

    raw_status = str(analysis_record.get("status", "success")).lower()
    report_status = raw_status if raw_status in ("success", "completed") else "failed"


    analysis_id = str(analysis_record.get("analysis_id", ""))
    if not analysis_id:
        raise ValueError("Missing analysis_id in analysis record")

    # Extract repository metadata
    raw_repo = analysis_record.get("repository")
    if not isinstance(raw_repo, dict):
        summary_obj = analysis_record.get("summary", {})
        if isinstance(summary_obj, dict) and isinstance(summary_obj.get("repository"), dict):
            raw_repo = summary_obj["repository"]
        else:
            raw_repo = {}

    repository_meta = {
        "owner": str(raw_repo.get("owner", "")),
        "repository": str(raw_repo.get("repository", "")),
        "branch": str(raw_repo.get("branch", "main")),
        "path": str(raw_repo.get("path", "."))
    }

    # Summary metrics
    raw_summary = analysis_record.get("summary", {})
    if not isinstance(raw_summary, dict):
        raw_summary = {}

    summary = {
        "total_files": int(raw_summary.get("total_files", 0)),
        "analyzed_files": int(raw_summary.get("analyzed_files", 0)),
        "skipped_files": int(raw_summary.get("skipped_files", 0)),
        "total_findings": int(raw_summary.get("total_findings", 0)),
        "critical_count": int(raw_summary.get("critical_count", 0)),
        "high_count": int(raw_summary.get("high_count", 0)),
        "medium_count": int(raw_summary.get("medium_count", 0)),
        "low_count": int(raw_summary.get("low_count", 0)),
        "info_count": int(raw_summary.get("info_count", 0))
    }

    # Findings list
    raw_findings = analysis_record.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []

    clean_findings: List[Dict[str, Any]] = []
    for idx, f in enumerate(raw_findings, start=1):
        if not isinstance(f, dict):
            continue

        f_id = str(f.get("finding_id") or f"finding_{idx}")
        title = _mask_secrets(str(f.get("title") or "Security Finding")).strip()
        description = _mask_secrets(str(f.get("description") or "")).strip()

        if len(description) > MAX_DESCRIPTION_LENGTH:
            description = description[:MAX_DESCRIPTION_LENGTH] + "...[truncated]"

        severity = str(f.get("severity", "unknown")).lower().strip()
        confidence = str(f.get("confidence", "low")).lower().strip()
        category = _mask_secrets(str(f.get("category") or "General Security")).strip()

        # Evidence list
        raw_ev = f.get("evidence", [])
        clean_ev: List[Dict[str, Any]] = []
        if isinstance(raw_ev, list):
            for ev_item in raw_ev:
                if isinstance(ev_item, dict) and ev_item.get("document_id"):
                    clean_ev.append({
                        "document_id": str(ev_item["document_id"]),
                        "line_start": ev_item.get("line_start") if isinstance(ev_item.get("line_start"), int) and not isinstance(ev_item.get("line_start"), bool) else None,
                        "line_end": ev_item.get("line_end") if isinstance(ev_item.get("line_end"), int) and not isinstance(ev_item.get("line_end"), bool) else None,
                        "signal_type": str(ev_item.get("signal_type") or "unknown").strip(),
                        "signal_name": str(ev_item.get("signal_name") or "unknown").strip()
                    })

        clean_finding = {
            "finding_id": f_id,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "evidence": clean_ev
        }
        # Explicitly ensure forbidden fields are stripped
        for forbidden in FORBIDDEN_FIELDS:
            clean_finding.pop(forbidden, None)

        clean_findings.append(clean_finding)

    # Ensure summary total_findings matches clean_findings length if out of sync
    if summary["total_findings"] != len(clean_findings):
        summary["total_findings"] = len(clean_findings)

    # Compute review_status decision
    review_status = compute_review_status(summary)

    report = {
        "status": report_status,
        "review_status": review_status,
        "analysis_id": analysis_id,
        "repository": repository_meta,
        "summary": summary,
        "findings": clean_findings,
        "analysis_version": str(analysis_record.get("analysis_version") or "1.0")
    }

    return report
