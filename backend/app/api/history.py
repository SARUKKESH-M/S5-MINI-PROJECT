"""FastAPI Router for CodeSentinel Analysis History APIs.

Provides REST endpoints to list, retrieve, and delete historical security analysis records
and findings from persistent storage.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel
from backend.analysis.storage.store import AnalysisStore

try:
    from backend.app.core.auth import require_active_user, require_admin_user
    from backend.analysis.storage.models import UserRecord
except ImportError:
    from app.core.auth import require_active_user, require_admin_user
    from analysis.storage.models import UserRecord

router = APIRouter(tags=["Analysis History"])


class FalsePositiveRequest(BaseModel):
    reason: Optional[str] = None
    repository_id: Optional[str] = None
    reason_code: Optional[str] = "FALSE_POSITIVE"
    expires_at: Optional[str] = None


def _get_store() -> AnalysisStore:
    """Helper to obtain default AnalysisStore instance."""
    return AnalysisStore()


def _check_analysis_access(analysis_id: str, current_user: UserRecord, store: AnalysisStore) -> Dict[str, Any]:
    """Retrieve analysis record and enforce that current_user has authorized access.

    Raises:
        HTTPException: HTTP 404 if record is missing, unowned, or belongs to another user.
    """
    record = store.get_analysis(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
        )
    if not current_user.is_admin():
        record_user_id = record.get("user_id")
        if not record_user_id or record_user_id != current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' not found",
            )
    return record


@router.get("/analyses")
def list_analyses_endpoint(
    limit: Optional[int] = Query(20, description="Maximum number of items to return"),
    offset: Optional[int] = Query(0, description="Offset index for pagination"),
    current_user: UserRecord = Depends(require_active_user),
):
    """Retrieve paginated list of historical security analysis summary records."""
    safe_limit = 20 if limit is None or limit <= 0 else min(100, limit)
    safe_offset = 0 if offset is None or offset < 0 else offset

    store = _get_store()
    user_id_filter = None if current_user.is_admin() else current_user.user_id
    analyses = store.list_analyses(limit=safe_limit, offset=safe_offset, user_id=user_id_filter)
    total_count = store.count_analyses(user_id=user_id_filter)

    return {
        "status": "success",
        "analyses": analyses,
        "analysis_count": len(analyses),
        "total_count": total_count,
    }


@router.get("/analyses/{analysis_id}")
def get_analysis_endpoint(
    analysis_id: str,
    current_user: UserRecord = Depends(require_active_user),
):
    """Retrieve a single historical analysis record including full findings."""
    store = _get_store()
    record = _check_analysis_access(analysis_id, current_user, store)
    return {
        "status": "success",
        "analysis": record,
    }


@router.get("/analyses/{analysis_id}/findings")
def get_findings_endpoint(
    analysis_id: str,
    current_user: UserRecord = Depends(require_active_user),
):
    """Retrieve list of findings associated with a specific analysis record."""
    store = _get_store()
    record = _check_analysis_access(analysis_id, current_user, store)
    findings = record.get("findings", [])
    return {
        "status": "success",
        "analysis_id": analysis_id,
        "findings": findings,
        "finding_count": len(findings),
    }


@router.delete("/analyses/{analysis_id}", dependencies=[Depends(require_admin_user)])
def delete_analysis_endpoint(analysis_id: str):
    """Delete a single analysis record and cascade delete its associated findings."""
    store = _get_store()
    success = store.delete_analysis(analysis_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
        )
    return {
        "status": "success",
        "analysis_id": analysis_id,
        "deleted": True,
    }


@router.post("/analyses/{analysis_id}/findings/{finding_id}/false-positive")
def mark_false_positive_endpoint(
    analysis_id: str,
    finding_id: str,
    payload: Optional[FalsePositiveRequest] = None,
    current_user: UserRecord = Depends(require_active_user),
):
    """Mark a finding as false positive in persistent storage (idempotent)."""
    store = _get_store()
    _check_analysis_access(analysis_id, current_user, store)

    if not store.finding_exists_for_analysis(analysis_id, finding_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in analysis '{analysis_id}'",
        )

    reason = payload.reason if payload else None
    repo_id = payload.repository_id if payload else None
    reason_code = payload.reason_code if payload and payload.reason_code else "FALSE_POSITIVE"
    expires_at = payload.expires_at if payload else None

    try:
        suppression = store.record_false_positive(
            analysis_id=analysis_id,
            finding_id=finding_id,
            reason=reason,
            repository_id=repo_id,
            reason_code=reason_code,
            expires_at=expires_at,
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )

    if not suppression:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in analysis '{analysis_id}'",
        )

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "finding_id": finding_id,
        "suppression": suppression,
    }


@router.get("/analyses/{analysis_id}/findings/{finding_id}/feedback")
def get_finding_feedback_endpoint(
    analysis_id: str,
    finding_id: str,
    current_user: UserRecord = Depends(require_active_user),
):
    """Retrieve false-positive feedback record for a specific finding."""
    store = _get_store()
    _check_analysis_access(analysis_id, current_user, store)

    if not store.finding_exists_for_analysis(analysis_id, finding_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in analysis '{analysis_id}'",
        )

    feedback = store.get_false_positive(analysis_id=analysis_id, finding_id=finding_id)
    is_fp = False
    is_exp = False
    if feedback and feedback.get("status") == "ACTIVE":
        from backend.analysis.storage.store import is_suppression_active
        exp_ts = feedback.get("expires_at")
        is_fp = is_suppression_active("ACTIVE", exp_ts)
        if exp_ts and not is_fp:
            is_exp = True
        feedback["is_expired"] = is_exp

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "finding_id": finding_id,
        "feedback": feedback,
        "is_false_positive": is_fp,
    }


@router.delete("/analyses/{analysis_id}/findings/{finding_id}/false-positive")
@router.post("/analyses/{analysis_id}/findings/{finding_id}/revoke-false-positive")
def revoke_false_positive_endpoint(
    analysis_id: str,
    finding_id: str,
    current_user: UserRecord = Depends(require_active_user),
):
    """Revoke false-positive feedback for a finding without deleting historical audit trail."""
    store = _get_store()
    _check_analysis_access(analysis_id, current_user, store)

    if not store.finding_exists_for_analysis(analysis_id, finding_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in analysis '{analysis_id}'",
        )

    suppression = store.revoke_false_positive(analysis_id=analysis_id, finding_id=finding_id)
    if not suppression:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"False-positive feedback for finding '{finding_id}' not found",
        )

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "finding_id": finding_id,
        "revoked": True,
        "suppression": suppression,
    }
