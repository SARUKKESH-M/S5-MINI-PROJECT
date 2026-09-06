"""FastAPI Router for CodeSentinel Analysis History APIs.

Provides REST endpoints to list, retrieve, and delete historical security analysis records
and findings from persistent storage.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Body, HTTPException, Query, status
from pydantic import BaseModel
from backend.analysis.storage.store import AnalysisStore

router = APIRouter(tags=["Analysis History"])


class FalsePositiveRequest(BaseModel):
    reason: Optional[str] = None
    repository_id: Optional[str] = None


def _get_store() -> AnalysisStore:
    """Helper to obtain default AnalysisStore instance."""
    return AnalysisStore()


@router.get("/analyses")
def list_analyses_endpoint(
    limit: Optional[int] = Query(20, description="Maximum number of items to return"),
    offset: Optional[int] = Query(0, description="Offset index for pagination"),
):
    """Retrieve paginated list of historical security analysis summary records."""
    safe_limit = 20 if limit is None or limit <= 0 else min(100, limit)
    safe_offset = 0 if offset is None or offset < 0 else offset

    store = _get_store()
    analyses = store.list_analyses(limit=safe_limit, offset=safe_offset)
    total_count = store.count_analyses()

    return {
        "status": "success",
        "analyses": analyses,
        "analysis_count": len(analyses),
        "total_count": total_count,
    }


@router.get("/analyses/{analysis_id}")
def get_analysis_endpoint(analysis_id: str):
    """Retrieve a single historical analysis record including full findings."""
    store = _get_store()
    record = store.get_analysis(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
        )
    return {
        "status": "success",
        "analysis": record,
    }


@router.get("/analyses/{analysis_id}/findings")
def get_findings_endpoint(analysis_id: str):
    """Retrieve list of findings associated with a specific analysis record."""
    store = _get_store()
    findings = store.get_findings(analysis_id)
    if findings is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
        )
    return {
        "status": "success",
        "analysis_id": analysis_id,
        "findings": findings,
        "finding_count": len(findings),
    }


@router.delete("/analyses/{analysis_id}")
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
):
    """Mark a finding as false positive in persistent storage (idempotent)."""
    store = _get_store()
    analysis = store.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
        )

    reason = payload.reason if payload else None
    repo_id = payload.repository_id if payload else None

    suppression = store.record_false_positive(
        analysis_id=analysis_id,
        finding_id=finding_id,
        reason=reason,
        repository_id=repo_id,
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
def get_finding_feedback_endpoint(analysis_id: str, finding_id: str):
    """Retrieve false-positive feedback record for a specific finding."""
    store = _get_store()
    analysis = store.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
        )

    feedback = store.get_false_positive(analysis_id=analysis_id, finding_id=finding_id)
    is_fp = feedback is not None and feedback.get("status") == "ACTIVE"

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "finding_id": finding_id,
        "feedback": feedback,
        "is_false_positive": is_fp,
    }


@router.delete("/analyses/{analysis_id}/findings/{finding_id}/false-positive")
@router.post("/analyses/{analysis_id}/findings/{finding_id}/revoke-false-positive")
def revoke_false_positive_endpoint(analysis_id: str, finding_id: str):
    """Revoke false-positive feedback for a finding without deleting historical audit trail."""
    store = _get_store()
    analysis = store.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found",
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
