"""
FastAPI Router for CodeSentinel Repository Security Analysis API Endpoint.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

try:
    from backend.analysis.repository_orchestrator import analyze_repository
    from backend.analysis.storage.store import AnalysisStore
    from backend.analysis.report_service import build_repository_report
    from backend.app.core.auth import require_active_user
    from backend.analysis.storage.models import UserRecord
except ImportError:
    from analysis.repository_orchestrator import analyze_repository
    from analysis.storage.store import AnalysisStore
    from analysis.report_service import build_repository_report
    from app.core.auth import require_active_user
    from analysis.storage.models import UserRecord

router = APIRouter(tags=["Repository Analysis"])


def _get_store() -> AnalysisStore:
    """Helper to obtain default AnalysisStore instance."""
    return AnalysisStore()


class RepositoryAnalysisRequest(BaseModel):
    """Pydantic request schema for POST /repository/analyze."""
    acquisition_id: str
    query: Optional[str] = "security analysis"


@router.post("/repository/analyze")
def repository_analyze_endpoint(
    request: RepositoryAnalysisRequest,
    current_user: UserRecord = Depends(require_active_user),
):
    """
    Executes repository-level static security analysis pipeline.
    Returns sanitized summary, repository info, and structured findings.
    Strictly excludes raw source code.
    """
    if not request.acquisition_id or not isinstance(request.acquisition_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="acquisition_id is required and must be a string"
        )

    try:
        res = analyze_repository(
            acquisition_id=request.acquisition_id,
            query=request.query or "security analysis",
            user_id=current_user.user_id if current_user else None,
        )
        return res
    except ValueError as ve:
        err_msg = str(ve)
        if "exceeds limit" in err_msg or "Path traversal" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=err_msg
            )
        elif "not found" in err_msg or "missing" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err_msg
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err_msg
            )
    except RuntimeError as re:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(re)
        )


@router.get("/repository/reports/{analysis_id}")
def get_repository_report_endpoint(
    analysis_id: str,
    current_user: UserRecord = Depends(require_active_user),
):
    """
    Retrieves the complete production security report contract for a repository analysis ID.
    Returns 404 for missing records and 400 for malformed IDs.
    """
    clean_id = (analysis_id or "").strip()
    if not clean_id or len(clean_id) < 3 or " " in clean_id or ".." in clean_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or malformed analysis_id '{analysis_id}'"
        )

    store = _get_store()
    record = store.get_analysis(clean_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{clean_id}' not found"
        )

    if not current_user.is_admin():
        record_user_id = record.get("user_id")
        if not record_user_id or record_user_id != current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{clean_id}' not found"
            )

    try:
        report = build_repository_report(record)
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to format repository report: {str(e)}"
        )

