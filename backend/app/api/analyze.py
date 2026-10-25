"""FastAPI Router for CodeSentinel Security Analysis API Endpoint."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from backend.analysis.orchestrator import analyze_source_code

try:
    from backend.app.core.auth import require_active_user
    from backend.analysis.storage.models import UserRecord
except ImportError:
    from app.core.auth import require_active_user
    from analysis.storage.models import UserRecord

router = APIRouter(tags=["Analysis"])


class AnalysisRequest(BaseModel):
    """Pydantic request schema for POST /analyze."""
    source_code: Optional[str] = ""
    query: Optional[str] = "security analysis"


@router.post("/analyze")
def analyze_endpoint(
    request: AnalysisRequest,
    current_user: UserRecord = Depends(require_active_user),
):
    """Execute complete security analysis pipeline on submitted source code."""
    res = analyze_source_code(
        source_code=request.source_code,
        query=request.query,
        user_id=current_user.user_id if current_user else None,
    )
    if res.get("status") == "error" and "exceeds maximum allowed size limit" in res.get("error_message", ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=res.get("error_message"),
        )
    return res
