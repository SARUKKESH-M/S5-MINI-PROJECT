"""
FastAPI Router for CodeSentinel Repository Intake API Endpoint.
"""

import os
from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

try:
    from backend.repository.service import prepare_repository_for_analysis
    from backend.repository.acquirer import acquire_repository
except ImportError:
    from repository.service import prepare_repository_for_analysis
    from repository.acquirer import acquire_repository

router = APIRouter(tags=["Repository Intake"])


class RepositoryIntakeRequest(BaseModel):
    """Pydantic request schema for POST /repository/intake."""
    repository_url: str
    branch: Optional[str] = "main"
    path: Optional[str] = ""
    local_path: Optional[str] = None


class RepositoryAcquireRequest(BaseModel):
    """Pydantic request schema for POST /repository/acquire."""
    repository_url: str
    branch: Optional[str] = "main"
    path: Optional[str] = ""
    local_path: Optional[str] = None


@router.post("/repository/intake")
def repository_intake_endpoint(request: RepositoryIntakeRequest):
    """
    Validates GitHub repository URL reference and processes local repository intake.
    Returns public metadata only. Strictly excludes raw source code.
    """
    if not request.repository_url or not isinstance(request.repository_url, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="repository_url is required and must be a string"
        )

    # Determine local repository directory to inspect
    target_local_path = request.local_path
    if not target_local_path:
        # Default to current workspace directory if no local_path provided
        target_local_path = os.getcwd()

    try:
        res = prepare_repository_for_analysis(
            repository_path=target_local_path,
            repository_url=request.repository_url,
            branch=request.branch or "main",
            path=request.path or ""
        )
        # Return public metadata only (excluding raw source code)
        return res["public_metadata"]
    except ValueError as ve:
        err_msg = str(ve)
        if "exceeds maximum allowed" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=err_msg
            )
        elif "does not exist" in err_msg or "not found" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err_msg
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err_msg
            )


@router.post("/repository/acquire")
def repository_acquire_endpoint(request: RepositoryAcquireRequest):
    """
    Validates repository input and performs controlled repository acquisition.
    Returns public acquisition metadata only. Strictly excludes raw source code.
    """
    if not request.repository_url or not isinstance(request.repository_url, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="repository_url is required and must be a string"
        )

    try:
        metadata = acquire_repository(
            repository_url=request.repository_url,
            branch=request.branch or "main",
            path=request.path or "",
            local_path=request.local_path
        )
        return metadata
    except ValueError as ve:
        err_msg = str(ve)
        if "exceeds limit" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=err_msg
            )
        elif "does not exist" in err_msg or "not found" in err_msg:
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

