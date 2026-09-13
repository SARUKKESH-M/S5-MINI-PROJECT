"""FastAPI Router for CodeSentinel Security Analytics V2 APIs.

Exposes server-side read-only aggregation endpoints:
- GET /analytics/summary: Consolidated summary metrics (total analyses, findings, severities, gate statuses, suppressions).
- GET /analytics/vulnerabilities: Category/CWE aggregation with severity breakdown and deterministic ordering.
- GET /analytics/repositories: Multi-repository security risk metrics with bounded limits.
- GET /analytics/suppressions: False-positive suppression metrics with derived expiration and reason taxonomy.

Observational only: Does not mutate findings, taint states, or Step 6O gate decisions.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

try:
    from backend.analysis.storage.store import AnalysisStore
    from backend.analysis.storage.models import DEFAULT_TIME_WINDOW, VALID_TIME_WINDOWS
except ImportError:
    from analysis.storage.store import AnalysisStore
    from analysis.storage.models import DEFAULT_TIME_WINDOW, VALID_TIME_WINDOWS

router = APIRouter(prefix="/analytics", tags=["Security Analytics V2"])


def _get_store() -> AnalysisStore:
    """Helper to obtain default AnalysisStore instance."""
    return AnalysisStore()


@router.get("/summary")
def get_analytics_summary_endpoint(
    time_window: Optional[str] = Query(
        DEFAULT_TIME_WINDOW,
        description=f"Time window filter: {sorted(list(VALID_TIME_WINDOWS))}",
    ),
    repository_id: Optional[str] = Query(
        None,
        description="Optional repository identifier filter (e.g., 'owner/repo')",
    ),
) -> Dict[str, Any]:
    """Retrieve consolidated security analytics summary."""
    store = _get_store()
    try:
        data = store.get_analytics_summary(
            time_window=time_window,
            repository_id=repository_id,
        )
        return {
            "status": "success",
            "data": data,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/vulnerabilities")
def get_vulnerabilities_analytics_endpoint(
    time_window: Optional[str] = Query(
        DEFAULT_TIME_WINDOW,
        description=f"Time window filter: {sorted(list(VALID_TIME_WINDOWS))}",
    ),
    repository_id: Optional[str] = Query(
        None,
        description="Optional repository identifier filter",
    ),
    limit: Optional[int] = Query(
        20,
        ge=1,
        le=100,
        description="Maximum number of vulnerability types to return (1-100)",
    ),
) -> Dict[str, Any]:
    """Retrieve vulnerability/CWE category aggregations with severity breakdown."""
    store = _get_store()
    try:
        vulnerabilities = store.get_vulnerability_analytics(
            time_window=time_window,
            repository_id=repository_id,
            limit=limit or 20,
        )
        return {
            "status": "success",
            "vulnerabilities": vulnerabilities,
            "total_categories": len(vulnerabilities),
            "time_window": time_window or DEFAULT_TIME_WINDOW,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/repositories")
def get_repository_analytics_endpoint(
    time_window: Optional[str] = Query(
        DEFAULT_TIME_WINDOW,
        description=f"Time window filter: {sorted(list(VALID_TIME_WINDOWS))}",
    ),
    limit: Optional[int] = Query(
        20,
        ge=1,
        le=100,
        description="Maximum number of repositories to return (1-100)",
    ),
) -> Dict[str, Any]:
    """Retrieve repository risk metrics and scan counts."""
    store = _get_store()
    try:
        repositories = store.get_repository_analytics(
            time_window=time_window,
            limit=limit or 20,
        )
        return {
            "status": "success",
            "repositories": repositories,
            "total_repositories": len(repositories),
            "time_window": time_window or DEFAULT_TIME_WINDOW,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/suppressions")
def get_suppression_analytics_endpoint(
    time_window: Optional[str] = Query(
        DEFAULT_TIME_WINDOW,
        description=f"Time window filter: {sorted(list(VALID_TIME_WINDOWS))}",
    ),
    repository_id: Optional[str] = Query(
        None,
        description="Optional repository identifier filter",
    ),
) -> Dict[str, Any]:
    """Retrieve false-positive suppression metrics and reason distribution."""
    store = _get_store()
    try:
        suppressions = store.get_suppression_analytics(
            time_window=time_window,
            repository_id=repository_id,
        )
        return {
            "status": "success",
            "data": suppressions,
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
