"""
CodeSentinel — Step 6T-9 & 6W-16: Platform Capabilities FastAPI Router

Exposes safe endpoints for health, readiness, release readiness verification,
capabilities/version info, policy profiles, and internal observability metrics.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Any, Dict, List, Optional

try:
    from backend.app.core.health import get_platform_health, get_platform_readiness
    from backend.app.core.capabilities import get_platform_capabilities
    from backend.app.core.metrics import metrics_collector
    from backend.app.core.readiness_verifier import evaluate_platform_release_readiness
    from backend.analysis.policy import list_available_policies, get_policy_profile
except ImportError:
    from app.core.health import get_platform_health, get_platform_readiness
    from app.core.capabilities import get_platform_capabilities
    from app.core.metrics import metrics_collector
    from app.core.readiness_verifier import evaluate_platform_release_readiness
    from analysis.policy import list_available_policies, get_policy_profile

router = APIRouter(prefix="/platform", tags=["Platform & Capabilities"])


@router.get("/health")
def platform_health() -> Dict[str, Any]:
    """Returns platform health check summary."""
    metrics_collector.increment("health_checks_total")
    return get_platform_health()


@router.get("/readiness")
def platform_readiness() -> Dict[str, Any]:
    """Returns platform readiness status."""
    return get_platform_readiness()


@router.get("/readiness/release")
def platform_release_readiness() -> Dict[str, Any]:
    """Returns detailed 6-series release readiness verification payload."""
    return evaluate_platform_release_readiness()


@router.get("/info")
def platform_info() -> Dict[str, Any]:
    """Returns platform version and enabled capabilities."""
    return get_platform_capabilities()


@router.get("/policies")
def platform_policies() -> List[Dict[str, Any]]:
    """Returns list of available security analysis policy profiles."""
    return list_available_policies()


@router.get("/metrics")
def platform_metrics() -> Dict[str, Any]:
    """Returns structured internal observability metrics."""
    return metrics_collector.get_summary()
