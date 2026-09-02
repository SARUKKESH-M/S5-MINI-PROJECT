"""
CodeSentinel — Step 6T-5: Analysis Traceability & Metadata Engine

Generates structured internal execution metadata for security analysis runs.
Maintains full backward compatibility with the Step 6O Production Report schema
by encapsulating metadata safely.
"""

import time
from typing import Any, Dict, Optional


def build_analysis_traceability_metadata(
    policy_name: str = "default",
    is_incremental: bool = False,
    files_considered: int = 0,
    files_analyzed: int = 0,
    files_excluded: int = 0,
    cache_hits: int = 0,
    cache_misses: int = 0,
    duration_ms: float = 0.0,
    extra_meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Builds internal analysis metadata dict for traceability.

    Returns:
        Dictionary containing execution metadata.
    """
    meta: Dict[str, Any] = {
        "policy_profile": policy_name,
        "analysis_mode": "incremental" if is_incremental else "full",
        "files_considered": max(0, int(files_considered)),
        "files_analyzed": max(0, int(files_analyzed)),
        "files_excluded": max(0, int(files_excluded)),
        "cache_hits": max(0, int(cache_hits)),
        "cache_misses": max(0, int(cache_misses)),
        "duration_ms": round(max(0.0, float(duration_ms)), 2),
        "platform_version": "1.0.0",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    if extra_meta and isinstance(extra_meta, dict):
        for k, v in extra_meta.items():
            if k not in meta and isinstance(k, str):
                meta[k] = v

    return meta
