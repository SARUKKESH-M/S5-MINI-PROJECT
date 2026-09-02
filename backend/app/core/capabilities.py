"""
CodeSentinel — Step 6T-7: Platform Capabilities & Version Information

Exposes safe platform metadata, API versions, enabled capabilities, policy profiles,
and supported analysis modes.
"""

from typing import Any, Dict, List


def get_platform_capabilities() -> Dict[str, Any]:
    """
    Returns dictionary describing platform capability capabilities and supported features.
    Guaranteed secret-safe and production-ready.
    """
    return {
        "service": "CodeSentinel",
        "version": "1.0.0",
        "api_version": "v1",
        "enabled_capabilities": [
            "static_ast_engine",
            "hybrid_rag_knowledge",
            "llm_security_analysis",
            "github_webhook_integration",
            "ci_cd_automated_scanning",
            "security_gate_enforcement",
            "analysis_policy_profiles",
            "repository_scope_exclusion",
            "incremental_changed_file_analysis",
            "deterministic_analysis_caching",
            "health_and_readiness_diagnostics",
            "structured_observability_metrics"
        ],
        "supported_policy_profiles": ["default", "strict", "ci", "developer"],
        "supported_analysis_modes": ["full", "incremental"],
        "supported_languages": ["python"],
        "security_gate_outcomes": ["ALLOW", "REVIEW", "BLOCK", "INVALID"]
    }
