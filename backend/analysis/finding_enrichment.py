"""Best-effort RAG and offline explanation enrichment for deterministic findings."""

from typing import Any, Dict, List, Optional

from rag.context_builder import build_security_analysis_context
from llm.provider import MockLLMProvider


def enrich_findings(findings: List[Dict[str, Any]], db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Attach RAG provenance without allowing retrieval failure to remove findings."""
    enriched: List[Dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        signal_type = str((item.get("evidence") or [{}])[0].get("signal_type", ""))
        category = {
            "unsafe_database_execution": "sql_injection",
            "command_execution_call": "command_execution",
            "dynamic_code_execution": "dynamic_code_execution",
            "possible_hardcoded_secret": "credential_handling",
            "credential_propagation_to_authorization_sink": "credential_handling",
        }.get(signal_type, "general_security")
        try:
            context = build_security_analysis_context(category, top_k=3, db_path=db_path)
            if context.get("status") == "success" and context.get("security_knowledge_context_count", 0) > 0:
                item["enriched_by"] = ["rag"]
            else:
                item["enriched_by"] = []
        except Exception:
            item["enriched_by"] = []
        enriched.append(item)
    return MockLLMProvider().explain_findings(enriched)
