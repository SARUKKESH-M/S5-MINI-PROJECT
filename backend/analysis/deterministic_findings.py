"""Convert AST security evidence into canonical findings before RAG enrichment."""

from typing import Any, Dict, List

_TITLES = {
    "unsafe_database_execution": "Potential SQL Injection Vulnerability",
    "command_execution_call": "Command Injection Risk",
    "dynamic_code_execution": "Arbitrary Dynamic Code Execution Risk",
    "possible_hardcoded_secret": "Possible Hardcoded Secret Detected",
    "credential_propagation_to_authorization_sink": "Credential Propagation to Authorization Header",
    "path_traversal_call": "Potential Path Traversal / Unsafe File Access",
    "insecure_deserialization_call": "Insecure Deserialization Risk",
    "dom_xss_call": "Cross-Site Scripting (DOM XSS) Vulnerability",
}
_CATEGORIES = {
    "sql_injection": "Injection",
    "command_execution": "Injection",
    "dynamic_code_execution": "Code Execution",
    "credential_management": "Credential Management",
    "credential_handling": "Credential Management",
    "path_traversal": "File Security",
    "insecure_deserialization": "Deserialization",
    "xss": "Cross-Site Scripting",
}


def generate_deterministic_findings(evidence_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Create one grounded finding per actionable AST evidence item."""
    findings: List[Dict[str, Any]] = []
    for evidence in evidence_items:
        signal_type = str(evidence.get("signal_type", ""))
        evidence_id = str(evidence.get("evidence_id", ""))
        if signal_type not in _TITLES or not evidence_id:
            continue
        findings.append({
            "evidence_id": evidence_id, "title": _TITLES[signal_type],
            "description": str(evidence.get("message", "Security-relevant AST evidence detected.")),
            "severity": str(evidence.get("severity", "medium")), "confidence": str(evidence.get("confidence", "medium")),
            "category": _CATEGORIES.get(str(evidence.get("category", "")), "General Security"),
            "file_path": str(evidence.get("file_path", "")), "line": evidence.get("line"), "source": "ast", "enriched_by": [],
            "recommendation": "Review this security-sensitive operation and avoid untrusted dynamic input.",
            "evidence": [{"document_id": evidence_id, "line_start": evidence.get("line"), "line_end": evidence.get("line"),
                          "signal_type": signal_type, "signal_name": str(evidence.get("call_name") or evidence.get("name") or "unknown")}],
        })
    return findings
