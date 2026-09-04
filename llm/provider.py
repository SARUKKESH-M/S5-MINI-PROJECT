"""LLM Provider Interface and Mock Implementation for CodeSentinel.

Provides an abstract LLMProvider base class and a deterministic MockLLMProvider
that executes offline without external network calls, API keys, or code execution.
"""

from typing import Any, Dict, List, Optional, Set


class LLMProvider:
    """Abstract base class for CodeSentinel LLM Security Analysis providers."""

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze security context and return structured findings dictionary."""
        raise NotImplementedError("Subclasses must implement analyze()")


class MockLLMProvider(LLMProvider):
    """Deterministic offline mock LLM provider for testing and safe offline analysis."""

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate deterministic, grounded security findings from Step 6G context input.

        Performs NO network calls, NO code execution, and NO secret exposure.
        All findings reference existing document IDs present in context_input.
        """
        if not isinstance(context_input, dict) or context_input.get("status") != "success":
            return {
                "status": "success",
                "query": "",
                "findings": [],
                "finding_count": 0,
                "provider": "mock",
            }

        query = str(context_input.get("query", ""))
        context = context_input.get("context", {})
        if not isinstance(context, dict):
            context = {}

        sec_evidence = context.get("security_evidence", [])
        code_structure = context.get("code_structure", [])
        sec_knowledge = context.get("security_knowledge", [])

        if not isinstance(sec_evidence, list):
            sec_evidence = []
        if not isinstance(code_structure, list):
            code_structure = []
        if not isinstance(sec_knowledge, list):
            sec_knowledge = []

        findings: List[Dict[str, Any]] = []

        # Analyze AST Security Evidence Signals
        for item in sec_evidence:
            if not isinstance(item, dict):
                continue
            doc_id = str(item.get("document_id", ""))
            meta = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
            signal_type = str(meta.get("signal_type") or item.get("signal_type") or "")
            signal_name = str(meta.get("signal_name") or item.get("signal_name") or "signal")
            line_start = meta.get("line_start")
            line_end = meta.get("line_end")

            evidence_obj = {
                "document_id": doc_id,
                "line_start": line_start if isinstance(line_start, int) else None,
                "line_end": line_end if isinstance(line_end, int) else None,
                "signal_type": signal_type,
                "signal_name": signal_name,
            }

            if signal_type in ("database_execution_call", "string_construction") or "sql" in query.lower():
                findings.append({
                    "title": "Potential SQL Injection Vulnerability",
                    "description": f"AST analysis detected dynamic string construction or database call '{signal_name}' in document '{doc_id}'.",
                    "severity": "high",
                    "confidence": "high",
                    "category": "Injection",
                    "evidence": [evidence_obj],
                })

            elif signal_type == "command_execution_call" or "command" in query.lower():
                findings.append({
                    "title": "Command Injection Risk",
                    "description": f"System command execution call '{signal_name}' detected in document '{doc_id}'.",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "Injection",
                    "evidence": [evidence_obj],
                })

            elif signal_type == "possible_hardcoded_secret" or "secret" in query.lower() or "api_key" in query.lower():
                findings.append({
                    "title": "Possible Hardcoded Secret Detected",
                    "description": f"Variable assignment matching secret keywords detected in document '{doc_id}'.",
                    "severity": "medium",
                    "confidence": "medium",
                    "category": "Credential Management",
                    "evidence": [evidence_obj],
                })

            elif signal_type in ("dynamic_code_execution", "dynamic_execution_call") or "dynamic" in query.lower() or "eval" in query.lower():
                findings.append({
                    "title": "Arbitrary Dynamic Code Execution Risk",
                    "description": f"Dynamic execution function '{signal_name}' invoked in document '{doc_id}'.",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "Code Execution",
                    "evidence": [evidence_obj],
                })

        return {
            "status": "success",
            "query": query,
            "findings": findings,
            "finding_count": len(findings),
            "provider": "mock",
        }

    def explain_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add deterministic explanation provenance without creating or removing findings.

        Stage 7A orchestration uses this method after AST finding generation.  The
        legacy ``analyze`` method remains for the existing public 6H context API.
        """
        explained: List[Dict[str, Any]] = []
        for finding in findings:
            item = dict(finding)
            if not item.get("recommendation"):
                item["recommendation"] = "Review this security-sensitive operation and avoid untrusted dynamic input."
            enriched_by = list(item.get("enriched_by", []))
            if "mock_llm" not in enriched_by:
                enriched_by.append("mock_llm")
            item["enriched_by"] = enriched_by
            explained.append(item)
        return explained
