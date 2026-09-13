"""LLM Provider Interface and Mock Implementation for CodeSentinel.

Provides an abstract LLMProvider base class and a deterministic MockLLMProvider
that executes offline without external network calls, API keys, or code execution.
"""

import os
from typing import Any, Dict, List, Optional, Set


class LLMProviderError(Exception):
    """Base exception for LLM provider execution or communication errors."""
    pass


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

    def explain_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optional hook for Stage 7A finding explanation enrichment."""
        return findings


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
        """Add deterministic structured explanation without creating or removing findings.

        Produces a full structured explanation contract grounded in authoritative
        metadata and curated OWASP/CWE knowledge while maintaining backward-compatible
        explanation and recommendation fields.
        """
        try:
            from llm.explanation_contract import generate_deterministic_fallback_explanation
        except ImportError:
            from explanation_contract import generate_deterministic_fallback_explanation

        explained: List[Dict[str, Any]] = []
        for finding in findings:
            item = dict(finding)
            k_doc = item.get("_retrieved_knowledge_doc")
            if not k_doc and isinstance(item.get("retrieved_knowledge"), list) and item.get("retrieved_knowledge"):
                k_doc = item["retrieved_knowledge"][0]

            structured = generate_deterministic_fallback_explanation(item, knowledge_doc=k_doc)
            structured["provenance"] = "mock_llm"

            item["structured_explanation"] = structured
            item["explanation"] = structured["why_it_matters"]
            item["recommendation"] = structured["remediation"]

            enriched_by = list(item.get("enriched_by", []))
            if "mock_llm" not in enriched_by:
                enriched_by.append("mock_llm")
            item["enriched_by"] = enriched_by
            explained.append(item)
        return explained


def get_llm_provider(
    settings: Optional[Any] = None,
    provider: Optional[LLMProvider] = None,
    force_fallback: bool = False,
) -> LLMProvider:
    """Factory to acquire the configured LLM provider according to project settings.

    Expected order:
      - If Groq API key is configured: Groq -> Ollama -> Mock
      - If Groq API key is unconfigured: Ollama -> Mock
      - In automated test environments (unless force_fallback=True): defaults safely to MockLLMProvider
        to enforce zero external network calls during regression testing.
    """
    if provider is not None:
        return provider

    # Enforce safe offline behavior during automated test runs unless live testing is explicitly requested
    if not force_fallback and os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("CODESENTINEL_TEST_LIVE_PROVIDERS"):
        return MockLLMProvider()

    if settings is None:
        try:
            from backend.app.core.config import settings as app_settings
            settings = app_settings
        except ImportError:
            try:
                from app.core.config import settings as app_settings
                settings = app_settings
            except ImportError:
                settings = None

    groq_key = getattr(settings, "GROQ_API_KEY", None) if settings else os.getenv("GROQ_API_KEY")

    from llm.groq_provider import GroqLLMProvider
    from llm.ollama_provider import OllamaLLMProvider
    from llm.fallback_provider import FallbackLLMProvider

    if groq_key:
        groq_prov = GroqLLMProvider(api_key=groq_key)
        ollama_prov = OllamaLLMProvider()
        return FallbackLLMProvider(providers=[groq_prov, ollama_prov, MockLLMProvider()])

    ollama_prov = OllamaLLMProvider()
    return FallbackLLMProvider(providers=[ollama_prov, MockLLMProvider()])

