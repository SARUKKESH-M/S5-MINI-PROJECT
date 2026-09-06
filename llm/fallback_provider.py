"""Fallback LLM Provider for CodeSentinel.

Implements an ordered, resilient fallback chain (e.g. Groq -> Ollama -> Mock)
ensuring that provider failures never crash the deterministic security analysis
pipeline or alter authoritative security findings.
"""

import logging
from typing import Any, Dict, List, Optional

from llm.provider import LLMProvider, LLMProviderError, MockLLMProvider

try:
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    from app.core.security import sanitize_sensitive_text

logger = logging.getLogger(__name__)


class FallbackLLMProvider(LLMProvider):
    """Executes a chain of LLM providers in sequence until one succeeds."""

    def __init__(self, providers: Optional[List[LLMProvider]] = None):
        if providers is None:
            from llm.groq_provider import GroqLLMProvider
            from llm.ollama_provider import OllamaLLMProvider
            self.providers: List[LLMProvider] = [
                GroqLLMProvider(),
                OllamaLLMProvider(),
                MockLLMProvider(),
            ]
        else:
            self.providers = list(providers)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Attempt analysis sequentially across configured providers."""
        last_error: Optional[Exception] = None

        for provider in self.providers:
            prov_name = type(provider).__name__
            try:
                result = provider.analyze(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    context_input=context_input,
                )
                return result
            except Exception as exc:
                safe_msg = sanitize_sensitive_text(str(exc))
                logger.info("Provider '%s' failed analysis (%s). Attempting next provider.", prov_name, safe_msg)
                last_error = exc
                continue

        # If every provider in the chain failed, fallback to safe deterministic mock
        logger.warning("All providers in FallbackLLMProvider chain failed. Falling back to offline MockLLMProvider.")
        return MockLLMProvider().analyze(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context_input=context_input,
        )

    def explain_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attempt explanation enrichment sequentially across configured providers."""
        if not findings:
            return []

        for provider in self.providers:
            prov_name = type(provider).__name__
            try:
                return provider.explain_findings(findings)
            except Exception as exc:
                safe_msg = sanitize_sensitive_text(str(exc))
                logger.info("Provider '%s' failed explanation enrichment (%s). Attempting next provider.", prov_name, safe_msg)
                continue

        # Ultimate fallback: deterministic mock explanation provenance
        return MockLLMProvider().explain_findings(findings)
