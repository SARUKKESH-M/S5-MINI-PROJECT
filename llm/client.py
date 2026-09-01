"""LLM Client Abstraction for CodeSentinel.

Delegates execution exclusively to an LLMProvider instance (defaults to MockLLMProvider).
Performs NO HTTP calls or network operations.
"""

from typing import Any, Dict, Optional
from llm.provider import LLMProvider, MockLLMProvider


class LLMClient:
    """Client for invoking CodeSentinel security analysis providers."""

    def __init__(self, provider: Optional[LLMProvider] = None):
        self.provider = provider or MockLLMProvider()

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Delegate analysis call to configured LLMProvider."""
        return self.provider.analyze(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context_input=context_input,
        )
