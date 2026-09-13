"""Ollama LLM Provider for CodeSentinel.

Executes security context analysis and finding explanation enrichment via a local
Ollama daemon using standard httpx, structured JSON mode, and zero LangChain dependencies.
"""

import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx
from llm.provider import LLMProvider, LLMProviderError

try:
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    from app.core.security import sanitize_sensitive_text

logger = logging.getLogger(__name__)

FORBIDDEN_RAW_SOURCE_FIELDS = {
    "source_code",
    "raw_source",
    "full_source",
    "original_source",
    "code",
    "raw_code",
}


def _verify_and_sanitize_context(context_input: Any) -> Any:
    """Recursively strip any lingering raw-source fields before transmission."""
    if isinstance(context_input, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in context_input.items():
            if k in FORBIDDEN_RAW_SOURCE_FIELDS:
                continue
            cleaned[k] = _verify_and_sanitize_context(v)
        return cleaned
    elif isinstance(context_input, list):
        return [_verify_and_sanitize_context(item) for item in context_input]
    return context_input


class OllamaLLMProvider(LLMProvider):
    """Local Ollama HTTP API provider for CodeSentinel security analysis and fallback."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 20.0,
    ):
        if base_url is None:
            try:
                from backend.app.core.config import settings
                base_url = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")
            except ImportError:
                base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

        if model is None:
            try:
                from backend.app.core.config import settings
                model = getattr(settings, "OLLAMA_MODEL", "codellama")
            except ImportError:
                model = os.getenv("OLLAMA_MODEL", "codellama")

        self.base_url = (base_url or "http://localhost:11434").rstrip("/")
        self.model = model or "codellama"
        self.timeout = float(timeout)

        self._client: Optional[httpx.Client] = None
        self._lock = threading.Lock()
        self._closed = False

    def _get_client(self) -> httpx.Client:
        """Lazily initialize or return the thread-safe reusable httpx.Client."""
        with self._lock:
            if self._closed:
                raise LLMProviderError("OllamaLLMProvider instance has been closed.")
            if self._client is None or self._client.is_closed:
                self._client = httpx.Client(timeout=self.timeout)
            return self._client

    def close(self) -> None:
        """Deterministic cleanup of underlying pooled HTTP client."""
        with self._lock:
            self._closed = True
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _post_chat(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Execute HTTP POST to Ollama /api/chat with format=json."""
        endpoint = f"{self.base_url}/api/chat"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0},
        }

        try:
            client = self._get_client()
            resp = client.post(endpoint, json=payload, headers=headers)

            if resp.status_code == 404:
                raise LLMProviderError(f"Ollama model '{self.model}' not found or endpoint missing.")

            if resp.is_error:
                raise LLMProviderError(f"Ollama request failed with HTTP {resp.status_code}.")

            data = resp.json()
            message = data.get("message", {})
            content_str = message.get("content", "")
            if not content_str:
                raise LLMProviderError("Ollama returned empty response message content.")

            # Parse JSON cleanly
            cleaned = content_str.strip()
            if "```" in cleaned:
                parts = cleaned.split("```")
                for part in parts:
                    if part.startswith("json"):
                        cleaned = part[4:].strip()
                        break
                    elif "{" in part:
                        cleaned = part.strip()
                        break
            start_idx = cleaned.find("{")
            end_idx = cleaned.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                cleaned = cleaned[start_idx:end_idx]

            parsed_json = json.loads(cleaned)
            if not isinstance(parsed_json, dict):
                raise LLMProviderError("Ollama output is not a valid JSON dictionary.")

            return parsed_json

        except httpx.ConnectError as exc:
            raise LLMProviderError(f"Ollama connection refused at {self.base_url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise LLMProviderError(f"Ollama request timed out after {self.timeout}s: {exc}") from exc
        except (json.JSONDecodeError, ValueError) as exc:
            raise LLMProviderError(f"Ollama output could not be parsed as JSON: {exc}") from exc
        except LLMProviderError:
            raise
        except Exception as exc:
            raise LLMProviderError(f"Unexpected error communicating with Ollama: {exc}") from exc

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze security context using Ollama and return structured findings dictionary."""
        sanitized_context = _verify_and_sanitize_context(context_input)

        clean_sys = sanitize_sensitive_text(system_prompt)
        clean_user = sanitize_sensitive_text(user_prompt)

        messages = [
            {"role": "system", "content": clean_sys},
            {"role": "user", "content": clean_user},
        ]

        result = self._post_chat(messages)
        result["provider"] = "ollama"
        result["status"] = "success"
        if "findings" not in result or not isinstance(result["findings"], list):
            result["findings"] = []
        result["finding_count"] = len(result["findings"])
        return result

    def explain_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich deterministic findings with Ollama-generated structured explanations."""
        if not findings:
            return []

        try:
            from llm.explanation_contract import (
                validate_and_sanitize_explanation,
                generate_deterministic_fallback_explanation,
            )
            from llm.prompts import EXPLANATION_SYSTEM_PROMPT, build_finding_explanation_prompt
        except ImportError:
            from explanation_contract import (
                validate_and_sanitize_explanation,
                generate_deterministic_fallback_explanation,
            )
            from prompts import EXPLANATION_SYSTEM_PROMPT, build_finding_explanation_prompt

        enriched: List[Dict[str, Any]] = []

        for f in findings:
            item = dict(f)
            orig_title = item.get("title")
            orig_severity = item.get("severity")
            orig_evidence = item.get("evidence")
            orig_finding_id = item.get("finding_id")

            k_doc = item.get("_retrieved_knowledge_doc")
            retrieved_knowledge = item.get("retrieved_knowledge") or ([k_doc] if k_doc else [])

            user_prompt = build_finding_explanation_prompt(item, retrieved_knowledge=retrieved_knowledge)
            clean_sys = sanitize_sensitive_text(EXPLANATION_SYSTEM_PROMPT)
            clean_user = sanitize_sensitive_text(user_prompt)

            messages = [
                {"role": "system", "content": clean_sys},
                {"role": "user", "content": clean_user},
            ]

            try:
                raw_resp = self._post_chat(messages)
                structured = validate_and_sanitize_explanation(raw_resp, item, provenance="ollama")
            except Exception as exc:
                logger.info("Ollama explanation failed for finding '%s' (%s). Using deterministic fallback.", orig_finding_id, exc)
                structured = generate_deterministic_fallback_explanation(item, knowledge_doc=k_doc)
                structured["provenance"] = "deterministic_fallback"

            item["structured_explanation"] = structured
            item["explanation"] = structured["why_it_matters"]
            item["recommendation"] = structured["remediation"]

            # Guarantee authoritative finding immutability
            if orig_title is not None:
                item["title"] = orig_title
            if orig_severity is not None:
                item["severity"] = orig_severity
            if orig_evidence is not None:
                item["evidence"] = orig_evidence
            if orig_finding_id is not None:
                item["finding_id"] = orig_finding_id

            enriched_by = list(item.get("enriched_by", []))
            if "ollama_llm" not in enriched_by:
                enriched_by.append("ollama_llm")
            item["enriched_by"] = enriched_by
            enriched.append(item)

        return enriched
