"""Groq LLM Provider for CodeSentinel.

Executes security context analysis and finding explanation enrichment via Groq's
high-speed cloud inference API using standard httpx, structured JSON mode,
and zero LangChain dependencies.
"""

import json
import logging
import os
import threading
import time
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
    """Recursively strip any lingering raw-source fields before remote transmission."""
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


class GroqLLMProvider(LLMProvider):
    """Groq Cloud API provider for CodeSentinel security analysis and enrichment."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 15.0,
        max_retries: int = 1,
    ):
        if api_key is None:
            try:
                from backend.app.core.config import settings
                api_key = getattr(settings, "GROQ_API_KEY", None)
            except ImportError:
                api_key = os.getenv("GROQ_API_KEY")

        if model is None:
            try:
                from backend.app.core.config import settings
                model = getattr(settings, "GROQ_MODEL", "llama3-70b-8192")
            except ImportError:
                model = os.getenv("GROQ_MODEL", "llama3-70b-8192")

        self.api_key = api_key or None
        self.model = model or "llama3-70b-8192"
        self.base_url = (base_url or "https://api.groq.com/openai/v1").rstrip("/")
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))

        self._client: Optional[httpx.Client] = None
        self._lock = threading.Lock()
        self._closed = False

    def _get_client(self) -> httpx.Client:
        """Lazily initialize or return the thread-safe reusable httpx.Client."""
        with self._lock:
            if self._closed:
                raise LLMProviderError("GroqLLMProvider instance has been closed.")
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

    def _post_chat_completion(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Execute HTTP POST to Groq chat completions with structured JSON response."""
        if not self.api_key:
            raise LLMProviderError("Groq API key is missing or unconfigured.")

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }

        retries = 0
        while True:
            try:
                client = self._get_client()
                resp = client.post(endpoint, json=payload, headers=headers)

                if resp.status_code == 429:
                    if retries < self.max_retries:
                        retries += 1
                        time.sleep(0.5)
                        continue
                    raise LLMProviderError("Groq rate limit exceeded (HTTP 429).")

                if resp.status_code >= 500:
                    if retries < self.max_retries:
                        retries += 1
                        time.sleep(0.5)
                        continue
                    raise LLMProviderError(f"Groq server error (HTTP {resp.status_code}).")

                if resp.is_error:
                    raise LLMProviderError(f"Groq request failed with HTTP {resp.status_code}.")

                data = resp.json()
                choices = data.get("choices", [])
                if not choices or not isinstance(choices, list):
                    raise LLMProviderError("Groq response contains no choices.")

                content_str = choices[0].get("message", {}).get("content", "")
                if not content_str:
                    raise LLMProviderError("Groq returned empty response content.")

                # Parse JSON content cleanly
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
                    raise LLMProviderError("Groq output is not a valid JSON dictionary.")

                return parsed_json

            except httpx.TimeoutException as exc:
                if retries < self.max_retries:
                    retries += 1
                    time.sleep(0.2)
                    continue
                raise LLMProviderError(f"Groq connection timed out: {exc}") from exc
            except httpx.ConnectError as exc:
                raise LLMProviderError(f"Groq connection failed: {exc}") from exc
            except (json.JSONDecodeError, ValueError) as exc:
                raise LLMProviderError(f"Groq output could not be parsed as JSON: {exc}") from exc
            except LLMProviderError:
                raise
            except Exception as exc:
                raise LLMProviderError(f"Unexpected error communicating with Groq: {exc}") from exc

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        context_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze security context using Groq and return structured findings dictionary."""
        # 1. Enforce zero raw source in context
        sanitized_context = _verify_and_sanitize_context(context_input)

        # 2. Scrub sensitive token literals from prompts before sending
        clean_sys = sanitize_sensitive_text(system_prompt)
        clean_user = sanitize_sensitive_text(user_prompt)

        messages = [
            {"role": "system", "content": clean_sys},
            {"role": "user", "content": clean_user},
        ]

        result = self._post_chat_completion(messages)
        result["provider"] = "groq"
        result["status"] = "success"
        if "findings" not in result or not isinstance(result["findings"], list):
            result["findings"] = []
        result["finding_count"] = len(result["findings"])
        return result

    def explain_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich deterministic findings with Groq-generated structured explanations."""
        if not findings:
            return []

        if not self.api_key:
            raise LLMProviderError("Groq API key is missing or unconfigured.")

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
                raw_resp = self._post_chat_completion(messages)
                structured = validate_and_sanitize_explanation(raw_resp, item, provenance="groq")
            except Exception as exc:
                logger.info("Groq explanation failed for finding '%s' (%s). Using deterministic fallback.", orig_finding_id, exc)
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
            if "groq_llm" not in enriched_by:
                enriched_by.append("groq_llm")
            item["enriched_by"] = enriched_by
            enriched.append(item)

        return enriched
