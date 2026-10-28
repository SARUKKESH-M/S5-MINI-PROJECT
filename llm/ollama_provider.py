"""Ollama LLM Provider for CodeSentinel.

Executes security context analysis and finding explanation enrichment via a local
Ollama daemon using standard httpx, structured JSON mode, and zero LangChain dependencies.
"""

import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx
from llm.provider import LLMProvider, LLMProviderError, LLMConnectionError

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


_COOLDOWN_LOCK = threading.Lock()
_LAST_CONNECT_FAILURE: float = 0.0
DEFAULT_COOLDOWN_SECONDS: float = 30.0


class OllamaLLMProvider(LLMProvider):
    """Local Ollama HTTP API provider for CodeSentinel security analysis and fallback."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        connect_timeout: Optional[float] = None,
        cooldown_seconds: Optional[float] = None,
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

        if timeout is None:
            try:
                from backend.app.core.config import settings
                timeout = float(getattr(settings, "OLLAMA_TIMEOUT", 20.0))
            except (ImportError, TypeError, ValueError):
                timeout = float(os.getenv("OLLAMA_TIMEOUT", "20.0"))

        if connect_timeout is None:
            try:
                from backend.app.core.config import settings
                connect_timeout = float(getattr(settings, "OLLAMA_CONNECT_TIMEOUT", 1.0))
            except (ImportError, TypeError, ValueError):
                connect_timeout = float(os.getenv("OLLAMA_CONNECT_TIMEOUT", "1.0"))

        if cooldown_seconds is None:
            try:
                from backend.app.core.config import settings
                cooldown_seconds = float(getattr(settings, "OLLAMA_COOLDOWN_SECONDS", 30.0))
            except (ImportError, TypeError, ValueError):
                cooldown_seconds = float(os.getenv("OLLAMA_COOLDOWN_SECONDS", "30.0"))

        self.base_url = (base_url or "http://localhost:11434").rstrip("/")
        self.model = model or "codellama"
        self.timeout = float(timeout)
        self.connect_timeout = float(connect_timeout)
        self.cooldown_seconds = float(cooldown_seconds)

        self._client: Optional[httpx.Client] = None
        self._lock = threading.Lock()
        self._closed = False

    def _is_in_cooldown(self, now: Optional[float] = None) -> bool:
        """Check if Ollama is currently in a failure cooldown window."""
        if self.cooldown_seconds <= 0.0:
            return False
        current = time.monotonic() if now is None else float(now)
        with _COOLDOWN_LOCK:
            return (current - _LAST_CONNECT_FAILURE) < self.cooldown_seconds

    def _record_connect_failure(self, now: Optional[float] = None) -> None:
        """Record connection failure timestamp to trigger subsequent fast-fail cooldown."""
        global _LAST_CONNECT_FAILURE
        if self.cooldown_seconds <= 0.0:
            return
        current = time.monotonic() if now is None else float(now)
        with _COOLDOWN_LOCK:
            _LAST_CONNECT_FAILURE = current

    @classmethod
    def reset_cooldown(cls) -> None:
        """Reset the failure cooldown timestamp across all instances."""
        global _LAST_CONNECT_FAILURE
        with _COOLDOWN_LOCK:
            _LAST_CONNECT_FAILURE = 0.0

    def _get_client(self) -> httpx.Client:
        """Lazily initialize or return the thread-safe reusable httpx.Client."""
        with self._lock:
            if self._closed:
                raise LLMProviderError("OllamaLLMProvider instance has been closed.")
            if self._client is None or self._client.is_closed:
                timeout_config = httpx.Timeout(self.timeout, connect=self.connect_timeout)
                self._client = httpx.Client(timeout=timeout_config)
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
        if self._is_in_cooldown():
            raise LLMConnectionError(f"Ollama daemon at {self.base_url} is unavailable (in failure cooldown).")

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

        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            self._record_connect_failure()
            raise LLMConnectionError(f"Ollama connection refused at {self.base_url}: {exc}") from exc
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

        if self._is_in_cooldown():
            raise LLMConnectionError(f"Ollama daemon at {self.base_url} is unavailable (in failure cooldown).")

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
            except LLMConnectionError:
                # Connection failures to the daemon must propagate immediately to allow FallbackLLMProvider to switch
                raise
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

            # Accurately record provenance: never falsely label deterministic fallback as ollama_llm
            enriched_by = list(item.get("enriched_by", []))
            prov = structured.get("provenance", "")
            if prov == "ollama":
                if "ollama_llm" not in enriched_by:
                    enriched_by.append("ollama_llm")
            else:
                if "ollama_llm" in enriched_by:
                    enriched_by.remove("ollama_llm")
                if "deterministic_fallback" not in enriched_by:
                    enriched_by.append("deterministic_fallback")
            item["enriched_by"] = enriched_by
            enriched.append(item)

        return enriched
