"""Ollama LLM Provider for CodeSentinel.

Executes security context analysis and finding explanation enrichment via a local
Ollama daemon using standard httpx, structured JSON mode, and zero LangChain dependencies.
"""

import json
import logging
import os
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
            with httpx.Client(timeout=self.timeout) as client:
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
        """Enrich deterministic findings with Ollama-generated explanations and recommendations."""
        if not findings:
            return []

        finding_summaries = []
        for f in findings:
            finding_summaries.append({
                "finding_id": f.get("finding_id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", "unknown"),
                "category": f.get("category", "Security"),
                "description": f.get("description", ""),
            })

        system_msg = (
            "You are a DevSecOps security expert. Review the security finding summaries and provide "
            "a concise technical explanation and practical remediation recommendation for each finding. "
            "Respond ONLY with a JSON object mapping 'explanations': [{\"finding_id\": \"...\", "
            "\"explanation\": \"...\", \"recommendation\": \"...\"}]."
        )
        user_msg = f"Finding Summaries:\n{json.dumps(finding_summaries, indent=2)}"

        clean_sys = sanitize_sensitive_text(system_msg)
        clean_user = sanitize_sensitive_text(user_msg)

        messages = [
            {"role": "system", "content": clean_sys},
            {"role": "user", "content": clean_user},
        ]

        resp = self._post_chat(messages)
        explanation_items = resp.get("explanations", [])
        if not isinstance(explanation_items, list):
            explanation_items = []

        exp_map = {item.get("finding_id"): item for item in explanation_items if isinstance(item, dict)}

        enriched: List[Dict[str, Any]] = []
        for f in findings:
            item = dict(f)
            fid = item.get("finding_id")
            matching_exp = exp_map.get(fid)
            if matching_exp:
                if matching_exp.get("explanation"):
                    item["explanation"] = matching_exp["explanation"]
                if matching_exp.get("recommendation"):
                    item["recommendation"] = matching_exp["recommendation"]

            if not item.get("recommendation"):
                item["recommendation"] = "Review this security-sensitive operation and avoid untrusted dynamic input."

            enriched_by = list(item.get("enriched_by", []))
            if "ollama_llm" not in enriched_by:
                enriched_by.append("ollama_llm")
            item["enriched_by"] = enriched_by
            enriched.append(item)

        return enriched
