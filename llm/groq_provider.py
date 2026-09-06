"""Groq LLM Provider for CodeSentinel.

Executes security context analysis and finding explanation enrichment via Groq's
high-speed cloud inference API using standard httpx, structured JSON mode,
and zero LangChain dependencies.
"""

import json
import logging
import os
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
                with httpx.Client(timeout=self.timeout) as client:
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
        """Enrich deterministic findings with Groq-generated explanations and recommendations."""
        if not findings:
            return []

        if not self.api_key:
            raise LLMProviderError("Groq API key is missing or unconfigured.")

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

        resp = self._post_chat_completion(messages)
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
            if "groq_llm" not in enriched_by:
                enriched_by.append("groq_llm")
            item["enriched_by"] = enriched_by
            enriched.append(item)

        return enriched
