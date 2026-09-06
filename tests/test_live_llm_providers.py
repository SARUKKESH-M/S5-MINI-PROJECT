"""Verification Test Suite for Live LLM Providers (Groq, Ollama, Fallback).

All 22 required verification test categories:
  1. Groq provider initialization
  2. Missing Groq key
  3. Successful Groq response
  4. Groq timeout
  5. Groq 429
  6. Groq 5xx
  7. Groq malformed JSON
  8. Ollama successful response
  9. Ollama connection failure
 10. Ollama timeout
 11. Groq -> Ollama fallback
 12. Groq -> Ollama -> Mock fallback
 13. Mock provider remains functional
 14. Secrets never appear in transmitted request
 15. Secrets never appear in logs/errors
 16. Raw source is absent from external provider context
 17. Deterministic findings remain unchanged when LLM fails
 18. Security gate result remains unchanged when LLM fails
 19. RAG structured security knowledge reaches the provider
 20. Oversized model output is rejected/clamped safely
 21. Unsupported evidence is rejected
 22. Provider selection works with/without Groq configuration

ZERO real network calls to Groq or Ollama. All external I/O is mocked.
"""

import json
import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import httpx
import pytest

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from llm.groq_provider import GroqLLMProvider, _verify_and_sanitize_context
from llm.ollama_provider import OllamaLLMProvider
from llm.fallback_provider import FallbackLLMProvider
from llm.provider import LLMProvider, LLMProviderError, MockLLMProvider, get_llm_provider
from llm.analyzer import analyze_security_context, MAX_FINDINGS
from backend.analysis.finding_enrichment import enrich_findings
from backend.analysis.security_gate import evaluate_security_gate
from backend.app.core.security import sanitize_sensitive_text


# ---------------------------------------------------------------------------
# TEST 1: Groq Provider Initialization
# ---------------------------------------------------------------------------
def test_1_groq_provider_initialization():
    provider = GroqLLMProvider(
        api_key="gsk_test_api_key_1234567890",
        model="llama-3.3-70b-versatile",
        base_url="https://api.groq.com/openai/v1",
        timeout=10.0,
    )
    assert provider.api_key == "gsk_test_api_key_1234567890"
    assert provider.model == "llama-3.3-70b-versatile"
    assert provider.base_url == "https://api.groq.com/openai/v1"
    assert provider.timeout == 10.0


# ---------------------------------------------------------------------------
# TEST 2: Missing Groq Key
# ---------------------------------------------------------------------------
def test_2_missing_groq_key():
    provider = GroqLLMProvider(api_key=None)
    with pytest.raises(LLMProviderError) as exc_info:
        provider.analyze("system prompt", "user prompt", {})
    assert "missing or unconfigured" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# TEST 3: Successful Groq Response
# ---------------------------------------------------------------------------
def test_3_successful_groq_response():
    provider = GroqLLMProvider(api_key="gsk_test_key_valid123456789")
    mock_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "findings": [
                            {
                                "title": "SQL Injection Detected",
                                "severity": "high",
                                "evidence": [{"document_id": "doc_1"}],
                            }
                        ]
                    })
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_error = False
    mock_resp.json.return_value = mock_payload

    with patch("httpx.Client.post", return_value=mock_resp):
        res = provider.analyze("sys prompt", "user prompt", {})
        assert res["provider"] == "groq"
        assert res["status"] == "success"
        assert len(res["findings"]) == 1
        assert res["findings"][0]["title"] == "SQL Injection Detected"


# ---------------------------------------------------------------------------
# TEST 4: Groq Timeout
# ---------------------------------------------------------------------------
def test_4_groq_timeout():
    provider = GroqLLMProvider(api_key="gsk_test_key_valid123456789", timeout=1.0, max_retries=0)
    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Read timeout")):
        with pytest.raises(LLMProviderError) as exc_info:
            provider.analyze("sys", "user", {})
        assert "timed out" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# TEST 5: Groq 429 Rate Limiting
# ---------------------------------------------------------------------------
def test_5_groq_429():
    provider = GroqLLMProvider(api_key="gsk_test_key_valid123456789", max_retries=0)
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.is_error = True

    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(LLMProviderError) as exc_info:
            provider.analyze("sys", "user", {})
        assert "429" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TEST 6: Groq 5xx Server Error
# ---------------------------------------------------------------------------
def test_6_groq_5xx():
    provider = GroqLLMProvider(api_key="gsk_test_key_valid123456789", max_retries=0)
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_resp.is_error = True

    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(LLMProviderError) as exc_info:
            provider.analyze("sys", "user", {})
        assert "503" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TEST 7: Groq Malformed JSON
# ---------------------------------------------------------------------------
def test_7_groq_malformed_json():
    provider = GroqLLMProvider(api_key="gsk_test_key_valid123456789")
    mock_payload = {
        "choices": [
            {
                "message": {
                    "content": "This is raw prose, definitely not JSON content!"
                }
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_error = False
    mock_resp.json.return_value = mock_payload

    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(LLMProviderError) as exc_info:
            provider.analyze("sys", "user", {})
        assert "json" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# TEST 8: Ollama Successful Response
# ---------------------------------------------------------------------------
def test_8_ollama_successful_response():
    provider = OllamaLLMProvider(base_url="http://localhost:11434", model="codellama")
    mock_payload = {
        "message": {
            "content": json.dumps({
                "findings": [
                    {
                        "title": "Command Injection Vulnerability",
                        "severity": "critical",
                    }
                ]
            })
        }
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_error = False
    mock_resp.json.return_value = mock_payload

    with patch("httpx.Client.post", return_value=mock_resp):
        res = provider.analyze("sys prompt", "user prompt", {})
        assert res["provider"] == "ollama"
        assert res["status"] == "success"
        assert len(res["findings"]) == 1
        assert res["findings"][0]["title"] == "Command Injection Vulnerability"


# ---------------------------------------------------------------------------
# TEST 9: Ollama Connection Failure
# ---------------------------------------------------------------------------
def test_9_ollama_connection_failure():
    provider = OllamaLLMProvider(base_url="http://localhost:11434")
    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
        with pytest.raises(LLMProviderError) as exc_info:
            provider.analyze("sys", "user", {})
        assert "connection refused" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# TEST 10: Ollama Timeout
# ---------------------------------------------------------------------------
def test_10_ollama_timeout():
    provider = OllamaLLMProvider(base_url="http://localhost:11434", timeout=2.0)
    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Read timeout")):
        with pytest.raises(LLMProviderError) as exc_info:
            provider.analyze("sys", "user", {})
        assert "timed out" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# TEST 11: Groq -> Ollama Fallback
# ---------------------------------------------------------------------------
def test_11_groq_to_ollama_fallback():
    groq = GroqLLMProvider(api_key="gsk_test_key_valid123456789")
    ollama = OllamaLLMProvider()
    fallback = FallbackLLMProvider(providers=[groq, ollama])

    # Groq fails with 500 error
    groq_err_resp = MagicMock()
    groq_err_resp.status_code = 500
    groq_err_resp.is_error = True

    # Ollama succeeds
    ollama_ok_resp = MagicMock()
    ollama_ok_resp.status_code = 200
    ollama_ok_resp.is_error = False
    ollama_ok_resp.json.return_value = {
        "message": {"content": json.dumps({"findings": [{"title": "Ollama Found"}]})}
    }

    def dispatch_post(url, *args, **kwargs):
        if "groq.com" in url:
            return groq_err_resp
        return ollama_ok_resp

    with patch("httpx.Client.post", side_effect=dispatch_post):
        res = fallback.analyze("sys", "user", {})
        assert res["provider"] == "ollama"
        assert res["findings"][0]["title"] == "Ollama Found"


# ---------------------------------------------------------------------------
# TEST 12: Groq -> Ollama -> Mock Fallback
# ---------------------------------------------------------------------------
def test_12_groq_to_ollama_to_mock_fallback():
    groq = GroqLLMProvider(api_key="gsk_test_key_valid123456789")
    ollama = OllamaLLMProvider()
    mock = MockLLMProvider()
    fallback = FallbackLLMProvider(providers=[groq, ollama, mock])

    context_input = {
        "status": "success",
        "query": "database execution",
        "context": {
            "security_evidence": [
                {
                    "document_id": "doc_sql_1",
                    "metadata": {
                        "signal_type": "database_execution_call",
                        "signal_name": "cursor.execute",
                    },
                }
            ]
        },
    }

    # Both Groq and Ollama raise ConnectError
    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Network unreachable")):
        res = fallback.analyze("sys", "user", context_input)
        assert res["provider"] == "mock"
        assert res["status"] == "success"
        assert len(res["findings"]) >= 1


# ---------------------------------------------------------------------------
# TEST 13: Mock Provider Remains Functional
# ---------------------------------------------------------------------------
def test_13_mock_provider_remains_functional():
    mock = MockLLMProvider()
    ctx = {
        "status": "success",
        "query": "command injection",
        "context": {
            "security_evidence": [
                {
                    "document_id": "doc_cmd_1",
                    "metadata": {
                        "signal_type": "command_execution_call",
                        "signal_name": "os.system",
                    },
                }
            ]
        },
    }
    res = mock.analyze("sys", "user", ctx)
    assert res["provider"] == "mock"
    assert res["status"] == "success"
    assert any("Command Injection" in f["title"] for f in res["findings"])


# ---------------------------------------------------------------------------
# TEST 14: Secrets Never Appear in Transmitted Request
# ---------------------------------------------------------------------------
def test_14_secrets_never_appear_in_transmitted_request():
    provider = GroqLLMProvider(api_key="gsk_real_api_key_must_not_leak_123456")
    captured_payloads = []

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_error = False
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": json.dumps({"findings": []})}}]
    }

    def capture_post(url, **kwargs):
        captured_payloads.append(kwargs.get("json", {}))
        return mock_resp

    prompt_with_secret = "Analyzing user code with gsk_secret_token_1234567890abcdef and ghp_githubtoken1234567890abcdef"
    with patch("httpx.Client.post", side_effect=capture_post):
        provider.analyze("system prompt", prompt_with_secret, {})

    assert len(captured_payloads) == 1
    sent_content = json.dumps(captured_payloads[0])
    assert "gsk_secret_token_1234567890abcdef" not in sent_content
    assert "ghp_githubtoken1234567890abcdef" not in sent_content
    assert "[REDACTED_SECRET]" in sent_content


# ---------------------------------------------------------------------------
# TEST 15: Secrets Never Appear in Logs/Errors
# ---------------------------------------------------------------------------
def test_15_secrets_never_appear_in_logs_or_errors():
    raw_error_message = "Failed to connect to API using key gsk_sensitive_key_9876543210 and token ghp_pat1234567890abcdef"
    sanitized = sanitize_sensitive_text(raw_error_message)
    assert "gsk_sensitive_key_9876543210" not in sanitized
    assert "ghp_pat1234567890abcdef" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


# ---------------------------------------------------------------------------
# TEST 16: Raw Source is Absent from External Provider Context
# ---------------------------------------------------------------------------
def test_16_raw_source_absent_from_external_context():
    dirty_context = {
        "query": "find sql injection",
        "source_code": "import os; os.system('rm -rf /')",
        "raw_source": "SELECT * FROM secrets;",
        "code": "cursor.execute(query)",
        "nested": {
            "full_source": "super secret code",
            "safe_key": "safe_value",
        },
    }
    cleaned = _verify_and_sanitize_context(dirty_context)
    assert "source_code" not in cleaned
    assert "raw_source" not in cleaned
    assert "code" not in cleaned
    assert "full_source" not in cleaned["nested"]
    assert cleaned["nested"]["safe_key"] == "safe_value"


# ---------------------------------------------------------------------------
# TEST 17: Deterministic Findings Remain Unchanged When LLM Fails
# ---------------------------------------------------------------------------
def test_17_deterministic_findings_remain_unchanged_when_llm_fails():
    deterministic_finding = {
        "finding_id": "finding_1",
        "title": "Hardcoded Credential Detected",
        "severity": "critical",
        "category": "Credential Management",
        "evidence": [{"signal_type": "possible_hardcoded_secret"}],
        "enriched_by": [],
    }

    # Broken provider that unconditionally raises an error
    broken_provider = MagicMock(spec=LLMProvider)
    broken_provider.explain_findings.side_effect = LLMProviderError("Provider unavailable")

    result = enrich_findings([deterministic_finding], provider=broken_provider)
    assert len(result) == 1
    assert result[0]["finding_id"] == "finding_1"
    assert result[0]["title"] == "Hardcoded Credential Detected"
    assert result[0]["severity"] == "critical"
    # Even on failure, fallback MockLLMProvider populates recommendation & provenance
    assert "mock_llm" in result[0]["enriched_by"]


# ---------------------------------------------------------------------------
# TEST 18: Security Gate Result Remains Unchanged When LLM Fails
# ---------------------------------------------------------------------------
def test_18_security_gate_result_remains_unchanged_when_llm_fails():
    critical_finding = {
        "finding_id": "finding_1",
        "title": "Command Execution Risk",
        "severity": "critical",
        "category": "Command Injection",
        "evidence": [{"document_id": "doc_1"}],
    }

    report_before = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }

    # Gate decision before LLM enrichment
    decision_before, exit_code_before, msg_before = evaluate_security_gate(report_before)
    assert decision_before == "BLOCK"
    assert exit_code_before == 1

    # Broken provider fails during explanation enrichment
    broken_provider = MagicMock(spec=LLMProvider)
    broken_provider.explain_findings.side_effect = RuntimeError("External LLM crashed")

    enriched = enrich_findings([critical_finding], provider=broken_provider)
    assert len(enriched) == 1
    assert enriched[0]["severity"] == "critical"

    # Reconstruct report with enriched findings
    report_after = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "critical_count": sum(1 for f in enriched if f.get("severity") == "critical"),
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }
    decision_after, exit_code_after, msg_after = evaluate_security_gate(report_after)

    assert decision_after == decision_before
    assert exit_code_after == exit_code_before
    assert "BLOCK" in decision_after


# ---------------------------------------------------------------------------
# TEST 19: RAG Structured Security Knowledge Reaches the Provider
# ---------------------------------------------------------------------------
def test_19_rag_structured_knowledge_reaches_provider():
    context_input = {
        "status": "success",
        "query": "SQL Injection",
        "context": {
            "security_evidence": [{"document_id": "doc_1"}],
            "code_structure": [{"name": "query_db"}],
            "security_knowledge": [
                {
                    "document_id": "cwe_89_doc",
                    "text": "SQL Injection (CWE-89): Use parameterized queries.",
                }
            ],
        },
    }

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.analyze.return_value = {
        "status": "success",
        "provider": "mock",
        "findings": [],
    }

    analyze_security_context(context_input, provider=mock_provider)
    mock_provider.analyze.assert_called_once()
    call_args = mock_provider.analyze.call_args[1]
    user_prompt = call_args["user_prompt"]

    assert "cwe_89_doc" in user_prompt
    assert "SQL Injection (CWE-89)" in user_prompt



# ---------------------------------------------------------------------------
# TEST 20: Oversized Model Output is Rejected/Clamped Safely
# ---------------------------------------------------------------------------
def test_20_oversized_model_output_clamped():
    valid_doc = "doc_valid_evidence_1"
    # Create 35 simulated findings
    massive_findings = [
        {
            "title": f"Vulnerability {i}",
            "severity": "medium",
            "confidence": "high",
            "description": "Short desc",
            "evidence": [{"document_id": valid_doc}],
        }
        for i in range(35)
    ]

    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.analyze.return_value = {
        "status": "success",
        "findings": massive_findings,
        "provider": "mock",
    }

    context = {
        "status": "success",
        "context": {"security_evidence": [{"document_id": valid_doc}]},
    }

    res = analyze_security_context(context, provider=mock_provider)
    assert len(res["findings"]) == MAX_FINDINGS
    assert res["summary"]["total_findings"] == MAX_FINDINGS


# ---------------------------------------------------------------------------
# TEST 21: Unsupported Evidence is Rejected
# ---------------------------------------------------------------------------
def test_21_unsupported_evidence_rejected():
    mock_provider = MagicMock(spec=LLMProvider)
    mock_provider.analyze.return_value = {
        "status": "success",
        "findings": [
            {
                "title": "Hallucinated Finding",
                "severity": "high",
                "evidence": [
                    {"document_id": "completely_fake_doc_id_9999"}
                ],
            }
        ],
        "provider": "mock",
    }

    context = {
        "status": "success",
        "context": {"security_evidence": [{"document_id": "real_doc_1"}]},
    }

    res = analyze_security_context(context, provider=mock_provider)
    # The hallucinated finding references an unknown document ID, so it must be discarded
    assert len(res["findings"]) == 0
    assert res["summary"]["total_findings"] == 0


# ---------------------------------------------------------------------------
# TEST 22: Provider Selection Works With/Without Groq Configuration
# ---------------------------------------------------------------------------
def test_22_provider_selection_with_and_without_groq():
    # 1. With Groq API key configured -> Groq -> Ollama -> Mock (3 providers)
    mock_settings_with_groq = MagicMock()
    mock_settings_with_groq.GROQ_API_KEY = "gsk_valid_test_key_12345"
    prov_with_groq = get_llm_provider(settings=mock_settings_with_groq, force_fallback=True)

    assert isinstance(prov_with_groq, FallbackLLMProvider)
    assert len(prov_with_groq.providers) == 3
    assert isinstance(prov_with_groq.providers[0], GroqLLMProvider)
    assert isinstance(prov_with_groq.providers[1], OllamaLLMProvider)
    assert isinstance(prov_with_groq.providers[2], MockLLMProvider)

    # 2. Without Groq API key configured -> Ollama -> Mock (2 providers)
    mock_settings_no_groq = MagicMock()
    mock_settings_no_groq.GROQ_API_KEY = None
    prov_no_groq = get_llm_provider(settings=mock_settings_no_groq, force_fallback=True)

    assert isinstance(prov_no_groq, FallbackLLMProvider)
    assert len(prov_no_groq.providers) == 2
    assert isinstance(prov_no_groq.providers[0], OllamaLLMProvider)
    assert isinstance(prov_no_groq.providers[1], MockLLMProvider)
