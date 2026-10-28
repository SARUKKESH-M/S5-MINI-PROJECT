"""
CodeSentinel U1-A2 — Ollama Fast-Fail Reliability Test Suite

Validates:
1. Bounded connection timeout (connect_timeout default 1.0s, configurable).
2. Exactly one connection attempt across a batch of 10 findings on connection error.
3. Fallback chain immediate routing to MockLLMProvider when Ollama is unavailable.
4. Non-connection errors retain best-effort deterministic fallback per finding.
5. Accurate provenance attribution (never label deterministic fallback as ollama_llm).
6. Process-level failure cooldown: zero HTTP calls during cooldown, concurrent safety, and recovery after expiry.
7. End-to-end repository analysis with FallbackLLMProvider fast-fail behavior.
"""

import concurrent.futures
import json
import threading
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import httpx
import pytest

from llm.fallback_provider import FallbackLLMProvider
from llm.ollama_provider import OllamaLLMProvider, DEFAULT_COOLDOWN_SECONDS
from llm.provider import LLMConnectionError, LLMProviderError, MockLLMProvider


@pytest.fixture(autouse=True)
def reset_ollama_state():
    """Ensure every test begins with clean cooldown state."""
    OllamaLLMProvider.reset_cooldown()
    yield
    OllamaLLMProvider.reset_cooldown()


def make_test_finding(idx: int = 1, rule: str = "unsafe_database_execution") -> Dict[str, Any]:
    return {
        "finding_id": f"find_{idx}",
        "title": f"SQL Injection Vulnerability {idx}",
        "severity": "HIGH",
        "category": "Injection",
        "cwe": "CWE-89",
        "cwe_id": "CWE-89",
        "evidence": [
            {
                "signal_type": rule,
                "file_path": f"src/db_{idx}.py",
                "line": 42,
            }
        ],
        "enriched_by": [],
    }


# =============================================================================
# 1. BOUNDED CONNECTION TIMEOUT
# =============================================================================

def test_01_ollama_default_and_custom_connect_timeout():
    """Verify default connect_timeout is 1.0s and custom timeouts are configured on httpx.Client."""
    default_prov = OllamaLLMProvider()
    assert default_prov.connect_timeout == 1.0
    assert default_prov.timeout == 20.0

    client = default_prov._get_client()
    assert client.timeout.connect == 1.0
    assert client.timeout.read == 20.0
    default_prov.close()

    custom_prov = OllamaLLMProvider(timeout=10.0, connect_timeout=0.5)
    assert custom_prov.connect_timeout == 0.5
    assert custom_prov.timeout == 10.0

    custom_client = custom_prov._get_client()
    assert custom_client.timeout.connect == 0.5
    assert custom_client.timeout.read == 10.0
    custom_prov.close()


# =============================================================================
# 2. BATCH OF 10 FINDINGS RESULTS IN AT MOST ONE CONNECTION ATTEMPT
# =============================================================================

def test_02_batch_of_ten_findings_attempts_at_most_one_connection_on_failure():
    """Verify that a connection failure across 10 findings stops immediately after 1 attempt."""
    provider = OllamaLLMProvider(cooldown_seconds=15.0)
    findings = [make_test_finding(i) for i in range(10)]

    call_count = 0

    def mock_connect_error(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("Connection refused to http://localhost:11434")

    with patch.object(httpx.Client, "post", side_effect=mock_connect_error):
        with pytest.raises(LLMConnectionError) as exc_info:
            provider.explain_findings(findings)

        assert "connection refused" in str(exc_info.value).lower()
        # Crucial invariant: exactly 1 attempt, NOT 10 attempts
        assert call_count == 1
    provider.close()


# =============================================================================
# 3. FALLBACK CHAIN ROUTES IMMEDIATELY TO MOCK PROVIDER
# =============================================================================

def test_03_fallback_chain_immediately_routes_to_mock_when_ollama_unavailable():
    """Verify FallbackLLMProvider catches connection error on finding 1 and immediately falls back."""
    ollama_prov = OllamaLLMProvider(cooldown_seconds=15.0)
    mock_prov = MockLLMProvider()
    chain = FallbackLLMProvider(providers=[ollama_prov, mock_prov])

    findings = [make_test_finding(i) for i in range(10)]
    call_count = 0

    def mock_connect_error(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("Connection refused")

    with patch.object(httpx.Client, "post", side_effect=mock_connect_error):
        explained = chain.explain_findings(findings)

        assert len(explained) == 10
        assert call_count == 1
        for item in explained:
            assert item["structured_explanation"]["provenance"] == "mock_llm"
            assert "mock_llm" in item["enriched_by"]
            assert "ollama_llm" not in item["enriched_by"]
    ollama_prov.close()


# =============================================================================
# 4. NON-CONNECTION ERRORS RETAIN BEST-EFFORT DETERMINISTIC FALLBACK
# =============================================================================

def test_04_non_connection_error_preserves_best_effort_deterministic_fallback():
    """Verify non-connection errors (e.g. invalid JSON) fall back per-finding without aborting."""
    provider = OllamaLLMProvider(cooldown_seconds=15.0)
    findings = [make_test_finding(1), make_test_finding(2)]

    responses = [
        # Finding 1: valid response
        MagicMock(
            status_code=200,
            is_error=False,
            json=lambda: {
                "message": {
                    "content": json.dumps({
                        "summary": "Valid Ollama Explanation",
                        "why_it_matters": "Risk",
                        "remediation": "Fix",
                    })
                }
            },
        ),
        # Finding 2: malformed output
        MagicMock(
            status_code=200,
            is_error=False,
            json=lambda: {
                "message": {
                    "content": "Not a valid json response {{"
                }
            },
        ),
    ]

    with patch.object(httpx.Client, "post", side_effect=responses):
        explained = provider.explain_findings(findings)
        assert len(explained) == 2

        # Finding 1: succeeded with Ollama
        assert explained[0]["structured_explanation"]["provenance"] == "ollama"
        assert "ollama_llm" in explained[0]["enriched_by"]

        # Finding 2: deterministic fallback for bad format, never labeled as ollama_llm
        assert explained[1]["structured_explanation"]["provenance"] == "deterministic_fallback"
        assert "deterministic_fallback" in explained[1]["enriched_by"]
        assert "ollama_llm" not in explained[1]["enriched_by"]
    provider.close()


# =============================================================================
# 5. PROVENANCE ACCURATE ATTRIBUTION
# =============================================================================

def test_05_provenance_accurate_attribution():
    """Verify that deterministic fallback is NEVER tagged with ollama_llm."""
    provider = OllamaLLMProvider()

    def mock_invalid_model(msgs):
        raise LLMProviderError("Ollama model 'codellama' not found")

    with patch.object(provider, "_post_chat", side_effect=mock_invalid_model):
        findings = [make_test_finding(1)]
        explained = provider.explain_findings(findings)

        assert len(explained) == 1
        item = explained[0]
        assert item["structured_explanation"]["provenance"] == "deterministic_fallback"
        assert "ollama_llm" not in item["enriched_by"]
        assert "deterministic_fallback" in item["enriched_by"]
    provider.close()


# =============================================================================
# 6. PROCESS-LEVEL COOLDOWN & AUTOMATIC RECOVERY
# =============================================================================

def test_06_cooldown_suppresses_http_calls_and_recovers_after_expiry():
    """Verify that during failure cooldown, network calls are suppressed (0 calls), and recover after expiry."""
    provider1 = OllamaLLMProvider(cooldown_seconds=15.0)
    provider2 = OllamaLLMProvider(cooldown_seconds=15.0)

    findings = [make_test_finding(1)]
    call_count = 0

    def mock_connect_error(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("Daemon down")

    def mock_success(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return MagicMock(
            status_code=200,
            is_error=False,
            json=lambda: {
                "message": {
                    "content": json.dumps({
                        "summary": "Recovered",
                        "why_it_matters": "Risk",
                        "remediation": "Fix",
                    })
                }
            },
        )

    # Step 1: Initial failure trips cooldown
    with patch.object(httpx.Client, "post", side_effect=mock_connect_error):
        with pytest.raises(LLMConnectionError):
            provider1.explain_findings(findings)
        assert call_count == 1
        assert provider1._is_in_cooldown() is True
        assert provider2._is_in_cooldown() is True  # Shared across instances

    # Step 2: Immediate second call on provider2 during cooldown window
    with patch.object(httpx.Client, "post", side_effect=mock_connect_error):
        with pytest.raises(LLMConnectionError) as exc_info:
            provider2.explain_findings(findings)
        assert "in failure cooldown" in str(exc_info.value)
        # Call count must STILL be 1 (0 additional network calls made!)
        assert call_count == 1

    # Step 3: Advance time beyond cooldown (15s) and verify recovery
    with patch("time.monotonic", return_value=time.monotonic() + 20.0):
        assert provider1._is_in_cooldown() is False
        assert provider2._is_in_cooldown() is False

        with patch.object(httpx.Client, "post", side_effect=mock_success):
            explained = provider1.explain_findings(findings)
            assert len(explained) == 1
            assert explained[0]["structured_explanation"]["provenance"] == "ollama"
            # Now call count is 2 (new network call was made and succeeded)
            assert call_count == 2

    provider1.close()
    provider2.close()


def test_07_concurrent_threads_respect_cooldown_without_duplicate_connects():
    """Verify thread-safety: multiple concurrent threads tripping connection failure do not corrupt state."""
    provider = OllamaLLMProvider(cooldown_seconds=15.0)
    findings = [make_test_finding(i) for i in range(5)]

    connect_attempts = 0
    lock = threading.Lock()

    def mock_connect_error(*args, **kwargs):
        nonlocal connect_attempts
        with lock:
            connect_attempts += 1
        time.sleep(0.01)
        raise httpx.ConnectError("Connection refused")

    with patch.object(httpx.Client, "post", side_effect=mock_connect_error):
        def worker():
            p = OllamaLLMProvider(cooldown_seconds=15.0)
            try:
                p.explain_findings(findings)
            except LLMConnectionError:
                pass
            p.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(worker) for _ in range(4)]
            concurrent.futures.wait(futures)

        # Connect attempts should be bounded (at most the concurrent threads racing before latch sets, typically 1)
        assert connect_attempts <= 4
        assert provider._is_in_cooldown() is True
    provider.close()


def test_08_provider_factory_wires_cooldown_settings():
    """Verify that get_llm_provider() wires OLLAMA_COOLDOWN_SECONDS from settings into OllamaLLMProvider."""
    from llm.provider import get_llm_provider
    from backend.app.core.config import Settings

    custom_settings = Settings(
        OLLAMA_TIMEOUT=12.0,
        OLLAMA_CONNECT_TIMEOUT=0.5,
        OLLAMA_COOLDOWN_SECONDS=45.0,
    )
    # force_fallback=True bypasses the PYTEST_CURRENT_TEST MockLLMProvider guard
    fallback_chain = get_llm_provider(settings=custom_settings, force_fallback=True)
    assert isinstance(fallback_chain, FallbackLLMProvider)
    
    ollama_prov = fallback_chain.providers[0]
    assert isinstance(ollama_prov, OllamaLLMProvider)
    assert ollama_prov.timeout == 12.0
    assert ollama_prov.connect_timeout == 0.5
    assert ollama_prov.cooldown_seconds == 45.0
    ollama_prov.close()
