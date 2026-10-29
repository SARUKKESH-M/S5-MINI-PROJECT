"""
CodeSentinel — Phase Upgrade 1E1 Test Suite
Curated Knowledge RAG Short-Circuit and Fallback Verification

Validates:
1. Exact curated CWE match skips vector retrieval entirely.
2. Curated enrichment properly populates metadata, references, security guidance, and provenance.
3. Missing, unmapped, or unsupported CWE falls back to hybrid vector retrieval.
4. Retrieval errors during fallback do not remove, drop, or downgrade authoritative findings.
5. LLM provider factory respects CODESENTINEL_FORCE_MOCK_LLM, pytest defaults, and live provider overrides.
6. Step 6O contracts, finding IDs, severities, evidence, and security-gate verdicts remain invariant.
"""

import os
import sys
import copy
import pytest
from unittest.mock import MagicMock

# Ensure backend and root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.finding_enrichment import (
    enrich_findings,
    SIGNAL_CWE_MAPPING,
)
from backend.analysis.security_gate import evaluate_security_gate
from knowledge.curated_owasp import CURATED_OWASP_KNOWLEDGE
from llm.provider import get_llm_provider, MockLLMProvider
from llm.fallback_provider import FallbackLLMProvider


# ==============================================================================
# TEST 1: Exact Curated CWE Match Skips Vector Retrieval
# ==============================================================================

def test_exact_curated_cwe_skips_vector_retrieval(monkeypatch):
    """Verify that findings with an exact curated CWE match bypass ChromaDB vector retrieval entirely."""
    vector_retrieval_calls = []

    def spy_build_security_analysis_context(*args, **kwargs):
        vector_retrieval_calls.append((args, kwargs))
        return {
            "status": "success",
            "context": {"security_knowledge": []},
            "security_knowledge_context_count": 0,
        }

    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        spy_build_security_analysis_context,
    )

    findings = [
        {
            "finding_id": "f_sql_1",
            "title": "Potential SQL Injection Vulnerability",
            "severity": "critical",
            "category": "Injection",
            "evidence": [{"document_id": "db.py", "signal_type": "unsafe_database_execution"}],
        },
        {
            "finding_id": "f_cmd_1",
            "title": "Command Injection Risk",
            "severity": "critical",
            "category": "Injection",
            "evidence": [{"document_id": "shell.py", "signal_type": "command_execution_call"}],
        },
    ]

    enriched = enrich_findings(findings)

    # Both findings have exact curated CWE matches (CWE-89 and CWE-78)
    assert len(enriched) == 2
    assert len(vector_retrieval_calls) == 0, (
        f"Expected 0 vector retrieval calls, but got {len(vector_retrieval_calls)}"
    )

    # Verify both findings received curated knowledge
    for item in enriched:
        assert item.get("cwe_id") in ("CWE-89", "CWE-78")
        assert len(item.get("retrieved_knowledge", [])) == 1
        assert "rag" in item.get("enriched_by", [])
        assert item.get("security_guidance") is not None
        assert len(item.get("references", [])) > 0


# ==============================================================================
# TEST 2: Curated Enrichment Populates Expected Metadata and Provenance
# ==============================================================================

def test_curated_enrichment_populates_expected_metadata_and_provenance():
    """Verify that curated enrichment sets cwe_id, references, security_guidance, and rag provenance."""
    sample_signals = {
        "unsafe_database_execution": "CWE-89",
        "command_execution_call": "CWE-78",
        "possible_hardcoded_secret": "CWE-798",
        "path_traversal_call": "CWE-22",
        "insecure_deserialization_call": "CWE-502",
        "reflected_xss_call": "CWE-79",
        "weak_crypto_call": "CWE-327",
        "missing_authentication": "CWE-306",
        "cross_site_request_forgery": "CWE-352",
        "unrestricted_file_upload": "CWE-434",
        "sensitive_data_exposure": "CWE-200",
        "null_pointer_dereference": "CWE-476",
    }

    for sig, expected_cwe in sample_signals.items():
        finding = {
            "finding_id": f"test_{sig}",
            "title": "Test Security Signal",
            "severity": "high",
            "evidence": [{"document_id": "test.py", "signal_type": sig}],
        }

        res = enrich_findings([finding])
        assert len(res) == 1
        item = res[0]

        assert item.get("cwe_id") == expected_cwe
        assert "rag" in item.get("enriched_by", [])
        assert any(expected_cwe in ref for ref in item.get("references", []))
        assert item.get("security_guidance") is not None
        assert len(item.get("retrieved_knowledge", [])) >= 1
        assert item["retrieved_knowledge"][0]["metadata"]["cwe_id"] == expected_cwe


# ==============================================================================
# TEST 3: Missing, Unmapped, or Unsupported CWE Falls Back to Vector Retrieval
# ==============================================================================

def test_unmapped_signal_falls_back_to_vector_retrieval(monkeypatch):
    """Verify that an unmapped signal (such as dynamic_code_execution) triggers vector retrieval fallback."""
    vector_retrieval_calls = []

    def spy_build_security_analysis_context(*args, **kwargs):
        vector_retrieval_calls.append((args, kwargs))
        return {
            "status": "success",
            "context": {
                "security_knowledge": [
                    {
                        "document_id": "kn_dynamic_code",
                        "content": "Code execution security details",
                        "metadata": {"cwe_id": "CWE-94", "title": "Code Injection Prevention"},
                    }
                ]
            },
            "security_knowledge_context_count": 1,
        }

    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        spy_build_security_analysis_context,
    )

    unmapped_finding = {
        "finding_id": "f_eval_1",
        "title": "Arbitrary Dynamic Code Execution Risk",
        "severity": "high",
        "evidence": [{"document_id": "eval.py", "signal_type": "dynamic_code_execution"}],
    }

    enriched = enrich_findings([unmapped_finding])
    assert len(enriched) == 1
    assert len(vector_retrieval_calls) == 1, (
        f"Expected 1 vector retrieval call for unmapped signal, got {len(vector_retrieval_calls)}"
    )
    assert enriched[0].get("cwe_id") == "CWE-94"
    assert "rag" in enriched[0].get("enriched_by", [])


# ==============================================================================
# TEST 4: Retrieval Errors Do Not Remove or Downgrade Authoritative Findings
# ==============================================================================

def test_retrieval_errors_do_not_remove_or_downgrade_findings(monkeypatch):
    """Verify that vector retrieval failures during fallback degrade gracefully without dropping findings."""
    def failing_builder(*args, **kwargs):
        raise RuntimeError("Simulated ChromaDB connection timeout")

    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        failing_builder,
    )

    findings = [
        {
            "finding_id": "f_unmapped_err",
            "title": "Dynamic Code Execution Warning",
            "severity": "critical",
            "confidence": "high",
            "category": "Code Execution",
            "evidence": [{"document_id": "exec.py", "line_start": 5, "line_end": 5, "signal_type": "dynamic_code_execution"}],
        }
    ]

    snapshot = copy.deepcopy(findings[0])
    enriched = enrich_findings(findings)

    # Finding must NOT be dropped
    assert len(enriched) == 1
    item = enriched[0]

    # Authoritative fields strictly preserved
    assert item["finding_id"] == snapshot["finding_id"]
    assert item["title"] == snapshot["title"]
    assert item["severity"] == snapshot["severity"]
    assert item["confidence"] == snapshot["confidence"]
    assert item["category"] == snapshot["category"]
    assert item["evidence"] == snapshot["evidence"]
    assert "structured_explanation" in item


# ==============================================================================
# TEST 5: Provider Factory Respects CODESENTINEL_FORCE_MOCK_LLM & Live Overrides
# ==============================================================================

def test_provider_factory_respects_force_mock_and_live_override(monkeypatch):
    """Verify that get_llm_provider respects CODESENTINEL_FORCE_MOCK_LLM, test envs, and live overrides."""
    # 1. Explicit mock override
    monkeypatch.setenv("CODESENTINEL_FORCE_MOCK_LLM", "1")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("CODESENTINEL_TEST_LIVE_PROVIDERS", raising=False)
    p1 = get_llm_provider()
    assert isinstance(p1, MockLLMProvider)

    # 2. force_fallback=True bypasses the mock guard
    p2 = get_llm_provider(force_fallback=True)
    assert isinstance(p2, FallbackLLMProvider)

    # 3. Explicit live providers override
    monkeypatch.delenv("CODESENTINEL_FORCE_MOCK_LLM", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "test_file.py::test_case")
    monkeypatch.setenv("CODESENTINEL_TEST_LIVE_PROVIDERS", "1")
    p3 = get_llm_provider()
    assert isinstance(p3, FallbackLLMProvider)


# ==============================================================================
# TEST 6: Step 6O Contract and Security-Gate Invariance
# ==============================================================================

def test_step_6o_contract_and_security_gate_invariance():
    """Verify that short-circuited findings preserve Step 6O schemas and security gate evaluations."""
    raw_findings = [
        {
            "finding_id": "f_crit_sqli",
            "title": "Potential SQL Injection Vulnerability",
            "severity": "critical",
            "confidence": "high",
            "category": "Injection",
            "evidence": [{"document_id": "app.py", "line_start": 10, "line_end": 10, "signal_type": "unsafe_database_execution"}],
        },
        {
            "finding_id": "f_high_cmd",
            "title": "Command Injection Risk",
            "severity": "high",
            "confidence": "high",
            "category": "Injection",
            "evidence": [{"document_id": "exec.py", "line_start": 20, "line_end": 20, "signal_type": "command_execution_call"}],
        },
    ]

    enriched = enrich_findings(raw_findings)
    assert len(enriched) == 2

    # Verify internal ephemeral references are purged
    for f in enriched:
        assert "_retrieved_knowledge_doc" not in f
        assert "structured_explanation" in f
        assert isinstance(f["structured_explanation"], dict)

    report = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "total_files": 2,
            "analyzed_files": 2,
            "skipped_files": 0,
            "total_findings": 2,
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
        "findings": enriched,
    }

    verdict, exit_code, violations = evaluate_security_gate(report)
    assert verdict == "BLOCK"
    assert exit_code == 1
    assert len(violations) >= 2
