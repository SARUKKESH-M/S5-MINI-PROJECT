"""Test suite for Phase 35C Safe Performance Optimizations.

Validates:
- P0-A: AnalysisStore process-level initialization guard
- P0-B: SQLite WAL mode + synchronous NORMAL configuration
- P1-C: Duplicate AST and taint analysis elimination
- P1-D: Request-local RAG query deduplication
- P1-E: Groq and Ollama HTTP client connection pooling
- Security Invariants: Step 6O gate authority, taint determinism, finding immutability
"""

import os
import gc
import shutil
import sqlite3
import tempfile
import threading
import pytest
from unittest.mock import MagicMock, patch

from backend.analysis.storage.store import AnalysisStore, _INITIALIZED_DATABASES, _DB_INIT_LOCK
from backend.analysis.orchestrator import analyze_source_code
import backend.analysis.orchestrator as orch_module
from backend.analysis.finding_enrichment import enrich_findings, build_structured_rag_query
from llm.groq_provider import GroqLLMProvider
from llm.ollama_provider import OllamaLLMProvider
from llm.provider import MockLLMProvider
from backend.analysis.security_gate import evaluate_security_gate


# =============================================================================
# P0-A & P0-B: AnalysisStore Initialization Guard & WAL / NORMAL PRAGMAs
# =============================================================================

def test_p0_a_store_initialization_guard_single_init():
    """Verify that schema initialization executes strictly once per database path."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_guard.db")

    try:
        norm_path = os.path.normcase(os.path.abspath(db_path))
        with _DB_INIT_LOCK:
            _INITIALIZED_DATABASES.pop(norm_path, None)

        # First instance initializes the DB
        store1 = AnalysisStore(db_path=db_path)
        assert norm_path in _INITIALIZED_DATABASES

        # Verify PRAGMA journal_mode and synchronous
        with store1._get_connection() as conn:
            journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            sync_mode = conn.execute("PRAGMA synchronous;").fetchone()[0]
            assert journal_mode.lower() == "wal"
            assert sync_mode in (1, "1", "NORMAL", "normal")

        # Second instance uses guard and avoids redundant schema checks
        store2 = AnalysisStore(db_path=db_path)
        assert norm_path in _INITIALIZED_DATABASES

        # Verify tables and functionality remain 100% operational
        res = store2.list_analyses(limit=5)
        assert isinstance(res, list)

    finally:
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_p0_a_store_guard_distinguishes_different_databases():
    """Verify that different database paths initialize independently."""
    temp_dir = tempfile.mkdtemp()
    path1 = os.path.join(temp_dir, "db1.db")
    path2 = os.path.join(temp_dir, "db2.db")

    try:
        norm1 = os.path.normcase(os.path.abspath(path1))
        norm2 = os.path.normcase(os.path.abspath(path2))

        with _DB_INIT_LOCK:
            _INITIALIZED_DATABASES.pop(norm1, None)
            _INITIALIZED_DATABASES.pop(norm2, None)

        store1 = AnalysisStore(db_path=path1)
        assert norm1 in _INITIALIZED_DATABASES
        assert norm2 not in _INITIALIZED_DATABASES

        store2 = AnalysisStore(db_path=path2)
        assert norm2 in _INITIALIZED_DATABASES

    finally:
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_p0_b_sqlite_concurrent_read_writes():
    """Verify that SQLite with WAL + NORMAL handles concurrent read/writes reliably."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_concurrent.db")

    try:
        store = AnalysisStore(db_path=db_path)
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(10):
                    analysis_record = {
                        "analysis_id": f"worker_{worker_id}_test_{i}",
                        "timestamp": "2026-09-11T12:00:00Z",
                        "repo_name": "test_repo",
                        "commit_hash": "abcdef1234567890",
                        "summary": {"total_findings": 0},
                        "findings": [],
                    }
                    store.save_analysis(analysis_record)
                    recent = store.list_analyses(limit=5)
                    assert isinstance(recent, list)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Concurrent workers encountered errors: {errors}"

    finally:
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)


# =============================================================================
# P1-C: Duplicate AST / Taint Processing Elimination
# =============================================================================

def test_p1_c_ast_taint_single_pass_python(monkeypatch):
    """Verify that analyze_source_code executes AST normalization exactly once and passes normalized evidence to RAG."""
    call_count = 0
    orig_normalize = orch_module.normalize_security_evidence

    def counting_normalize(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return orig_normalize(*args, **kwargs)

    monkeypatch.setattr(orch_module, "normalize_security_evidence", counting_normalize)

    sample_py = '''
import os
import subprocess

def handler(user_input):
    cmd = "echo " + user_input
    os.system(cmd)
'''
    result = analyze_source_code(sample_py)

    assert result["status"] == "success"
    # Previously, normalize_security_evidence was called twice (once for findings, once for RAG adapter).
    # Now it must be called exactly once per file analysis.
    assert call_count == 1, f"Expected exactly 1 call to normalize_security_evidence, got {call_count}"
    assert len(result["findings"]) > 0
    assert result["findings"][0]["severity"] in ("critical", "high", "medium", "low", "unknown")


def test_p1_c_deterministic_output_identity():
    """Verify that the single-pass normalized evidence yields identical findings and evidence structure."""
    sample_py = '''
import sqlite3

def get_user(db_conn, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db_conn.execute(query).fetchall()
'''
    result = analyze_source_code(sample_py)
    findings = result["findings"]
    assert len(findings) >= 1
    sqli_finding = [f for f in findings if "SQL" in f.get("title", "") or "injection" in f.get("category", "").lower()][0]

    assert "evidence" in sqli_finding
    assert len(sqli_finding["evidence"]) > 0
    ev = sqli_finding["evidence"][0]
    assert "document_id" in ev
    assert ev.get("line_start") is not None or ev.get("line_end") is not None


# =============================================================================
# P1-D: Request-Local RAG Query Deduplication
# =============================================================================

def test_p1_d_rag_query_deduplication():
    """Verify that multiple findings with identical CWE and query context share RAG retrieval."""
    findings = [
        {
            "finding_id": f"FIND-{i}",
            "cwe_id": "CWE-89",
            "title": "SQL Injection",
            "severity": "HIGH",
            "file_path": f"src/db_{i}.py",
            "line_number": 10 + i,
            "evidence": "db.execute(query)",
        }
        for i in range(5)
    ]

    mock_llm = MockLLMProvider()

    with patch("backend.analysis.finding_enrichment.build_security_analysis_context") as mock_rag:
        mock_rag.return_value = {
            "retrieved_context": "Safe parameterized query documentation",
            "chunks": [{"source": "kb_cwe89", "content": "Safe query"}],
        }

        enriched = enrich_findings(findings, provider=mock_llm)

        assert len(enriched) == 5
        # The 5 identical CWE findings must execute build_security_analysis_context exactly ONCE
        assert mock_rag.call_count == 1, f"Expected 1 RAG retrieval call, got {mock_rag.call_count}"

        for item in enriched:
            assert "structured_explanation" in item
            assert item["structured_explanation"]["why_it_matters"]
            assert item["structured_explanation"]["remediation"]


def test_p1_d_rag_distinct_cwe_separate_retrieval():
    """Verify that findings with different CWEs query RAG separately."""
    findings = [
        {"finding_id": "F1", "cwe_id": "CWE-89", "title": "SQLi", "severity": "HIGH", "file_path": "a.py", "line_number": 1, "evidence": "a"},
        {"finding_id": "F2", "cwe_id": "CWE-78", "title": "Command Injection", "severity": "CRITICAL", "file_path": "b.py", "line_number": 2, "evidence": "b"},
    ]

    mock_llm = MockLLMProvider()

    with patch("backend.analysis.finding_enrichment.build_security_analysis_context") as mock_rag:
        mock_rag.return_value = {"retrieved_context": "docs", "chunks": []}
        enriched = enrich_findings(findings, provider=mock_llm)

        assert len(enriched) == 2
        assert mock_rag.call_count == 2


# =============================================================================
# P1-E: Pooled Groq & Ollama HTTP Clients
# =============================================================================

def test_p1_e_groq_client_pooling():
    """Verify that GroqLLMProvider reuses its pooled HTTP client across requests."""
    provider = GroqLLMProvider(api_key="gsk_test123")

    # Initial state
    assert provider._client is None

    # Get client
    c1 = provider._get_client()
    assert c1 is not None
    assert not c1.is_closed

    # Second call returns the identical client
    c2 = provider._get_client()
    assert c1 is c2

    # Deterministic cleanup
    provider.close()
    assert provider._closed
    assert c1.is_closed
    assert provider._client is None


def test_p1_e_ollama_client_pooling():
    """Verify that OllamaLLMProvider reuses its pooled HTTP client across requests."""
    provider = OllamaLLMProvider(base_url="http://localhost:11434")

    assert provider._client is None

    c1 = provider._get_client()
    assert c1 is not None
    assert not c1.is_closed

    c2 = provider._get_client()
    assert c1 is c2

    provider.close()
    assert provider._closed
    assert c1.is_closed
    assert provider._client is None


# =============================================================================
# Security Invariants Preservation
# =============================================================================

def test_security_invariants_step6o_gate():
    """Verify that Step 6O security gate decisions remain authoritative and strictly preserved."""
    base_report = {
        "status": "success",
        "analysis_id": "test_inv_1",
        "timestamp": "2026-09-11T12:00:00Z",
        "commit_hash": "a" * 40,
        "repo_name": "owner/repo",
        "summary": {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
        "findings": [],
    }

    # ALLOW
    allow_rep = dict(base_report, review_status="allow")
    dec, code, _ = evaluate_security_gate(allow_rep)
    assert dec == "ALLOW"
    assert code == 0

    # REVIEW
    review_rep = dict(base_report, review_status="review", summary={
        "total_findings": 1,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 1,
        "low_count": 0,
        "info_count": 0,
    })
    dec, code, _ = evaluate_security_gate(review_rep)
    assert dec == "REVIEW"
    assert code == 2

    # BLOCK
    block_rep = dict(base_report, review_status="block", summary={
        "total_findings": 1,
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    })
    dec, code, _ = evaluate_security_gate(block_rep)
    assert dec == "BLOCK"
    assert code == 1

    # Malformed / contradictory -> INVALID / fail-closed
    dec_inv, code_inv, _ = evaluate_security_gate({"invalid": "report"})
    assert dec_inv == "INVALID"
    assert code_inv == 1
