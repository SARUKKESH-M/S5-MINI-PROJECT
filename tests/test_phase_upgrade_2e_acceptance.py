"""CodeSentinel Upgrade 2E — Comprehensive End-to-End Acceptance Test Suite.

Validates the interaction and invariants of:
1. Upgrade 2B: AST rule quality, taint propagation, dynamic concatenation, and security-gate BLOCK decisions.
2. Upgrade 2C: Deterministic balanced RAG context selection and knowledge anti-starvation quota enforcement.
3. Upgrade 2D: GitHub webhook delivery idempotency, atomic concurrent claim fencing, and publication deduplication.
4. Step 6O Contract Invariance: Strict compliance with frozen Step 6O Production Report schema.
5. Deterministic Findings: Identical inputs produce bit-for-bit stable finding IDs and evidence ordering.
"""

import concurrent.futures
import copy
import os
import sys
import tempfile
from typing import Any, Dict, List
import pytest

# Ensure root and backend are on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ast_engine.security_analyzer import analyze_security_structure
from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings
from backend.analysis.report_service import build_repository_report, compute_review_status
from backend.analysis.security_gate import evaluate_security_gate, validate_security_report
from backend.analysis.storage.store import AnalysisStore, reset_database_initialization_cache
from backend.github.orchestrator import orchestrate_webhook_event
from backend.github.webhook import claim_webhook_delivery
from rag.context_builder import (
    build_security_analysis_context,
    MAX_CONTEXT_DOCUMENTS,
    MAX_CONTENT_LENGTH,
)
from rag.vector_store import (
    generate_transient_ast_collection_name,
    get_collection,
    delete_transient_collection,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.ingestion import ingest_documents


@pytest.fixture(autouse=True)
def clean_webhook_deliveries():
    """Override global clean_webhook_deliveries to avoid shared DB access."""
    yield


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Provide an isolated SQLite database file path."""
    reset_database_initialization_cache()
    db_file = str(tmp_path / "upgrade_2e_acceptance.db")
    monkeypatch.setenv("CODESENTINEL_DB_PATH", db_file)
    store = AnalysisStore(db_path=db_file)
    store.initialize()
    yield db_file
    reset_database_initialization_cache()


# ==============================================================================
# SCENARIO 1: Detection & Security Gate Invariance (Upgrade 2B)
# ==============================================================================

def test_upgrade_2e_detection_and_security_gate():
    """Verify high-severity JS SQLi and Python path traversal produce BLOCK gate decision, while safe code produces ALLOW."""
    # 1. Hostile / Vulnerable JavaScript (Express req.query concatenation into SQL)
    js_vuln = """
    app.get('/users', (req, res) => {
        const query = "SELECT * FROM users WHERE username = '" + req.query.user + "'";
        db.query(query);
    });
    """
    js_res = analyze_javascript_security_structure(js_vuln, file_path="server.js")
    js_signals = [s for s in js_res["security_signals"] if s["signal_type"] == "unsafe_database_execution"]
    assert len(js_signals) >= 1
    assert js_signals[0]["severity"] == "high"
    assert js_signals[0]["category"] == "sql_injection"

    # 2. Hostile / Vulnerable Python (dynamic path traversal with string concatenation)
    py_vuln = """
    def read_document(base_dir, user_file):
        full_path = base_dir + "/" + user_file
        with open(full_path, "r") as f:
            return f.read()
    """
    py_res = analyze_security_structure(py_vuln, file_path="reader.py")
    py_signals = [s for s in py_res["security_signals"] if s["signal_type"] == "path_traversal_call"]
    assert len(py_signals) >= 1
    assert py_signals[0]["severity"] == "high"
    assert py_signals[0]["argument_assessment"]["path_kind"] == "string_concatenation"

    # 3. Deterministic finding generation & category preservation
    all_signals = js_signals + py_signals
    raw_findings = generate_deterministic_findings(all_signals)
    categories = {f["category"] for f in raw_findings}
    assert "Injection" in categories
    assert "File Security" in categories

    # 4. Aggregation and Step 6O Report building
    agg_res = aggregate_and_deduplicate_findings(raw_findings, file_stats={"total_files": 2, "analyzed_files": 2, "skipped_files": 0})
    analysis_record = {
        "status": "success",
        "analysis_id": "ana_u2e_vuln_001",
        "repository": {"owner": "test-org", "repository": "test-repo", "branch": "main", "path": "."},
        "summary": agg_res["summary"],
        "findings": agg_res["findings"],
        "analysis_version": "1.0",
    }
    report = build_repository_report(analysis_record)
    assert report["review_status"] == "block"
    assert report["summary"]["high_count"] >= 2

    # 5. Security gate must evaluate to BLOCK with exit_code=1
    decision, exit_code, msg = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1
    assert "BLOCK" in msg

    # 6. Safe Code Baseline Verification (Parameterized SQL & resolved static path)
    js_safe = "db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);"
    py_safe = 'BASE = "/var/log/app.log"\nwith open(BASE) as f: pass'
    safe_signals = (
        analyze_javascript_security_structure(js_safe, file_path="safe.js")["security_signals"]
        + analyze_security_structure(py_safe, file_path="safe.py")["security_signals"]
    )
    safe_findings = generate_deterministic_findings(safe_signals)
    safe_agg = aggregate_and_deduplicate_findings(safe_findings, file_stats={"total_files": 2, "analyzed_files": 2, "skipped_files": 0})
    safe_report = build_repository_report({
        "status": "success",
        "analysis_id": "ana_u2e_safe_001",
        "repository": {"owner": "test-org", "repository": "test-repo", "branch": "main", "path": "."},
        "summary": safe_agg["summary"],
        "findings": safe_agg["findings"],
        "analysis_version": "1.0",
    })
    safe_decision, safe_exit, _ = evaluate_security_gate(safe_report)
    assert safe_decision == "ALLOW"
    assert safe_exit == 0


# ==============================================================================
# SCENARIO 2: Balanced RAG Context Selection & Anti-Starvation (Upgrade 2C)
# ==============================================================================

def test_upgrade_2e_balanced_rag_context_selection():
    """Verify balanced RAG selection guarantees equal quota (up to 10 each) and prevents AST from starving security knowledge."""
    transient_ast_name = generate_transient_ast_collection_name("u2e_balanced_test")
    try:
        # Ingest 15 AST documents
        ast_docs = [
            {
                "document_id": f"ast_doc_{i:02d}",
                "content": f"AST syntax node for security call pattern {i} in application module.",
                "metadata": {"source_category": "ast", "language": "python", "node_type": "call_expression"},
            }
            for i in range(15)
        ]
        ingest_documents(documents=ast_docs, collection_name=transient_ast_name)

        # Ingest 15 Security Knowledge documents into knowledge collection
        kn_docs = [
            {
                "document_id": f"kn_doc_{i:02d}",
                "content": f"Security guidance and remediation pattern {i} for SQL injection and CWE-89.",
                "metadata": {"source_category": "security_knowledge", "topic": "sql_injection", "cwe_id": "CWE-89"},
            }
            for i in range(15)
        ]
        ingest_documents(documents=kn_docs, collection_name=SECURITY_KNOWLEDGE_COLLECTION_NAME)

        # Build security analysis context requesting top_k=10
        context_res = build_security_analysis_context(
            query="SQL injection vulnerability pattern and remediation guidance",
            top_k=10,
            ast_collection_name=transient_ast_name,
        )

        assert context_res["status"] == "success"
        bounded_docs = context_res.get("context_documents", [])
        assert len(bounded_docs) <= MAX_CONTEXT_DOCUMENTS

        # Category quota check: category_quota = min(10, 20 // 2) = 10
        # Neither category should starve the other; each should have 10 documents
        ast_count = context_res.get("ast_context_count", 0)
        kn_count = context_res.get("security_knowledge_context_count", 0)
        assert ast_count == 10, f"Expected 10 AST documents, got {ast_count}"
        assert kn_count == 10, f"Expected 10 Knowledge documents, got {kn_count}"

        # Deterministic ranking order: rank 1 to 20
        ranks = [d["rank"] for d in bounded_docs]
        assert ranks == list(range(1, len(bounded_docs) + 1))

        # Size constraint: each document content length bounded
        for doc in bounded_docs:
            assert len(doc["content"]) <= MAX_CONTENT_LENGTH

    finally:
        delete_transient_collection(transient_ast_name)


# ==============================================================================
# SCENARIO 3: Webhook Idempotency & Concurrent Claim Fencing (Upgrade 2D)
# ==============================================================================

def test_upgrade_2e_webhook_idempotency_and_concurrent_fencing(isolated_db):
    """Verify atomic delivery claiming under concurrency and idempotency of webhook orchestration."""
    store = AnalysisStore(db_path=isolated_db)

    # 1. Concurrent delivery claiming: exactly 1 thread wins the claim
    delivery_id = "del_u2e_concurrent_001"
    winners = []

    def attempt_claim(worker_id: int):
        claimed = claim_webhook_delivery(delivery_id, "pull_request", db_path=isolated_db)
        if claimed:
            winners.append(worker_id)
        return claimed

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt_claim, range(8)))

    assert results.count(True) == 1, f"Expected exactly 1 claim winner, got {results.count(True)}"
    assert results.count(False) == 7
    assert len(winners) == 1
    assert store.is_delivery_claimed(delivery_id) is True

    # 2. End-to-End Orchestration Duplicate Prevention
    orchestration_delivery_id = "del_u2e_orchestration_002"
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "head": {"sha": "c" * 40},
            "base": {"sha": "d" * 40},
            "title": "Fix security vulnerability",
            "user": {"login": "dev_sec"},
            "html_url": "https://github.com/test-owner/test-repo/pull/42",
        },
        "repository": {"owner": {"login": "test-owner"}, "name": "test-repo"},
    }

    # Mock client and analyzer to track invocations
    analysis_invocations = 0

    def mock_generate_report(*args, **kwargs):
        nonlocal analysis_invocations
        analysis_invocations += 1
        return {
            "status": "success",
            "analysis_id": "ana_u2e_orch_001",
            "summary": {"total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0},
            "findings": [],
        }

    from unittest.mock import patch
    with patch("backend.github.orchestrator._generate_pr_analysis_report", side_effect=mock_generate_report), \
         patch("backend.github.orchestrator.acquire_pull_request") as mock_acq, \
         patch("backend.github.orchestrator.publish_step_6o_report_status") as mock_pub, \
         patch("backend.github.orchestrator.post_pr_security_comment") as mock_comment:

        from unittest.mock import MagicMock
        mock_acq.return_value = MagicMock(
            owner="test-owner", repository="test-repo", pr_number=42,
            head_sha="c" * 40, base_sha="d" * 40, title="PR", changed_files=[]
        )
        mock_pub.return_value = {"status": "success", "check_run_id": 1001}
        mock_comment.return_value = {"status": "success", "comment_id": 2002}

        # First delivery: executes analysis and publication
        res1 = orchestrate_webhook_event("pull_request", orchestration_delivery_id, payload, db_path=isolated_db)
        assert res1["status"] == "success"
        assert analysis_invocations == 1
        assert mock_pub.call_count == 1
        assert mock_comment.call_count == 1

        # Second delivery with identical ID: must be recognized as duplicate
        res2 = orchestrate_webhook_event("pull_request", orchestration_delivery_id, payload, db_path=isolated_db)
        assert res2["status"] == "duplicate"
        assert res2["reason"] == "delivery_already_processed"
        # Analysis and publications must NOT have run a second time!
        assert analysis_invocations == 1
        assert mock_pub.call_count == 1
        assert mock_comment.call_count == 1


# ==============================================================================
# SCENARIO 4: Frozen Step 6O Report Contract Invariance
# ==============================================================================

def test_upgrade_2e_step_6o_contract_invariance():
    """Verify that build_repository_report produces canonical Step 6O fields and strips forbidden internals."""
    raw_record = {
        "status": "success",
        "analysis_id": "ana_contract_inv_001",
        "repository": {"owner": "test-org", "repository": "core-engine", "branch": "release", "path": "."},
        "summary": {
            "total_files": 10,
            "analyzed_files": 10,
            "skipped_files": 0,
            "total_findings": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
        "findings": [
            {
                "finding_id": "finding_1",
                "title": "SQL Injection in User Lookup",
                "description": "User input concatenated directly into SQL statement.",
                "severity": "high",
                "confidence": "high",
                "category": "Injection",
                "evidence": [
                    {
                        "document_id": "ast_ev_001",
                        "line_start": 42,
                        "line_end": 42,
                        "signal_type": "unsafe_database_execution",
                        "signal_name": "db.query",
                    }
                ],
                # Forbidden fields that MUST be stripped
                "raw_source_code": "SELECT * FROM users",
                "prompt": "Evaluate this vulnerability",
                "llm_token_count": 450,
                "internal_trace": "stacktrace_data",
            }
        ],
        "analysis_version": "1.0",
    }

    report = build_repository_report(raw_record)

    # 1. Exact top-level contract fields
    expected_top_keys = {"status", "review_status", "analysis_id", "repository", "summary", "findings", "analysis_version"}
    assert set(report.keys()) == expected_top_keys

    # 2. Validation by security gate schema checker
    is_valid, err_msg, summary = validate_security_report(report)
    assert is_valid is True, f"Contract validation failed: {err_msg}"
    assert summary["high_count"] == 1

    # 3. Forbidden fields stripped from findings
    finding = report["findings"][0]
    forbidden_keys = {"raw_source_code", "prompt", "llm_token_count", "internal_trace"}
    for fk in forbidden_keys:
        assert fk not in finding, f"Forbidden key {fk} was not stripped from finding"

    # 4. Mandatory finding fields preserved
    assert finding["finding_id"] == "finding_1"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["category"] == "Injection"
    assert len(finding["evidence"]) == 1
    assert finding["evidence"][0]["line_start"] == 42


# ==============================================================================
# SCENARIO 5: Deterministic Finding Identity & Ordering
# ==============================================================================

def test_upgrade_2e_deterministic_finding_identity():
    """Verify that equivalent AST evidence inputs produce identical, stable finding IDs, categories, and evidence ordering."""
    evidence_sample = [
        {
            "evidence_id": "ev_sql_001",
            "signal_type": "unsafe_database_execution",
            "category": "sql_injection",
            "severity": "high",
            "confidence": "high",
            "file_path": "service/db.py",
            "line": 15,
            "call_name": "cursor.execute",
            "message": "Dynamic SQL concatenation",
        },
        {
            "evidence_id": "ev_path_002",
            "signal_type": "path_traversal_call",
            "category": "path_traversal",
            "severity": "high",
            "confidence": "high",
            "file_path": "service/files.py",
            "line": 88,
            "call_name": "open",
            "message": "Unvalidated path traversal",
        },
    ]

    # Run pass 1
    pass1_raw = generate_deterministic_findings(copy.deepcopy(evidence_sample))
    pass1_agg = aggregate_and_deduplicate_findings(pass1_raw)

    # Run pass 2 (reversed input order to test deterministic sorting)
    pass2_raw = generate_deterministic_findings(copy.deepcopy(evidence_sample[::-1]))
    pass2_agg = aggregate_and_deduplicate_findings(pass2_raw)

    # Verify findings lists are identical
    f1 = pass1_agg["findings"]
    f2 = pass2_agg["findings"]
    assert len(f1) == len(f2) == 2

    for item1, item2 in zip(f1, f2):
        assert item1["finding_id"] == item2["finding_id"]
        assert item1["title"] == item2["title"]
        assert item1["severity"] == item2["severity"]
        assert item1["category"] == item2["category"]
        assert item1["evidence"] == item2["evidence"]
