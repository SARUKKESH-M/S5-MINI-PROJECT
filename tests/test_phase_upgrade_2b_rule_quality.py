"""Comprehensive Verification Test Suite for CodeSentinel Upgrade 2B.

Verifies:
1. JavaScript SQL injection detection for direct user taint and unverified parameters.
2. JavaScript SQL injection safety preservation for resolved static strings.
3. Python path traversal false-positive suppression for resolved local and module static variables.
4. Python path traversal dynamic concatenation severity accuracy.
5. Deterministic finding category idempotency across canonical categories.
6. Evidence line_end mapping fidelity for multi-line findings.
7. End-to-end AST determinism and Step 6O Security Gate invariance.
"""

import pytest

from ast_engine.security_analyzer import analyze_security_structure
from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.report_service import compute_review_status
from backend.analysis.security_gate import evaluate_security_gate


# ==============================================================================
# 1. JavaScript SQL Injection Improvements & Regressions
# ==============================================================================

def test_js_sql_dynamic_concatenation_with_taint_detected():
    """Verify dynamic SQL concatenation with Express req.query emits high-severity SQL injection with taint flow."""
    js = """
    app.get('/search', (req, res) => {
        db.query("SELECT * FROM users WHERE id = " + req.query.id);
    });
    """
    res = analyze_javascript_security_structure(js, file_path="search.js")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "unsafe_database_execution"]
    assert len(signals) == 1
    assert signals[0]["severity"] == "high"
    assert signals[0]["confidence"] == "high"
    assert signals[0]["category"] == "sql_injection"
    assert "taint" in signals[0]["argument_assessment"]
    assert signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_sql_template_literal_with_taint_detected():
    """Verify template literal with Express req.query emits high-severity SQL injection with taint."""
    js = """
    app.get('/search', (req, res) => {
        db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
    });
    """
    res = analyze_javascript_security_structure(js, file_path="search.js")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "unsafe_database_execution"]
    assert len(signals) == 1
    assert signals[0]["severity"] == "high"
    assert signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_sql_unverified_function_parameter_is_deferred():
    """Verify unparameterized bare query argument without taint is deferred per test_53/54 contract."""
    js = """
    function executeUserQuery(query) {
        db.query(query);
    }
    """
    res = analyze_javascript_security_structure(js, file_path="db_helper.js")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "unsafe_database_execution"]
    assert len(signals) == 0


def test_js_sql_resolved_static_variable_is_safe():
    """Verify local const query = 'SELECT 1'; db.query(query) does not trigger false positive."""
    js = """
    function getStatus() {
        const query = "SELECT 1";
        db.query(query);
    }
    """
    res = analyze_javascript_security_structure(js, file_path="status.js")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "unsafe_database_execution"]
    assert len(signals) == 0


def test_js_sql_parameterized_query_remains_safe():
    """Verify parameterized query with array placeholder remains safe."""
    js = """
    function getUser(userId) {
        db.query("SELECT * FROM users WHERE id = ?", [userId]);
    }
    """
    res = analyze_javascript_security_structure(js, file_path="user.js")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "unsafe_database_execution"]
    assert len(signals) == 0


# ==============================================================================
# 2. Python Path Traversal False-Positive Suppression & Severity
# ==============================================================================

def test_python_path_traversal_local_static_variable_is_safe():
    """Verify local variable assigned a static string literal is not reported as path traversal."""
    py = """
    def read_config():
        p = "config.json"
        open(p)
    """
    res = analyze_security_structure(py, file_path="config.py")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "path_traversal_call"]
    assert len(signals) == 0


def test_python_path_traversal_module_static_variable_is_safe():
    """Verify module-level constant path is not reported as path traversal."""
    py = """
    DEFAULT_CONFIG = "/etc/app/config.ini"

    def read_default():
        open(DEFAULT_CONFIG)
    """
    res = analyze_security_structure(py, file_path="loader.py")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "path_traversal_call"]
    assert len(signals) == 0


def test_python_path_traversal_resolved_concatenation_is_high_severity():
    """Verify variable assigned string concatenation is correctly resolved as high severity."""
    py = """
    def get_document(filename):
        target_path = "/uploads/" + filename
        open(target_path)
    """
    res = analyze_security_structure(py, file_path="docs.py")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "path_traversal_call"]
    assert len(signals) == 1
    assert signals[0]["severity"] == "high"
    assert signals[0]["confidence"] == "high"
    assert signals[0]["argument_assessment"]["path_kind"] == "string_concatenation"


def test_python_path_traversal_unresolved_parameter_remains_medium_severity():
    """Verify unverified function parameter path retains conservative medium severity fallback."""
    py = """
    def read_file(user_path):
        open(user_path)
    """
    res = analyze_security_structure(py, file_path="io_util.py")
    signals = [s for s in res["security_signals"] if s["signal_type"] == "path_traversal_call"]
    assert len(signals) == 1
    assert signals[0]["severity"] == "medium"
    assert signals[0]["confidence"] == "medium"
    assert signals[0]["argument_assessment"]["path_kind"] == "dynamic_expression"


# ==============================================================================
# 3. Deterministic Findings Category Idempotence & Line End Support
# ==============================================================================

def test_canonical_category_idempotence():
    """Verify canonical category names are preserved without falling back to General Security."""
    categories_to_test = [
        ("Injection", "Injection"),
        ("sql_injection", "Injection"),
        ("command_execution", "Injection"),
        ("Code Execution", "Code Execution"),
        ("dynamic_code_execution", "Code Execution"),
        ("Credential Management", "Credential Management"),
        ("credential_management", "Credential Management"),
        ("File Security", "File Security"),
        ("path_traversal", "File Security"),
        ("Deserialization", "Deserialization"),
        ("insecure_deserialization", "Deserialization"),
        ("Cross-Site Scripting", "Cross-Site Scripting"),
        ("xss", "Cross-Site Scripting"),
    ]

    for input_cat, expected_cat in categories_to_test:
        raw_evidence = [{
            "evidence_id": "test_ev_001",
            "signal_type": "unsafe_database_execution",
            "category": input_cat,
            "severity": "high",
            "line": 42,
            "call_name": "db.execute",
        }]
        findings = generate_deterministic_findings(raw_evidence)
        assert len(findings) == 1
        assert findings[0]["category"] == expected_cat, f"Failed for input category: {input_cat}"


def test_finding_evidence_preserves_line_end():
    """Verify line_end is accurately mapped into evidence when provided."""
    raw_evidence = [{
        "evidence_id": "test_multiline_001",
        "signal_type": "command_execution_call",
        "category": "command_execution",
        "severity": "critical",
        "line": 10,
        "line_end": 14,
        "call_name": "subprocess.run",
    }]
    findings = generate_deterministic_findings(raw_evidence)
    assert len(findings) == 1
    ev_record = findings[0]["evidence"][0]
    assert ev_record["line_start"] == 10
    assert ev_record["line_end"] == 14


# ==============================================================================
# 4. AST Determinism & Security Gate Invariance
# ==============================================================================

def test_upgrade_2b_ast_determinism_repeated_runs():
    """Verify identical outputs across multiple runs of updated analyzer rules."""
    js_code = """
    app.get('/query', (req, res) => {
        db.query(req.query.sql);
    });
    """
    res1 = analyze_javascript_security_structure(js_code, file_path="app.js")
    res2 = analyze_javascript_security_structure(js_code, file_path="app.js")
    f1 = generate_deterministic_findings(res1["security_signals"])
    f2 = generate_deterministic_findings(res2["security_signals"])
    assert res1 == res2
    assert f1 == f2


def test_upgrade_2b_security_gate_integration():
    """Verify detected high-severity SQL finding triggers BLOCK gate decision."""
    js = "db.query('SELECT * FROM users WHERE id = ' + req.query.sql);"
    res = analyze_javascript_security_structure(js, file_path="app.js")
    findings = generate_deterministic_findings(res["security_signals"])
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"

    summary = {
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }
    report = {
        "status": "success",
        "review_status": compute_review_status(summary),
        "summary": summary,
        "findings": findings,
    }
    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1
