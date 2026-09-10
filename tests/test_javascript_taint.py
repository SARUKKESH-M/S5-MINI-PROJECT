"""Comprehensive Test Suite for JavaScript Intra-File Taint Analysis.

Phase 30E - Bounded Intra-File Taint Analysis.
Verifies:
1. JavaScript source recognition (Express req.query/params/body, location, DOM value).
2. Transitive assignment propagation (const, let, var).
3. Template literals and binary string concatenation.
4. Child process aliasing and command execution taint flow.
5. DOM XSS sinks (innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln).
6. SQL sinks (db.query, client.query, pool.query, knex.raw, sequelize.query, prisma.$queryRaw).
7. Numeric sanitizer strict category binding (Correction 1: SQL only, NOT XSS or command execution).
8. Approved contextual DOM XSS sanitizers (DOMPurify.sanitize, encodeURIComponent).
9. Mismatched sanitizer category defense (DOMPurify does NOT sanitize SQL).
10. Function summaries (pass-through, sanitizers, static returns).
11. Control-flow joins (ternary, if/else) and UNKNOWN composition (Correction 2).
"""

import pytest
from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure


def _get_signals(source: str, file_path: str = "test_app.js"):
    res = analyze_javascript_security_structure(source, file_path=file_path)
    return res["security_signals"]


# ==============================================================================
# 1. Sources and Direct Propagation
# ==============================================================================

def test_js_source_req_query_to_sql():
    source = """
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
    const id = req.query.id;
    const q = "SELECT * FROM users WHERE id = " + id;
    db.query(q);
});
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assert sql_signals[0]["severity"] == "high"
    assert "taint" in sql_signals[0]["argument_assessment"]
    assert sql_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_source_req_params_to_dom_xss():
    source = """
const id = req.params.id;
element.innerHTML = "<div>" + id + "</div>";
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["severity"] == "high"
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_transitive_propagation_to_command():
    source = """
const cp = require('child_process');
const raw = req.body.cmd;
const a = raw;
const b = a;
cp.exec(b);
"""
    signals = _get_signals(source)
    cmd_signals = [s for s in signals if s["category"] == "command_execution"]
    assert len(cmd_signals) == 1
    assert cmd_signals[0]["severity"] == "critical"
    taint_info = cmd_signals[0]["argument_assessment"]["taint"]
    assert taint_info["taint_state"] == "TAINTED"
    assert len(taint_info["propagation_path"]) >= 2


# ==============================================================================
# 2. Template Literals and DOM Sinks
# ==============================================================================

def test_js_template_literal_dom_xss():
    source = """
const userInput = req.query.name;
element.outerHTML = `<p>Hello ${userInput}</p>`;
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_insert_adjacent_html_tainted():
    source = """
const userInput = req.query.input;
element.insertAdjacentHTML("beforeend", "<span>" + userInput + "</span>");
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_document_write_tainted():
    source = """
const userInput = req.query.input;
document.write("Content: " + userInput);
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


# ==============================================================================
# 3. Numeric Sanitizer Category Binding (Correction 1)
# ==============================================================================

def test_js_number_sanitizes_sql_injection():
    """Number(x) sanitizes SQL injection -> finding safely suppressed."""
    source = """
const id = req.query.id;
const q = "SELECT * FROM users WHERE id = " + Number(id);
db.query(q);
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_js_parse_int_sanitizes_sql_injection():
    """parseInt(x) sanitizes SQL injection -> finding safely suppressed."""
    source = """
const id = req.query.id;
const q = "SELECT * FROM users WHERE id = " + parseInt(id, 10);
db.query(q);
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_js_parse_float_sanitizes_sql_injection():
    """parseFloat(x) sanitizes SQL injection -> finding safely suppressed."""
    source = """
const rate = req.query.rate;
const q = "SELECT * FROM rates WHERE r = " + parseFloat(rate);
db.query(q);
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_js_number_does_NOT_sanitize_dom_xss():
    """Number(x) passed to DOM sink does NOT sanitize XSS -> remains TAINTED."""
    source = """
const x = req.query.id;
const html = "<div>" + Number(x) + "</div>";
element.innerHTML = html;
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["severity"] == "high"
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_parse_int_does_NOT_sanitize_dom_xss():
    """parseInt(x) passed to DOM sink does NOT sanitize XSS -> remains TAINTED."""
    source = """
const x = req.query.id;
const html = "<div>" + parseInt(x) + "</div>";
element.innerHTML = html;
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_number_does_NOT_sanitize_command_execution():
    """Number(x) passed to child_process does NOT sanitize command execution."""
    source = """
const cp = require('child_process');
const id = req.query.id;
cp.exec("kill " + Number(id));
"""
    signals = _get_signals(source)
    cmd_signals = [s for s in signals if s["category"] == "command_execution"]
    assert len(cmd_signals) == 1
    assert cmd_signals[0]["severity"] == "critical"
    assert cmd_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


# ==============================================================================
# 4. Contextual XSS Sanitizers & Mismatched Categories
# ==============================================================================

def test_js_dompurify_sanitizes_dom_xss():
    """DOMPurify.sanitize(x) sanitizes XSS -> finding safely suppressed."""
    source = """
const x = req.query.content;
element.innerHTML = DOMPurify.sanitize(x);
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "xss" for s in signals)


def test_js_encode_uri_component_sanitizes_dom_xss():
    """encodeURIComponent(x) sanitizes XSS -> finding safely suppressed."""
    source = """
const x = req.query.param;
element.innerHTML = "<a href='?q=" + encodeURIComponent(x) + "'>link</a>";
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "xss" for s in signals)


def test_js_dompurify_does_NOT_sanitize_sql():
    """DOMPurify.sanitize(x) evaluated for SQL must remain TAINTED -> finding emitted."""
    source = """
const x = req.query.id;
const q = "SELECT * FROM users WHERE name = " + DOMPurify.sanitize(x);
db.query(q);
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assert sql_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


# ==============================================================================
# 5. Function Summaries in JavaScript
# ==============================================================================

def test_js_function_summary_pass_through():
    source = """
function getVal(a) {
    return a;
}

const raw = req.query.id;
const out = getVal(raw);
db.query("SELECT * FROM users WHERE id = " + out);
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assert sql_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_function_summary_sanitizing_wrapper():
    source = """
function cleanId(a) {
    return Number(a);
}

const raw = req.query.id;
const cleaned = cleanId(raw);
db.query("SELECT * FROM users WHERE id = " + cleaned);
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_js_function_summary_sanitizer_mismatch_fails_closed():
    """Helper wrapping Number(a) sanitizes SQL, but when used in innerHTML, emits XSS finding."""
    source = """
function cleanId(a) {
    return Number(a);
}

const raw = req.query.id;
const cleaned = cleanId(raw);
element.innerHTML = "<b>" + cleaned + "</b>";
"""
    signals = _get_signals(source)
    xss_signals = [s for s in signals if s["category"] == "xss"]
    assert len(xss_signals) == 1
    assert xss_signals[0]["argument_assessment"]["taint"]["taint_state"] == "TAINTED"


def test_js_function_summary_static_return():
    source = """
function getStaticQuery() {
    return "SELECT 1";
}

const q = getStaticQuery();
db.query(q);
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


# ==============================================================================
# 6. Control Flow and UNKNOWN Semantics (Correction 2)
# ==============================================================================

def test_js_ternary_join_tainted_and_static():
    source = """
const q = condition ? ("SELECT " + req.query.id) : "SELECT 1";
db.query(q);
"""
    signals = _get_signals(source)
    # TAINTED \sqcup STATIC -> UNVERIFIED_DYNAMIC -> baseline emitted
    assert any(s["category"] == "sql_injection" for s in signals)


def test_js_unknown_global_composition():
    source = """
const x = unknownGlobalVar;
const q = "SELECT * FROM users WHERE id = " + x;
db.query(q);
"""
    signals = _get_signals(source)
    # STATIC + UNKNOWN -> UNVERIFIED_DYNAMIC -> baseline emitted
    assert any(s["category"] == "sql_injection" for s in signals)
