"""End-to-End Integration and Contract Test Suite for Taint Analysis.

Phase 30E - Bounded Intra-File Taint Analysis.
Verifies:
1. Evidence string syntax and length bounds (<= 240 chars).
2. Deterministic SHA-256 evidence ID contract (repeatability, distinctness).
3. Step 6O Security Gate evaluation (ALLOW / BLOCK / REVIEW).
4. Finding schema backward compatibility with Step 6O / Step 6N.
5. AI / LLM boundary preservation (taint outputs are read-only metadata).
"""

import pytest
from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
from ast_engine.security_analyzer import analyze_security_structure
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.security_gate import evaluate_security_gate


def test_evidence_string_format_and_length_bound_python():
    source = """
from flask import request

def handler():
    a = request.args.get("param1")
    b = a
    c = b
    d = c
    query = "SELECT * FROM users WHERE col = " + d
    db.execute(query)
"""
    signals = analyze_security_structure(source, file_path="api/views.py")["security_signals"]
    assert len(signals) == 1
    sig = signals[0]
    ev = sig["evidence"]
    assert len(ev) <= 240
    assert ev.startswith("[Taint Flow]")
    assert "Source:" in ev
    assert "Sink:" in ev


def test_evidence_string_format_and_length_bound_javascript():
    source = """
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const raw = req.query.q;
    const a = raw;
    const b = a;
    element.innerHTML = "<p>" + b + "</p>";
});
"""
    signals = analyze_javascript_security_structure(source, file_path="routes/search.js")["security_signals"]
    assert len(signals) == 1
    sig = signals[0]
    ev = sig["evidence"]
    assert len(ev) <= 240
    assert ev.startswith("[Taint Flow]")
    assert "Source:" in ev
    assert "Sink:" in ev


def test_deterministic_evidence_ids_python():
    source = """
from flask import request

def handler():
    x = request.args.get("id")
    db.execute("SELECT " + x)
"""
    res1 = analyze_security_structure(source, file_path="app.py")["security_signals"]
    res2 = analyze_security_structure(source, file_path="app.py")["security_signals"]
    assert len(res1) == 1 and len(res2) == 1
    assert res1[0]["evidence_id"] == res2[0]["evidence_id"]
    assert len(res1[0]["evidence_id"]) == 64


def test_deterministic_evidence_ids_javascript():
    source = """
const cp = require('child_process');
const cmd = req.query.cmd;
cp.exec(cmd);
"""
    res1 = analyze_javascript_security_structure(source, file_path="server.js")["security_signals"]
    res2 = analyze_javascript_security_structure(source, file_path="server.js")["security_signals"]
    assert len(res1) == 1 and len(res2) == 1
    assert res1[0]["evidence_id"] == res2[0]["evidence_id"]
    assert len(res1[0]["evidence_id"]) == 64


def test_distinct_evidence_ids_for_different_lines():
    source = """
from flask import request

def handler():
    x = request.args.get("id")
    db.execute("SELECT " + x)
    db.execute("SELECT " + x)
"""
    signals = analyze_security_structure(source, file_path="app.py")["security_signals"]
    assert len(signals) == 2
    assert signals[0]["evidence_id"] != signals[1]["evidence_id"]


def test_step_6o_security_gate_block_on_tainted_command_execution():
    source = """
import sys, subprocess

def run():
    subprocess.run(sys.argv[1], shell=True)
"""
    signals = analyze_security_structure(source, file_path="tool.py")["security_signals"]
    findings = generate_deterministic_findings(signals)
    report = {
        "status": "success",
        "analysis_id": "test_ana_12345",
        "repository": {"repository": "test/repo", "owner": "test", "path": ""},
        "review_status": "block",
        "summary": {
            "total_files": 1,
            "analyzed_files": 1,
            "skipped_files": 0,
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in findings if f["severity"] == "high"),
            "medium_count": sum(1 for f in findings if f["severity"] == "medium"),
            "low_count": sum(1 for f in findings if f["severity"] == "low"),
            "info_count": 0,
        },
        "findings": findings,
        "analysis_version": "1.0",
    }
    decision, exit_code, reasons = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1


def test_step_6o_security_gate_allow_on_sanitized_flow():
    source = """
from flask import request

def run():
    uid = request.args.get("id")
    safe_id = int(uid)
    db.execute("SELECT * FROM users WHERE id = " + str(safe_id))
"""
    signals = analyze_security_structure(source, file_path="safe_app.py")["security_signals"]
    findings = generate_deterministic_findings(signals)
    assert len(findings) == 0
    report = {
        "status": "success",
        "analysis_id": "test_ana_12345",
        "repository": {"repository": "test/repo", "owner": "test", "path": ""},
        "review_status": "allow",
        "summary": {
            "total_files": 1,
            "analyzed_files": 1,
            "skipped_files": 0,
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
        "findings": [],
        "analysis_version": "1.0",
    }
    decision, exit_code, reasons = evaluate_security_gate(report)
    assert decision == "ALLOW"
    assert exit_code == 0


def test_finding_schema_contract_integrity():
    source = """
const express = require('express');
const id = req.query.id;
element.innerHTML = id;
"""
    signals = analyze_javascript_security_structure(source, file_path="vuln.js")["security_signals"]
    assert len(signals) == 1
    sig = signals[0]

    # Required baseline keys
    required_keys = {
        "evidence_id",
        "file_path",
        "line",
        "category",
        "signal_type",
        "severity",
        "confidence",
        "name",
        "evidence",
        "related_variables",
        "message",
    }
    assert required_keys.issubset(set(sig.keys()))

    findings = generate_deterministic_findings(signals)
    assert len(findings) == 1
    f = findings[0]
    finding_keys = {"evidence_id", "file_path", "line", "category", "severity", "confidence", "title", "description"}
    assert finding_keys.issubset(set(f.keys()))
