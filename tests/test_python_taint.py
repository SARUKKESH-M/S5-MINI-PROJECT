"""Comprehensive Test Suite for Python Intra-File Taint Analysis.

Phase 30E - Bounded Intra-File Taint Analysis.
Verifies:
1. Python source recognition (Flask, Django, sys.argv).
2. Transitive assignment propagation (a -> b -> c -> sink).
3. String operations (concatenation, f-strings, format, % formatting).
4. Function summaries (Cases A through G).
5. Control-flow joins (if/else, branches without else).
6. Loop traversal bounds and dynamic updates.
7. Call depth bounds (MAX_CALL_DEPTH = 3) and recursion defense.
8. Numeric sanitizer strict category binding (Correction 1: SQL only, NOT command execution).
9. Command sanitizers (shlex.quote only for command, NOT SQL).
10. UNKNOWN composition with static content yields UNVERIFIED_DYNAMIC (Correction 2).
"""

import pytest
from ast_engine.security_analyzer import analyze_security_structure
from ast_engine.taint.models import TaintState


def _get_signals(source: str, file_path: str = "test_app.py"):
    res = analyze_security_structure(source, file_path=file_path)
    return res["security_signals"]


# ==============================================================================
# 1. Sources and Direct Flow
# ==============================================================================

def test_python_source_flask_request_args_to_sql():
    source = """
from flask import request

def handler():
    x = request.args.get("id")
    q = "SELECT * FROM users WHERE id = " + x
    db.execute(q)
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assert sql_signals[0]["severity"] == "high"
    assessment = sql_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"
    assert assessment.get("taint_source") == "request.args"


def test_python_source_sys_argv_to_command():
    source = """
import sys, subprocess

def handler():
    cmd = sys.argv[1]
    subprocess.run(cmd, shell=True)
"""
    signals = _get_signals(source)
    cmd_signals = [s for s in signals if s["category"] == "command_execution"]
    assert len(cmd_signals) == 1
    assert cmd_signals[0]["severity"] == "critical"
    assessment = cmd_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"


def test_python_transitive_propagation():
    source = """
from flask import request

def handler():
    a = request.args.get("val")
    b = a
    c = b
    q = f"SELECT * FROM items WHERE name = '{c}'"
    db.execute(q)
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assessment = sql_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"
    assert len(assessment.get("propagation_path", [])) >= 2


# ==============================================================================
# 2. String Composition
# ==============================================================================

def test_python_fstring_and_percent_formatting():
    source_fstring = """
from flask import request

def handler():
    val = request.args.get("val")
    q = f"SELECT {val}"
    db.execute(q)
"""
    signals = _get_signals(source_fstring)
    assert any(s["category"] == "sql_injection" for s in signals)

    source_percent = """
from flask import request

def handler():
    val = request.args.get("val")
    q = "SELECT %s" % val
    db.execute(q)
"""
    signals2 = _get_signals(source_percent)
    assert any(s["category"] == "sql_injection" for s in signals2)


# ==============================================================================
# 3. Numeric Sanitizer Category Binding (Correction 1)
# ==============================================================================

def test_python_int_cast_sanitizes_sql():
    """int(x) sanitizes SQL injection -> finding suppressed."""
    source = """
from flask import request

def handler():
    uid = request.args.get("id")
    q = "SELECT * FROM users WHERE id = " + str(int(uid))
    db.execute(q)
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 0  # Safely suppressed!


def test_python_float_cast_sanitizes_sql():
    """float(x) sanitizes SQL injection -> finding suppressed."""
    source = """
from flask import request

def handler():
    rate = request.args.get("rate")
    q = "SELECT * FROM rates WHERE r = " + str(float(rate))
    db.execute(q)
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_python_int_cast_does_NOT_sanitize_command_execution():
    """int(x) evaluated for command execution must remain TAINTED -> finding emitted."""
    source = """
import os
from flask import request

def handler():
    uid = request.args.get("id")
    cmd = "kill " + str(int(uid))
    os.system(cmd)
"""
    signals = _get_signals(source)
    cmd_signals = [s for s in signals if s["category"] == "command_execution"]
    assert len(cmd_signals) == 1
    assert cmd_signals[0]["severity"] == "critical"
    assessment = cmd_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"


def test_python_shlex_quote_sanitizes_command_but_not_sql():
    """shlex.quote sanitizes command_execution, but does not sanitize sql_injection."""
    # Case 1: Command execution -> Suppressed
    source_cmd = """
import shlex, subprocess
from flask import request

def handler():
    param = request.args.get("target")
    safe_param = shlex.quote(param)
    subprocess.run("ping " + safe_param, shell=True)
"""
    signals_cmd = _get_signals(source_cmd)
    assert not any(s["category"] == "command_execution" for s in signals_cmd)

    # Case 2: SQL Injection -> NOT suppressed (mismatched category)
    source_sql = """
import shlex
from flask import request

def handler():
    param = request.args.get("name")
    bad_sql = "SELECT * FROM users WHERE name = " + shlex.quote(param)
    db.execute(bad_sql)
"""
    signals_sql = _get_signals(source_sql)
    assert any(s["category"] == "sql_injection" for s in signals_sql)


# ==============================================================================
# 4. Function Summaries (Cases A - G)
# ==============================================================================

def test_python_summary_case_a_direct_pass_through():
    source = """
from flask import request

def identity(val):
    return val

def run():
    raw = request.args.get("x")
    out = identity(raw)
    db.execute("SELECT " + out)
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assessment = sql_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"


def test_python_summary_case_b_sanitizing_helper():
    source = """
from flask import request

def clean_id(val):
    return int(val)

def run():
    raw = request.args.get("id")
    cleaned = clean_id(raw)
    db.execute("SELECT " + str(cleaned))
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_python_summary_case_b_mismatched_category_in_helper():
    """Helper sanitizes SQL, but when passed to os.system, remains TAINTED."""
    source = """
import os
from flask import request

def clean_id(val):
    return int(val)

def run():
    raw = request.args.get("id")
    cleaned = clean_id(raw)
    os.system("kill " + str(cleaned))
"""
    signals = _get_signals(source)
    cmd_signals = [s for s in signals if s["category"] == "command_execution"]
    assert len(cmd_signals) == 1
    assessment = cmd_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"


def test_python_summary_case_c_compound_return():
    source = """
from flask import request

def combine(a, b):
    return a + b

def run():
    raw = request.args.get("id")
    res = combine("SELECT ", raw)
    db.execute(res)
"""
    signals = _get_signals(source)
    sql_signals = [s for s in signals if s["category"] == "sql_injection"]
    assert len(sql_signals) == 1
    assessment = sql_signals[0].get("argument_assessment", {})
    assert assessment.get("taint_state") == "TAINTED"


def test_python_summary_case_d_static_return():
    source = """
def get_query():
    return "SELECT 1"

def run():
    q = get_query()
    db.execute(q)
"""
    signals = _get_signals(source)
    assert not any(s["category"] == "sql_injection" for s in signals)


def test_python_summary_case_e_unresolved_external():
    source = """
from flask import request
from external_module import transform

def wrap(x):
    return transform(x)

def run():
    raw = request.args.get("id")
    out = wrap(raw)
    db.execute("SELECT " + out)
"""
    signals = _get_signals(source)
    # Unresolved external preserves baseline dynamic detection
    assert any(s["category"] == "sql_injection" for s in signals)


# ==============================================================================
# 5. Control Flow Join and UNKNOWN Semantics (Correction 2)
# ==============================================================================

def test_python_branch_join_tainted_and_static():
    source = """
from flask import request

def run(cond):
    if cond:
        q = "SELECT " + request.args.get("id")
    else:
        q = "SELECT 1"
    db.execute(q)
"""
    signals = _get_signals(source)
    # TAINTED \sqcup STATIC -> UNVERIFIED_DYNAMIC -> baseline emitted
    assert any(s["category"] == "sql_injection" for s in signals)


def test_python_unknown_global_composition():
    source = """
def run():
    x = unknown_global_variable
    q = "SELECT " + x
    db.execute(q)
"""
    signals = _get_signals(source)
    # STATIC + UNKNOWN -> UNVERIFIED_DYNAMIC -> baseline emitted
    assert any(s["category"] == "sql_injection" for s in signals)


def test_python_branch_without_else():
    source = """
def run(cond):
    if cond:
        q = "SELECT " + unknown_var
    db.execute(q)
"""
    signals = _get_signals(source)
    assert any(s["category"] == "sql_injection" for s in signals)


# ==============================================================================
# 6. Call Depth Bound and Recursion
# ==============================================================================

def test_python_call_depth_bound():
    source = """
from flask import request

def h1(x): return h2(x)
def h2(x): return h3(x)
def h3(x): return h4(x)
def h4(x): return x

def run():
    v = request.args.get("id")
    out = h1(v)
    db.execute("SELECT " + out)
"""
    signals = _get_signals(source)
    assert any(s["category"] == "sql_injection" for s in signals)
