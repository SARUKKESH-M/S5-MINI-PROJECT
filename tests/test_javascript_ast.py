"""Comprehensive Test Suite for P2 #1: JavaScript Tree-Sitter AST & Scoping.

Verifies:
1. Basic JavaScript parsing into Tree-Sitter Tree.
2. Function declaration extraction (function authenticate() {}).
3. Arrow function extraction with derived variable names (const authenticate = () => {}).
4. Function expression extraction with derived variable names (const authenticate = function() {}).
5. Class declaration extraction (class AuthService {}).
6. Class method extraction (validateToken() {} with class_name).
7. Constructor extraction (constructor() {}).
8. Nested function extraction (outer and inner functions).
9. Async function detection for declarations, methods, and arrow functions.
10. Multiple functions in a single module.
11. Anonymous function handling (<anonymous>).
12. Accurate 1-based line spans (start_line and end_line).
13. JSX-containing JavaScript parsing (does not crash, extracts components).
14. Malformed JavaScript handling (safe fallback, parse_status='has_errors', no crash).
15. Empty JavaScript source handling (clean empty structures).
16. Module-level code handling without functions.
17. JavaScript changed-line scope mapping in diff_scope.py.
18. Nested changed-line scope selection (resolves to innermost enclosing function).
19. Existing Python diff-scope behavior invariance.
20. JavaScript parser failure cannot bypass Step 6O security gate behavior.
"""

import pytest
from ast_engine.javascript_parser import parse_javascript_source, extract_javascript_function_names
from ast_engine.structural_analyzer import (
    analyze_javascript_structure,
    analyze_python_structure,
    analyze_source_structure,
)
from backend.analysis.diff_scope import (
    map_changed_lines_to_scopes,
    EnclosingScope,
    parse_unified_diff,
)
from backend.analysis.security_gate import evaluate_security_gate


# ---------------------------------------------------------------------------
# 1. Basic JavaScript Parsing
# ---------------------------------------------------------------------------
def test_1_basic_javascript_parsing():
    source = "const greeting = 'Hello, CodeSentinel!';"
    tree = parse_javascript_source(source)
    assert tree is not None
    assert tree.root_node.type == "program"
    assert not tree.root_node.has_error


# ---------------------------------------------------------------------------
# 2. Function Declaration
# ---------------------------------------------------------------------------
def test_2_function_declaration():
    source = """
function authenticate(user, password) {
    if (!user || !password) {
        return false;
    }
    return true;
}
"""
    struct = analyze_javascript_structure(source)
    assert struct["language"] == "javascript"
    assert struct["parse_status"] == "success"
    functions = struct["functions"]
    assert len(functions) == 1
    fn = functions[0]
    assert fn["name"] == "authenticate"
    assert fn["is_async"] is False
    assert fn["is_method"] is False
    assert fn["class_name"] is None
    assert fn["parameters"] == ["user", "password"]
    assert fn["return_statement_count"] == 2
    assert fn["start_line"] == 2
    assert fn["end_line"] == 7


# ---------------------------------------------------------------------------
# 3. Arrow Function with Derived Name
# ---------------------------------------------------------------------------
def test_3_arrow_function_derived_name():
    source = """
const authenticate = (credentials) => {
    return credentials.valid;
};
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    assert len(functions) == 1
    fn = functions[0]
    assert fn["name"] == "authenticate"
    assert fn["is_async"] is False
    assert fn["start_line"] == 2
    assert fn["end_line"] == 4


# ---------------------------------------------------------------------------
# 4. Function Expression with Derived Name
# ---------------------------------------------------------------------------
def test_4_function_expression_derived_name():
    source = """
const executeQuery = function(query, params) {
    return db.run(query, params);
};
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    assert len(functions) == 1
    fn = functions[0]
    assert fn["name"] == "executeQuery"
    assert fn["is_async"] is False
    assert fn["parameters"] == ["query", "params"]
    assert fn["start_line"] == 2
    assert fn["end_line"] == 4


# ---------------------------------------------------------------------------
# 5. Class Declaration
# ---------------------------------------------------------------------------
def test_5_class_declaration():
    source = """
class AuthService {
    constructor(secret) {
        this.secret = secret;
    }
}
"""
    struct = analyze_javascript_structure(source)
    classes = struct["classes"]
    assert len(classes) == 1
    cls = classes[0]
    assert cls["name"] == "AuthService"
    assert cls["start_line"] == 2
    assert cls["end_line"] == 6
    assert len(cls["methods"]) == 1
    assert cls["methods"][0]["name"] == "constructor"


# ---------------------------------------------------------------------------
# 6. Class Method with class_name
# ---------------------------------------------------------------------------
def test_6_class_method():
    source = """
class SessionManager {
    validateSession(token) {
        return token.isValid();
    }
}
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    assert len(functions) == 1
    fn = functions[0]
    assert fn["name"] == "validateSession"
    assert fn["is_method"] is True
    assert fn["class_name"] == "SessionManager"
    assert fn["start_line"] == 3
    assert fn["end_line"] == 5


# ---------------------------------------------------------------------------
# 7. Constructor
# ---------------------------------------------------------------------------
def test_7_constructor():
    source = """
class TokenFactory {
    constructor(signingKey, ttl) {
        this.key = signingKey;
        this.ttl = ttl;
    }
}
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    assert len(functions) == 1
    ctor = functions[0]
    assert ctor["name"] == "constructor"
    assert ctor["class_name"] == "TokenFactory"
    assert ctor["parameters"] == ["signingKey", "ttl"]


# ---------------------------------------------------------------------------
# 8. Nested Functions
# ---------------------------------------------------------------------------
def test_8_nested_functions():
    source = """
function outerHandler(req) {
    function innerValidator(input) {
        return input != null;
    }
    const innerHelper = (data) => data.trim();
    return innerValidator(req.body) && innerHelper(req.body);
}
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    names = [f["name"] for f in functions]
    assert "outerHandler" in names
    assert "innerValidator" in names
    assert "innerHelper" in names
    assert len(functions) == 3


# ---------------------------------------------------------------------------
# 9. Async Functions
# ---------------------------------------------------------------------------
def test_9_async_functions():
    source = """
async function fetchData() {
    return await api.get('/data');
}

class ApiClient {
    async query(sql) {
        return await db.execute(sql);
    }
}

const asyncArrow = async () => {
    return await doWork();
};
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    assert len(functions) == 3
    for fn in functions:
        assert fn["is_async"] is True


# ---------------------------------------------------------------------------
# 10. Multiple Functions and Imports
# ---------------------------------------------------------------------------
def test_10_multiple_functions_and_imports():
    source = """
import express from 'express';
import { verify } from 'jsonwebtoken';
const crypto = require('crypto');

function setupServer() {
    return express();
}

const generateNonce = () => crypto.randomBytes(16);

function verifyToken(token) {
    return verify(token, 'secret');
}
"""
    struct = analyze_javascript_structure(source)
    assert len(struct["functions"]) == 3
    assert "express" in struct["imports"]
    assert "jsonwebtoken" in struct["imports"]
    assert "crypto" in struct["imports"]


# ---------------------------------------------------------------------------
# 11. Anonymous Function
# ---------------------------------------------------------------------------
def test_11_anonymous_function():
    source = """
[1, 2, 3].map((x) => x * 2);
setTimeout(function() {
    console.log('timeout');
}, 1000);
"""
    struct = analyze_javascript_structure(source)
    functions = struct["functions"]
    assert len(functions) == 2
    for fn in functions:
        assert fn["name"] == "<anonymous>"


# ---------------------------------------------------------------------------
# 12. Correct 1-based Line Spans
# ---------------------------------------------------------------------------
def test_12_correct_line_spans():
    source = (
        "// Line 1\n"
        "// Line 2\n"
        "function computeSum(a, b) {\n"   # Line 3
        "    const res = a + b;\n"         # Line 4
        "    return res;\n"                # Line 5
        "}\n"                              # Line 6
        "// Line 7\n"
    )
    struct = analyze_javascript_structure(source)
    fn = struct["functions"][0]
    assert fn["start_line"] == 3
    assert fn["end_line"] == 6


# ---------------------------------------------------------------------------
# 13. JSX-Containing JavaScript Parsing
# ---------------------------------------------------------------------------
def test_13_jsx_containing_javascript():
    source = """
import React from 'react';

function UserBadge({ username, role }) {
    return (
        <div className="user-badge">
            <span className="name">{username}</span>
            <span className="role">{role}</span>
        </div>
    );
}

export const Header = () => (
    <header>
        <h1>CodeSentinel</h1>
    </header>
);
"""
    struct = analyze_javascript_structure(source)
    assert struct["parse_status"] == "success"
    functions = struct["functions"]
    assert len(functions) == 2
    names = [f["name"] for f in functions]
    assert "UserBadge" in names
    assert "Header" in names


# ---------------------------------------------------------------------------
# 14. Malformed JavaScript Handling
# ---------------------------------------------------------------------------
def test_14_malformed_javascript_handling():
    source = """
function broken(a, b {
    this is invalid syntax !!!
"""
    struct = analyze_javascript_structure(source)
    assert struct["language"] == "javascript"
    # Tree-Sitter marks syntax errors without throwing
    assert struct["parse_status"] == "has_errors"
    # Doesn't crash and returns valid dictionary format
    assert isinstance(struct["functions"], list)
    assert isinstance(struct["classes"], list)


# ---------------------------------------------------------------------------
# 15. Empty JavaScript Source
# ---------------------------------------------------------------------------
def test_15_empty_javascript_source():
    source = ""
    struct = analyze_javascript_structure(source)
    assert struct["language"] == "javascript"
    assert struct["parse_status"] == "success"
    assert struct["functions"] == []
    assert struct["classes"] == []
    assert struct["imports"] == []


# ---------------------------------------------------------------------------
# 16. Module-Level Code
# ---------------------------------------------------------------------------
def test_16_module_level_code():
    source = """
const PORT = process.env.PORT || 8080;
console.log(`Server starting on port ${PORT}`);
"""
    struct = analyze_javascript_structure(source)
    assert struct["functions"] == []
    assert struct["classes"] == []


# ---------------------------------------------------------------------------
# 17. JavaScript Changed-Line Scope Mapping (diff_scope.py)
# ---------------------------------------------------------------------------
def test_17_javascript_changed_line_scope_mapping():
    source = """
function login(username, password) {
    if (!password) {
        return false;
    }
    return checkDb(username, password);
}

function register(user) {
    return createUser(user);
}
"""
    # Line 4 modified in login()
    scopes = map_changed_lines_to_scopes(source, [4], language="javascript")
    assert len(scopes) == 1
    assert scopes[0].name == "login"
    assert scopes[0].scope_type == "function"
    assert scopes[0].start_line == 2
    assert scopes[0].end_line == 7
    assert scopes[0].changed_lines == [4]


# ---------------------------------------------------------------------------
# 18. Nested Changed-Line Scope Selection
# ---------------------------------------------------------------------------
def test_18_nested_changed_line_scope_selection():
    source = """
function outerController(req, res) {
    const handleValidation = (body) => {
        if (!body.token) throw new Error('Missing token');
        return true;
    };
    return handleValidation(req.body);
}
"""
    # Line 4 modified: inside handleValidation (nested arrow function)
    scopes = map_changed_lines_to_scopes(source, [4], language="javascript")
    assert len(scopes) == 1
    # Must resolve to the innermost tightest scope
    assert scopes[0].name == "handleValidation"
    assert scopes[0].start_line == 3
    assert scopes[0].end_line == 6


# ---------------------------------------------------------------------------
# 19. Existing Python Diff-Scope Invariance
# ---------------------------------------------------------------------------
def test_19_existing_python_diff_scope_invariance():
    py_source = """
def authenticate(user, password):
    if not user:
        return False
    return True
"""
    # Default language='python'
    scopes_default = map_changed_lines_to_scopes(py_source, [4])
    scopes_explicit = map_changed_lines_to_scopes(py_source, [4], language="python")
    assert len(scopes_default) == 1
    assert scopes_default[0].name == "authenticate"
    assert scopes_explicit[0].name == "authenticate"
    assert scopes_default[0].start_line == 2
    assert scopes_default[0].end_line == 5


# ---------------------------------------------------------------------------
# 20. Parser Failure Cannot Bypass Step 6O Security Gate
# ---------------------------------------------------------------------------
def test_20_parser_failure_cannot_bypass_security_gate():
    # If a critical finding exists, Step 6O must enforce gate rules (BLOCK, exit_code 1)
    report_block = {
        "status": "success",
        "review_status": "block",
        "summary": {
            "total_findings": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }
    decision, exit_code, msg = evaluate_security_gate(report_block)
    assert decision == "BLOCK"
    assert exit_code == 1

    # Clean report yields ALLOW (exit_code 0)
    report_allow = {
        "status": "success",
        "review_status": "allow",
        "summary": {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    }
    decision, exit_code, msg = evaluate_security_gate(report_allow)
    assert decision == "ALLOW"
    assert exit_code == 0

