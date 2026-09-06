"""
CodeSentinel — Diff Scope & AST Enclosing Scope Engine Test Suite

Validates unified diff hunk parsing (standard, single-line, new file, deleted lines, malformed),
changed lines to AST scope mapping (functions, methods, nested functions, module-level, duplicates),
scoped finding filtering, and Step 6O PR report generation.
"""

import sys
import os

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from backend.analysis.diff_scope import (
    parse_unified_diff,
    map_changed_lines_to_scopes,
    filter_findings_to_diff_scope,
    ChangedLinesInfo,
    EnclosingScope,
)
from backend.github.orchestrator import _generate_pr_analysis_report
from backend.github.models import GitHubChangedFile


# =====================================================================
# 1. UNIFIED DIFF HUNK PARSING TESTS
# =====================================================================

def test_parse_standard_hunk_header():
    """1. Validates standard unified diff header: @@ -10,5 +20,7 @@"""
    diff = (
        "@@ -10,5 +20,7 @@\n"
        " context line 20\n"
        "+added line 21\n"
        "+added line 22\n"
        " context line 23\n"
    )
    info = parse_unified_diff(diff)
    assert info.added_lines == [21, 22]
    assert info.affected_lines == [21, 22]
    assert info.deleted_lines == []


def test_parse_single_line_hunk_header():
    """2. Validates single-line header without comma: @@ -10 +20 @@ (fixing OLD bug)."""
    diff = (
        "@@ -10 +20 @@\n"
        "+single added line 20\n"
    )
    info = parse_unified_diff(diff)
    assert info.added_lines == [20]
    assert info.affected_lines == [20]
    assert info.deleted_lines == []


def test_parse_new_file_diff():
    """3. Validates newly created file diff: @@ -0,0 +1,10 @@"""
    diff = (
        "@@ -0,0 +1,3 @@\n"
        "+line 1\n"
        "+line 2\n"
        "+line 3\n"
    )
    info = parse_unified_diff(diff)
    assert info.added_lines == [1, 2, 3]
    assert info.affected_lines == [1, 2, 3]
    assert info.deleted_lines == []


def test_parse_deleted_line_handling():
    """4. Validates deleted lines (-) do not advance new-file line numbering."""
    diff = (
        "@@ -5,4 +5,3 @@\n"
        " context 5\n"
        "-deleted old line 6\n"
        "-deleted old line 7\n"
        "+added new line 6\n"
        " context 7\n"
    )
    info = parse_unified_diff(diff)
    # The added line is line 6 in the new file
    assert info.added_lines == [6]
    assert info.affected_lines == [6]
    assert info.deleted_lines == [6, 7]


def test_parse_multiple_hunks():
    """5. Validates multiple sequential hunks in a single diff patch."""
    diff = (
        "@@ -10,3 +10,4 @@\n"
        " ctx 10\n"
        "+add 11\n"
        "+add 12\n"
        " ctx 13\n"
        "@@ -50,2 +51,3 @@\n"
        " ctx 51\n"
        "+add 52\n"
        " ctx 53\n"
    )
    info = parse_unified_diff(diff)
    assert info.added_lines == [11, 12, 52]
    assert info.affected_lines == [11, 12, 52]


def test_parse_malformed_diff():
    """6. Validates graceful fallback for malformed/empty/garbage diffs."""
    empty_info = parse_unified_diff("")
    assert empty_info.added_lines == []
    assert empty_info.affected_lines == []

    none_info = parse_unified_diff(None)
    assert none_info.added_lines == []

    garbage_info = parse_unified_diff("This is not a git diff @@ malformed @@ junk")
    assert garbage_info.added_lines == []


# =====================================================================
# 2. AST ENCLOSING SCOPE MAPPING TESTS
# =====================================================================

SAMPLE_PYTHON_SOURCE = """
import os

API_KEY = "sk-global-12345"  # Line 4

def helper_function(x):      # Line 6
    val = x * 2              # Line 7
    return val               # Line 8

class UserManager:           # Line 10
    def __init__(self):      # Line 11
        self.users = []      # Line 12
                             # Line 13
    def authenticate(self, user, token):  # Line 14
        query = "SELECT * FROM u WHERE id=" + user  # Line 15
        return query         # Line 16
                             # Line 17
def outer_service():         # Line 18
    def inner_worker(t):     # Line 19
        os.system("echo " + t) # Line 20
    return inner_worker      # Line 21
"""


def test_map_single_changed_function():
    """7. Validates changed line maps to the enclosing function."""
    changed_lines = [7]  # inside helper_function (lines 6-8)
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 1
    scope = scopes[0]
    assert scope.scope_type == "function"
    assert scope.name == "helper_function"
    assert scope.start_line == 6
    assert scope.end_line == 8
    assert scope.changed_lines == [7]


def test_map_multiple_changed_functions():
    """8. Validates changes in separate functions return distinct scopes."""
    changed_lines = [7, 15]  # helper_function and authenticate
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 2
    names = [s.name for s in scopes]
    assert "helper_function" in names
    assert "UserManager.authenticate" in names


def test_map_multiple_hunks_in_same_function():
    """9. Validates multiple changes in the same function merge into one scope."""
    changed_lines = [7, 8]  # lines 7 and 8 both in helper_function
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 1
    assert scopes[0].name == "helper_function"
    assert scopes[0].changed_lines == [7, 8]


def test_map_class_method():
    """10. Validates class method returns method scope, not class duplicate."""
    changed_lines = [15]  # inside UserManager.authenticate
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 1
    assert scopes[0].scope_type == "method"
    assert scopes[0].class_name == "UserManager"
    assert scopes[0].name == "UserManager.authenticate"


def test_map_nested_function():
    """11. Validates nested function selects the innermost tightest function."""
    changed_lines = [20]  # inside inner_worker (lines 19-20) inside outer_service (lines 18-21)
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 1
    assert scopes[0].name == "inner_worker"
    assert scopes[0].start_line == 19
    assert scopes[0].end_line == 20


def test_map_module_level_change():
    """12. Validates changes outside any function map to module scope."""
    changed_lines = [4]  # API_KEY line outside any function
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 1
    assert scopes[0].scope_type == "module"
    assert scopes[0].name == "<module>"
    assert scopes[0].changed_lines == [4]


def test_map_no_matching_function():
    """13. Validates empty input returns empty list gracefully."""
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, [])
    assert scopes == []

    empty_scopes = map_changed_lines_to_scopes("", [1])
    assert empty_scopes == []


def test_duplicate_scope_prevention():
    """14. Validates duplicate line inputs do not produce duplicate scopes."""
    changed_lines = [14, 15, 15, 14, 16]
    scopes = map_changed_lines_to_scopes(SAMPLE_PYTHON_SOURCE, changed_lines)
    assert len(scopes) == 1
    assert scopes[0].name == "UserManager.authenticate"
    assert scopes[0].changed_lines == [14, 15, 16]


# =====================================================================
# 3. SCOPED FINDING FILTERING & PR ANALYSIS TESTS
# =====================================================================

def test_finding_in_changed_function_is_included():
    """15. Validates findings in a changed function are included in scoped results."""
    # Line 15 has SQL injection in UserManager.authenticate
    findings = [
        {
            "finding_id": "f_1",
            "title": "SQL Injection",
            "severity": "critical",
            "confidence": "high",
            "category": "Injection",
            "line": 15,
            "evidence": [{"document_id": "test.py", "line_start": 15, "line_end": 15}]
        }
    ]
    scopes = [
        EnclosingScope(
            scope_type="method",
            name="UserManager.authenticate",
            class_name="UserManager",
            start_line=14,
            end_line=16,
            changed_lines=[15]
        )
    ]
    filtered = filter_findings_to_diff_scope(findings, scopes, changed_lines=[15])
    assert len(filtered) == 1
    assert filtered[0]["finding_id"] == "f_1"


def test_preexisting_finding_in_unchanged_function_is_excluded():
    """16. Validates pre-existing vulnerabilities in untouched functions are excluded from PR review."""
    # PR only touched helper_function (lines 6-8)
    scopes = [
        EnclosingScope(
            scope_type="function",
            name="helper_function",
            class_name=None,
            start_line=6,
            end_line=8,
            changed_lines=[7]
        )
    ]
    # Finding is pre-existing at line 15 in UserManager.authenticate (unchanged)
    preexisting_findings = [
        {
            "finding_id": "f_preexisting",
            "title": "SQL Injection",
            "severity": "critical",
            "confidence": "high",
            "category": "Injection",
            "line": 15,
            "evidence": [{"document_id": "test.py", "line_start": 15, "line_end": 15}]
        }
    ]
    filtered = filter_findings_to_diff_scope(preexisting_findings, scopes, changed_lines=[7])
    assert len(filtered) == 0


def test_step_6o_pr_report_contract_valid():
    """17. Validates end-to-end report generated by _generate_pr_analysis_report preserves Step 6O contract."""
    patch_text = (
        "@@ -10,3 +14,3 @@\n"
        " def authenticate(self, user, token):\n"
        "-    pass\n"
        "+    query = 'SELECT * FROM u WHERE id=' + user\n"
        "     return query\n"
    )
    changed_file = GitHubChangedFile(
        filename="app/auth.py",
        status="modified",
        additions=1,
        deletions=1,
        changes=2,
        patch=patch_text
    )

    report = _generate_pr_analysis_report(
        owner="test-org",
        repository="test-repo",
        pr_number=42,
        head_sha="0000000000000000000000000000000000000000",
        changed_files=[changed_file]
    )

    assert report["status"] == "success"
    assert "review_status" in report
    assert report["review_status"] in ("allow", "review", "block")
    assert "analysis_id" in report
    assert report["repository"]["owner"] == "test-org"
    assert report["repository"]["repository"] == "test-repo"
    assert "summary" in report
    assert "total_findings" in report["summary"]
    assert "findings" in report
    assert isinstance(report["findings"], list)
