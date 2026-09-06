"""
CodeSentinel — Diff Scope & AST Enclosing Scope Engine

Parses git unified diff hunks into changed line ranges and maps them to
Tree-Sitter AST enclosing scopes (functions, methods, classes, and module-level).
Enables precision-scoped security analysis on pull request diffs without analyzing
unrelated pre-existing code.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from ast_engine.structural_analyzer import analyze_python_structure, analyze_javascript_structure
except ImportError:
    from structural_analyzer import analyze_python_structure, analyze_javascript_structure


# Standard unified diff hunk header pattern:
# e.g.: @@ -10,5 +20,7 @@ or @@ -10 +20 @@ or @@ -0,0 +1,10 @@ or @@ -1,10 +0,0 @@
HUNK_HEADER_REGEX = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?\s+@@"
)


@dataclass(frozen=True)
class ChangedLinesInfo:
    """Immutable representation of line-level changes derived from a unified diff."""
    added_lines: List[int] = field(default_factory=list)      # Lines added/modified in the new file (1-indexed)
    deleted_lines: List[int] = field(default_factory=list)    # Lines removed from old file (1-indexed)
    affected_lines: List[int] = field(default_factory=list)   # All new-file lines directly touched or affected


@dataclass(frozen=True)
class EnclosingScope:
    """Represents an AST syntactic scope enclosing changed lines."""
    scope_type: str             # "function", "method", or "module"
    name: str                   # e.g. "authenticate", "AuthService.login", "<module>"
    class_name: Optional[str]   # e.g. "AuthService" or None
    start_line: int             # 1-indexed start line of scope in new file
    end_line: int               # 1-indexed end line of scope in new file
    changed_lines: List[int]    # Sorted list of changed new-file line numbers in this scope


def parse_unified_diff(diff_text: Optional[str]) -> ChangedLinesInfo:
    """
    Parses a unified diff string and returns structured line-level change information.

    Args:
        diff_text: Unified diff patch string.

    Returns:
        ChangedLinesInfo containing added_lines, deleted_lines, and affected_lines.
    """
    if not diff_text or not isinstance(diff_text, str) or not diff_text.strip():
        return ChangedLinesInfo()

    added_lines: List[int] = []
    deleted_lines: List[int] = []
    current_new_line = 0
    current_old_line = 0
    in_hunk = False
    new_count = 0

    for line in diff_text.splitlines():
        # Check for hunk header
        hunk_match = HUNK_HEADER_REGEX.match(line)
        if hunk_match:
            in_hunk = True
            new_start = int(hunk_match.group("new_start"))
            new_count_str = hunk_match.group("new_count")
            new_count = int(new_count_str) if new_count_str is not None else 1

            old_start = int(hunk_match.group("old_start"))
            old_count_str = hunk_match.group("old_count")
            old_count = int(old_count_str) if old_count_str is not None else 1

            current_new_line = new_start
            current_old_line = old_start
            continue

        if not in_hunk:
            continue

        # Skip diff headers / metadata outside content
        if line.startswith("+++") or line.startswith("---") or line.startswith("diff ") or line.startswith("index "):
            in_hunk = False
            continue

        # Added line in new file
        if line.startswith("+"):
            if new_count > 0:
                added_lines.append(current_new_line)
                current_new_line += 1
        # Deleted line in old file
        elif line.startswith("-"):
            deleted_lines.append(current_old_line)
            current_old_line += 1
            # Note: current_new_line does not advance for deleted lines
        elif line.startswith("\\"):
            # e.g., "\ No newline at end of file"
            continue
        else:
            # Context line (unchanged)
            current_new_line += 1
            current_old_line += 1

    unique_added = sorted(list(set(added_lines)))
    unique_deleted = sorted(list(set(deleted_lines)))

    # If lines were added, affected_lines are the added lines.
    # If pure deletion, anchor to where deletion happened in new file.
    affected = unique_added
    if not affected and unique_deleted:
        anchor = max(1, current_new_line)
        affected = [anchor]

    return ChangedLinesInfo(
        added_lines=unique_added,
        deleted_lines=unique_deleted,
        affected_lines=affected
    )


def map_changed_lines_to_scopes(
    source_code: Optional[str],
    changed_lines: List[int],
    language: str = "python",
) -> List[EnclosingScope]:
    """
    Maps changed line numbers to AST enclosing scopes using Tree-Sitter structural analysis.

    Rules enforced:
    1. If a changed line belongs to a function/method, select the tightest enclosing scope.
    2. If multiple hunks/lines modify the same function, return ONE scope with merged lines.
    3. If a method belongs to a class, return the method (not the entire class).
    4. If a nested function is changed, select the innermost enclosing function.
    5. If code is changed outside any function, represent it as module-level scope.
    6. Never silently drop module-level changes.
    7. Never duplicate scopes.

    Args:
        source_code: Complete source code string of the new file.
        changed_lines: List of 1-indexed line numbers modified in the new file.
        language: Language of the source code ("python" or "javascript").

    Returns:
        Sorted list of EnclosingScope objects.
    """
    if not source_code or not isinstance(source_code, str) or not changed_lines:
        return []

    clean_lines = sorted(list(set(line for line in changed_lines if isinstance(line, int) and line > 0)))
    if not clean_lines:
        return []

    # 1. Parse AST structure using appropriate language structural analyzer
    clean_lang = (language or "python").lower().strip()
    try:
        if clean_lang in ("javascript", "js", "jsx"):
            structure = analyze_javascript_structure(source_code)
        else:
            structure = analyze_python_structure(source_code)
    except Exception:
        # Fallback to module scope if structural parser fails
        total_lines = max(1, len(source_code.splitlines()))
        return [
            EnclosingScope(
                scope_type="module",
                name="<module>",
                class_name=None,
                start_line=1,
                end_line=total_lines,
                changed_lines=clean_lines
            )
        ]

    functions = structure.get("functions", [])

    # 2. Map each changed line to the tightest enclosing function/method
    # Key: (name, class_name, start_line, end_line) -> List[int] (changed lines)
    function_scope_map: Dict[Tuple[str, Optional[str], int, int], List[int]] = {}
    module_level_lines: List[int] = []

    for line in clean_lines:
        enclosing_candidates = []
        for fn in functions:
            fn_start = fn.get("start_line")
            fn_end = fn.get("end_line")
            if fn_start is not None and fn_end is not None:
                if fn_start <= line <= fn_end:
                    span = fn_end - fn_start
                    enclosing_candidates.append((span, fn))

        if enclosing_candidates:
            # Sort by span ascending (tightest innermost scope first), then start_line descending
            enclosing_candidates.sort(key=lambda x: (x[0], -x[1].get("start_line", 0)))
            chosen_fn = enclosing_candidates[0][1]
            fn_name = chosen_fn.get("name") or "anonymous"
            class_name = chosen_fn.get("class_name")
            start_line = chosen_fn.get("start_line", 1)
            end_line = chosen_fn.get("end_line", 1)

            key = (fn_name, class_name, start_line, end_line)
            if key not in function_scope_map:
                function_scope_map[key] = []
            function_scope_map[key].append(line)
        else:
            # Not in any function/method -> module-level change
            module_level_lines.append(line)

    scopes: List[EnclosingScope] = []

    # 3. Build EnclosingScope objects for functions and methods
    for (fn_name, class_name, start_line, end_line), lines_in_scope in function_scope_map.items():
        scope_type = "method" if class_name else "function"
        display_name = f"{class_name}.{fn_name}" if class_name else fn_name
        scopes.append(
            EnclosingScope(
                scope_type=scope_type,
                name=display_name,
                class_name=class_name,
                start_line=start_line,
                end_line=end_line,
                changed_lines=sorted(list(set(lines_in_scope)))
            )
        )

    # 4. If any changed lines exist at module level, add single module scope
    if module_level_lines:
        total_lines = max(1, len(source_code.splitlines()))
        scopes.append(
            EnclosingScope(
                scope_type="module",
                name="<module>",
                class_name=None,
                start_line=1,
                end_line=total_lines,
                changed_lines=sorted(list(set(module_level_lines)))
            )
        )

    # Sort scopes by start_line ascending
    return sorted(scopes, key=lambda s: (s.start_line, s.end_line))


def filter_findings_to_diff_scope(
    findings: List[Dict[str, Any]],
    scopes: List[EnclosingScope],
    changed_lines: List[int],
    file_path: str = ""
) -> List[Dict[str, Any]]:
    """
    Filters raw findings to only those that fall within the PR's affected scopes or changed lines.

    Rules:
    - If a finding is inside a changed function/method scope, it is included.
    - If a finding is at module level, it is included only if its line was directly modified.
    - If scopes is empty (e.g. diff unparseable or fallback), all findings are preserved.

    Args:
        findings: List of raw finding dictionaries from deterministic_findings.
        scopes: List of EnclosingScope objects from map_changed_lines_to_scopes.
        changed_lines: List of changed line numbers.
        file_path: Relative path of the file being evaluated.

    Returns:
        Filtered list of finding dictionaries.
    """
    if not findings:
        return []

    # Fallback: if no scope information was extracted, retain findings safely
    if not scopes and not changed_lines:
        return findings

    changed_set = set(changed_lines)
    function_scopes = [s for s in scopes if s.scope_type in ("function", "method")]
    has_module_scope = any(s.scope_type == "module" for s in scopes)

    filtered: List[Dict[str, Any]] = []

    for finding in findings:
        # Determine finding line number
        f_line = finding.get("line")
        if f_line is None:
            evidence = finding.get("evidence", [])
            if evidence and isinstance(evidence, list):
                f_line = evidence[0].get("line_start")

        # If finding has no line information, retain it to avoid dropping valid issues
        if f_line is None:
            filtered.append(finding)
            continue

        try:
            line_num = int(f_line)
        except (ValueError, TypeError):
            filtered.append(finding)
            continue

        # Check 1: Direct line match
        if line_num in changed_set:
            filtered.append(finding)
            continue

        # Check 2: Falls within any changed function/method scope
        in_function_scope = False
        for s in function_scopes:
            if s.start_line <= line_num <= s.end_line:
                in_function_scope = True
                break

        if in_function_scope:
            filtered.append(finding)
            continue

        # If it's outside changed function scopes, it's pre-existing unchanged code -> exclude

    return filtered
