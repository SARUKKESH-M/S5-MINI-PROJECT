"""Category-Bound Sanitizer Registries for Python and JavaScript.

Frozen Specification: Phase 30C + Phase 30D-R.
Sanitizers are category-bound. Numeric casts strictly sanitize sql_injection only.
"""

from typing import Any, Optional
from ast_engine.taint.models import SanitizerPattern


def _node_text(node: Optional[Any]) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text or "")


# Python Sanitizers
_PY_SANITIZERS = {
    "shlex.quote": SanitizerPattern(name="shlex.quote", target_category="command_execution", is_numeric_cast=False, ast_pattern="shlex.quote"),
    "html.escape": SanitizerPattern(name="html.escape", target_category="xss", is_numeric_cast=False, ast_pattern="html.escape"),
    "int": SanitizerPattern(name="int", target_category="sql_injection", is_numeric_cast=True, ast_pattern="int"),
    "float": SanitizerPattern(name="float", target_category="sql_injection", is_numeric_cast=True, ast_pattern="float"),
}


def match_python_sanitizer(call_node: Any) -> Optional[SanitizerPattern]:
    """Check if a Python call node matches an approved category-bound sanitizer."""
    if call_node is None or call_node.type != "call":
        return None

    fn_node = call_node.child_by_field_name("function")
    fn_name = _node_text(fn_node).strip()

    return _PY_SANITIZERS.get(fn_name)


# JavaScript Sanitizers
_JS_SANITIZERS = {
    "DOMPurify.sanitize": SanitizerPattern(name="DOMPurify.sanitize", target_category="xss", is_numeric_cast=False, ast_pattern="DOMPurify.sanitize"),
    "encodeURIComponent": SanitizerPattern(name="encodeURIComponent", target_category="xss", is_numeric_cast=False, ast_pattern="encodeURIComponent"),
    "Number": SanitizerPattern(name="Number", target_category="sql_injection", is_numeric_cast=True, ast_pattern="Number"),
    "parseInt": SanitizerPattern(name="parseInt", target_category="sql_injection", is_numeric_cast=True, ast_pattern="parseInt"),
    "parseFloat": SanitizerPattern(name="parseFloat", target_category="sql_injection", is_numeric_cast=True, ast_pattern="parseFloat"),
}


def match_javascript_sanitizer(call_node: Any) -> Optional[SanitizerPattern]:
    """Check if a JavaScript call_expression node matches an approved category-bound sanitizer."""
    if call_node is None or call_node.type != "call_expression":
        return None

    fn_node = call_node.child_by_field_name("function")
    fn_name = _node_text(fn_node).strip()

    return _JS_SANITIZERS.get(fn_name)
