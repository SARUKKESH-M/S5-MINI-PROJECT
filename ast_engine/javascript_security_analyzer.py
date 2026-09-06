"""JavaScript AST Security Evidence Extraction for CodeSentinel using Tree-sitter.

Treats source code strictly as static text without executing or evaluating it.
Extracts deterministic security evidence for:
  - DOM Cross-Site Scripting (innerHTML, outerHTML, insertAdjacentHTML)
  - React dangerouslySetInnerHTML
  - Node.js child_process command injection (exec, execSync)
  - Hardcoded secrets
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ast_engine.javascript_parser import parse_javascript_source

_SECRET_KEYWORDS = {
    "password", "passwd", "secret", "api_key", "apikey",
    "token", "access_token", "private_key", "credential", "auth",
}

_IGNORED_SECRET_VALUES = {
    "true", "false", "null", "undefined", "test", "development",
    "production", "placeholder", "example", "not-a-secret",
}

_SQL_RECEIVERS = {
    "db",
    "database",
    "client",
    "pool",
    "connection",
    "conn",
    "sequelize",
}

_SQL_METHODS = {"query", "execute"}


def _check_has_errors(node: Any) -> bool:
    """Recursively check if AST contains syntax error nodes."""
    if node.has_error or node.type == "ERROR":
        return True
    return any(_check_has_errors(child) for child in node.children)


def _text(node: Optional[Any]) -> str:
    """Safely decode text from a Tree-sitter AST node."""
    return node.text.decode("utf-8") if node is not None else ""


def _is_static_string(node: Optional[Any]) -> bool:
    """Return True if node is a static string literal or template string without substitutions."""
    if node is None:
        return False
    if node.type == "string":
        return True
    if node.type == "template_string":
        return not any(child.type == "template_substitution" for child in node.children)
    return False


def _secret_like(name: str) -> bool:
    """Determine whether variable name matches sensitive credential patterns."""
    name_lower = name.lower()
    return any(keyword in name_lower for keyword in _SECRET_KEYWORDS)


def _is_sql_sink(fn_node: Any) -> Optional[str]:
    """Check if function node is an exact database sink or dedicated raw SQL method."""
    if fn_node.type != "member_expression":
        return None
    prop = fn_node.child_by_field_name("property")
    prop_name = _text(prop)
    obj = fn_node.child_by_field_name("object")
    if obj is None or obj.type != "identifier":
        return None
    obj_name = _text(obj)
    if obj_name in _SQL_RECEIVERS and prop_name in _SQL_METHODS:
        return f"{obj_name}.{prop_name}"
    if obj_name == "knex" and prop_name == "raw":
        return "knex.raw"
    if obj_name == "prisma" and prop_name in ("$queryRaw", "$executeRaw"):
        return f"prisma.{prop_name}"
    return None


def _is_parameterized_sql(query_node: Optional[Any], args: List[Any]) -> bool:
    """Return True if query argument is static with recognized parameter placeholders and arguments."""
    if not _is_static_string(query_node) or len(args) < 2:
        return False
    query_text = _text(query_node)
    if "?" in query_text or "%s" in query_text:
        return True
    if re.search(r"\$\d+", query_text):
        return True
    if re.search(r"%\(\w+\)s", query_text):
        return True
    if re.search(r":\w+", query_text):
        return True
    return False


def _is_dynamic_concatenation(node: Any) -> bool:
    """Return True if binary expression represents dynamic string concatenation."""
    if node.type != "binary_expression":
        return False
    op = node.child_by_field_name("operator")
    if not op or _text(op) != "+":
        return False
    leaves: List[Any] = []

    def collect_leaves(n: Any) -> None:
        if n.type == "binary_expression":
            bin_op = n.child_by_field_name("operator")
            if bin_op and _text(bin_op) == "+":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left:
                    collect_leaves(left)
                if right:
                    collect_leaves(right)
                return
        leaves.append(n)

    collect_leaves(node)
    has_string = any(leaf.type in ("string", "template_string") for leaf in leaves)
    has_dynamic = any(not _is_static_string(leaf) for leaf in leaves)
    return has_string and has_dynamic


def _is_dynamic_sql_construction(node: Optional[Any]) -> bool:
    """Return True if query argument is dynamic string concatenation or template interpolation."""
    if node is None:
        return False
    if node.type == "template_string":
        return any(child.type == "template_substitution" for child in node.children)
    if _is_dynamic_concatenation(node):
        return True
    return False


def analyze_javascript_security_structure(
    source_code: str,
    file_path: str = "",
) -> Dict[str, Any]:
    """Extract deterministic, file-scoped JavaScript security evidence without dynamic execution.

    Safely handles malformed JavaScript by returning partial trees with
    parse_status='has_errors' and never crashes on unexpected syntax.
    """
    try:
        tree = parse_javascript_source(source_code)
    except Exception:
        return {
            "language": "javascript",
            "parse_status": "error",
            "file_path": file_path,
            "security_signals": [],
        }

    signals: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, int]] = set()

    def add_signal(
        signal_type: str,
        category: str,
        severity: str,
        confidence: str,
        name: str,
        line: int,
        evidence: str,
        related_variables: List[str],
        message: str,
        assessment: Optional[Dict[str, Any]] = None,
    ) -> None:
        key = (signal_type, name, line)
        if key in seen:
            return
        seen.add(key)
        clean_evidence = evidence.strip().replace("\r\n", " ").replace("\n", " ")
        if len(clean_evidence) > 240:
            clean_evidence = clean_evidence[:237] + "..."
        stable_input = "|".join((file_path, str(line), category, signal_type, name, clean_evidence))
        signals.append({
            "evidence_id": hashlib.sha256(stable_input.encode("utf-8")).hexdigest(),
            "file_path": file_path,
            "line": line,
            "category": category,
            "signal_type": signal_type,
            "severity": severity,
            "confidence": confidence,
            "call_name": name,
            "name": name,
            "evidence": clean_evidence,
            "related_variables": related_variables,
            "argument_assessment": assessment or {},
            "message": message,
        })

    def _get_call_arguments(call_node: Any) -> List[Any]:
        args_node = call_node.child_by_field_name("arguments")
        if not args_node or args_node.type != "arguments":
            return []
        return [c for c in args_node.children if c.type not in ("(", ")", ",")]

    def _is_child_process_exec(fn_node: Any) -> Optional[str]:
        if fn_node.type != "member_expression":
            return None
        prop = fn_node.child_by_field_name("property")
        prop_name = _text(prop)
        if prop_name not in ("exec", "execSync"):
            return None
        obj = fn_node.child_by_field_name("object")
        if obj is None:
            return None
        if obj.type == "identifier" and _text(obj) == "child_process":
            return f"child_process.{prop_name}"
        if obj.type == "call_expression":
            req_fn = obj.child_by_field_name("function")
            req_args = obj.child_by_field_name("arguments")
            if req_fn and _text(req_fn) == "require" and req_args:
                arg_texts = [_text(c).strip("'\"`") for c in req_args.children if c.type not in ("(", ")", ",")]
                if "child_process" in arg_texts:
                    return f"require(\"child_process\").{prop_name}"
        return None

    def walk(node: Any) -> None:
        line = node.start_point[0] + 1

        # 1. Assignment Expressions (innerHTML, outerHTML, and variable assignments)
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                # DOM XSS: innerHTML / outerHTML
                if left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    prop_name = _text(prop)
                    if prop_name in ("innerHTML", "outerHTML"):
                        if not _is_static_string(right):
                            sink_name = f"element.{prop_name}"
                            add_signal(
                                "dom_xss_call",
                                "xss",
                                "high",
                                "high",
                                sink_name,
                                line,
                                _text(node),
                                [_text(left)],
                                f"Dynamic or untrusted content is injected into the DOM via {prop_name} without sanitization.",
                                {"sink": prop_name, "dynamic": True},
                            )
                # Assignment Secret: apiKey = "sk-..."
                elif left.type == "identifier":
                    var_name = _text(left)
                    if _secret_like(var_name) and right.type == "string":
                        val_str = _text(right).strip("'\"`")
                        if len(val_str) >= 8 and val_str.lower() not in _IGNORED_SECRET_VALUES:
                            add_signal(
                                "possible_hardcoded_secret",
                                "credential_management",
                                "medium",
                                "medium",
                                var_name,
                                line,
                                f"{var_name} assigned a string literal",
                                [var_name],
                                "A secret-like variable is assigned a string literal.",
                                {"variable": var_name},
                            )

        # 2. Variable Declarators: const apiKey = "sk-..."
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            val_node = node.child_by_field_name("value")
            if name_node is not None and val_node is not None and name_node.type == "identifier":
                var_name = _text(name_node)
                if _secret_like(var_name) and val_node.type == "string":
                    val_str = _text(val_node).strip("'\"`")
                    if len(val_str) >= 8 and val_str.lower() not in _IGNORED_SECRET_VALUES:
                        add_signal(
                            "possible_hardcoded_secret",
                            "credential_management",
                            "medium",
                            "medium",
                            var_name,
                            line,
                            f"{var_name} assigned a string literal",
                            [var_name],
                            "A secret-like variable is assigned a string literal.",
                            {"variable": var_name},
                        )

        # 3. Call Expressions: insertAdjacentHTML & child_process.exec / execSync
        elif node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None:
                # insertAdjacentHTML
                if fn_node.type == "member_expression":
                    prop = fn_node.child_by_field_name("property")
                    if _text(prop) == "insertAdjacentHTML":
                        args = _get_call_arguments(node)
                        if len(args) > 1:
                            payload_arg = args[1]
                            if not _is_static_string(payload_arg):
                                add_signal(
                                    "dom_xss_call",
                                    "xss",
                                    "high",
                                    "high",
                                    "element.insertAdjacentHTML",
                                    line,
                                    _text(node),
                                    [_text(fn_node)],
                                    "Dynamic content is injected into the DOM via insertAdjacentHTML without sanitization.",
                                    {"sink": "insertAdjacentHTML", "dynamic": True},
                                )
                # child_process.exec / execSync
                cp_target = _is_child_process_exec(fn_node)
                if cp_target:
                    args = _get_call_arguments(node)
                    if args:
                        cmd_arg = args[0]
                        if not _is_static_string(cmd_arg):
                            add_signal(
                                "command_execution_call",
                                "command_execution",
                                "critical",
                                "high",
                                cp_target,
                                line,
                                _text(node),
                                [cp_target],
                                "Operating system command execution sink is invoked with a dynamic command string.",
                                {"command_sink": cp_target, "dynamic_command": True},
                            )

                # Database SQL injection sinks
                sql_target = _is_sql_sink(fn_node)
                if sql_target:
                    args = _get_call_arguments(node)
                    if args:
                        query_arg = args[0]
                        if not _is_static_string(query_arg) and not _is_parameterized_sql(query_arg, args):
                            if _is_dynamic_sql_construction(query_arg):
                                add_signal(
                                    "unsafe_database_execution",
                                    "sql_injection",
                                    "high",
                                    "high",
                                    sql_target,
                                    line,
                                    _text(node),
                                    [sql_target],
                                    "A database query is dynamically constructed or cannot be verified as parameterized.",
                                    {"sink": sql_target, "dynamic_sql": True, "parameterized": False},
                                )

        # 4. JSX Attributes: dangerouslySetInnerHTML
        elif node.type == "jsx_attribute":
            attr_name_node = None
            attr_val_node = None
            for child in node.children:
                if child.type == "property_identifier":
                    attr_name_node = child
                elif child.type == "jsx_expression":
                    attr_val_node = child
            if attr_name_node is not None and _text(attr_name_node) == "dangerouslySetInnerHTML":
                if attr_val_node is not None:
                    def _check_danger_obj(expr: Any) -> bool:
                        for c in expr.children:
                            if c.type == "object":
                                for p in c.children:
                                    if p.type == "pair":
                                        key_child = p.child_by_field_name("key")
                                        val_child = p.child_by_field_name("value")
                                        if key_child and _text(key_child) == "__html":
                                            return not _is_static_string(val_child)
                            elif c.type not in ("{", "}"):
                                if _check_danger_obj(c):
                                    return True
                        return False

                    if _check_danger_obj(attr_val_node):
                        add_signal(
                            "dom_xss_call",
                            "xss",
                            "high",
                            "high",
                            "dangerouslySetInnerHTML",
                            line,
                            _text(node),
                            ["dangerouslySetInnerHTML"],
                            "Dynamic content is rendered unsafely through React dangerouslySetInnerHTML.",
                            {"sink": "dangerouslySetInnerHTML", "dynamic": True},
                        )

        for child in node.children:
            walk(child)

    walk(tree.root_node)

    return {
        "language": "javascript",
        "parse_status": "has_errors" if _check_has_errors(tree.root_node) else "success",
        "file_path": file_path,
        "security_signals": signals,
    }
