"""Security-Relevant AST Evidence Analyzer for CodeSentinel.

Extracts structural security signals from Python Tree-sitter ASTs.
Treats source code strictly as static text without executing or evaluating it.
Produces structural evidence (signals), NOT security verdicts or severity ratings.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from ast_engine.python_parser import parse_python_source

# Secret keywords to detect hardcoded secrets (case-insensitive substring match)
_SECRET_KEYWORDS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "private_key",
}

# DB execution call target suffixes / names
_DB_EXEC_NAMES = {"execute", "executemany", "executescript"}

# Command execution call target names
_CMD_EXEC_NAMES = {
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
}

# Dynamic code execution call names
_DYNAMIC_EXEC_NAMES = {"eval", "exec", "compile"}

# File operation call target names
_FILE_OP_NAMES = {"open", "pathlib.Path.open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}

# Network operation call target names
_NETWORK_OP_NAMES = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "urllib.request.urlopen",
}

# Python reserved / built-in words to filter out from related variables
_IGNORED_VAR_NAMES = {"self", "cls", "True", "False", "None"}


def _check_has_errors(node: Any) -> bool:
    """Check recursively if AST node has parsing errors."""
    if node.has_error or node.type == "ERROR":
        return True
    return any(_check_has_errors(child) for child in node.children)


def _get_call_target(call_node: Any) -> Optional[str]:
    """Extract string representation of call target function/method."""
    func_child = call_node.child_by_field_name("function")
    if func_child:
        return func_child.text.decode("utf-8")
    return None


def _extract_related_variables(node: Any) -> List[str]:
    """Extract unique identifier names (variables) from an AST subtree."""
    vars_list: List[str] = []
    seen: Set[str] = set()

    def _walk(n: Any) -> None:
        if n.type == "identifier":
            var_name = n.text.decode("utf-8")
            if var_name not in seen and var_name not in _IGNORED_VAR_NAMES:
                seen.add(var_name)
                vars_list.append(var_name)
        elif n.type in ("attribute", "call"):
            # Avoid duplicating full call string as a single variable
            for child in n.children:
                _walk(child)
            return

        for child in n.children:
            _walk(child)

    _walk(node)
    return vars_list


def _is_binary_string_construction(node: Any) -> bool:
    """Check if binary_operator contains string construction (string literal + expression)."""
    if node.type != "binary_operator":
        return False

    op_child = node.child_by_field_name("operator")
    if op_child and op_child.text.decode("utf-8") != "+":
        return False

    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")

    def _contains_string(n: Any) -> bool:
        if n is None:
            return False
        if n.type == "string":
            return True
        return any(_contains_string(c) for c in n.children)

    return _contains_string(left) or _contains_string(right)


def analyze_security_structure(source_code: str) -> Dict[str, Any]:
    """Extract security-relevant structural signals from Python source code.

    Returns a JSON-serializable dictionary with 'language', 'parse_status', and 'security_signals'.
    Source code is treated strictly as untrusted static text.
    """
    try:
        tree = parse_python_source(source_code)
    except Exception:
        return {
            "language": "python",
            "parse_status": "error",
            "security_signals": [],
        }

    has_errors = _check_has_errors(tree.root_node)
    parse_status = "has_errors" if has_errors else "success"

    signals: List[Dict[str, Any]] = []
    seen_signal_keys: Set[Tuple[str, str, int]] = set()

    def _add_signal(
        signal_type: str,
        name: str,
        line: int,
        evidence: str,
        related_variables: List[str],
    ) -> None:
        key = (signal_type, name, line)
        if key in seen_signal_keys:
            return
        seen_signal_keys.add(key)

        # Truncate evidence string if exceedingly long
        clean_evidence = evidence.strip().replace("\r\n", " ").replace("\n", " ")
        if len(clean_evidence) > 120:
            clean_evidence = clean_evidence[:117] + "..."

        signals.append({
            "signal_type": signal_type,
            "name": name,
            "line": line,
            "evidence": clean_evidence,
            "related_variables": related_variables,
        })

    def _traverse_ast(node: Any) -> None:
        line_no = node.start_point[0] + 1

        # 1. HARDCODED SECRET ASSIGNMENT
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")

            if left and right:
                target_var = left.text.decode("utf-8").strip()
                # Check if target var matches any secret keyword
                target_lower = target_var.lower()
                if any(kw in target_lower for kw in _SECRET_KEYWORDS):
                    # Check if RHS value is a string literal
                    if right.type == "string":
                        # SAFE EVIDENCE: Never expose the secret value!
                        safe_evidence = f"{target_var} assigned a string literal"
                        _add_signal(
                            signal_type="possible_hardcoded_secret",
                            name=target_var,
                            line=line_no,
                            evidence=safe_evidence,
                            related_variables=[target_var],
                        )

        # 2. CALL-BASED SIGNALS
        if node.type == "call":
            target = _get_call_target(node)
            if target:
                related_vars = _extract_related_variables(node)

                # Database execution call
                target_base = target.split(".")[-1]
                if target_base in _DB_EXEC_NAMES:
                    _add_signal(
                        signal_type="database_execution_call",
                        name=target,
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

                # Command execution call
                elif target in _CMD_EXEC_NAMES or target.startswith("subprocess.") or target == "os.system":
                    _add_signal(
                        signal_type="command_execution_call",
                        name=target,
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

                # Dynamic code execution
                elif target in _DYNAMIC_EXEC_NAMES:
                    _add_signal(
                        signal_type="dynamic_code_execution",
                        name=target,
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

                # External input source (e.g., request.args.get, input)
                elif "request." in target or target == "input":
                    _add_signal(
                        signal_type="external_input_source",
                        name=target,
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

                # File operation call
                elif target in _FILE_OP_NAMES or target.startswith("os.remove") or target.startswith("os.unlink"):
                    _add_signal(
                        signal_type="file_operation",
                        name=target,
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

                # Network operation call
                elif target in _NETWORK_OP_NAMES or target.startswith("requests.") or target.startswith("httpx."):
                    _add_signal(
                        signal_type="network_operation",
                        name=target,
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

                # Formatted string construction via .format() call
                elif target.endswith(".format"):
                    _add_signal(
                        signal_type="formatted_string_construction",
                        name="format_call",
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

        # 3. EXTERNAL INPUT SOURCE ATTRIBUTE ACCESS (e.g. request.args, request.form)
        elif node.type == "attribute":
            attr_str = node.text.decode("utf-8")
            if attr_str in (
                "request.args",
                "request.form",
                "request.json",
                "request.query_params",
                "request.GET",
                "request.POST",
                "request.values",
                "request.cookies",
                "request.headers",
            ):
                # Check parent is not call to avoid duplicate with request.args.get
                if node.parent is None or node.parent.type != "call" or node.parent.child_by_field_name("function") != node:
                    _add_signal(
                        signal_type="external_input_source",
                        name=attr_str,
                        line=line_no,
                        evidence=attr_str,
                        related_variables=_extract_related_variables(node),
                    )

        # 4. BINARY STRING CONCATENATION
        elif node.type == "binary_operator":
            if _is_binary_string_construction(node):
                # Ensure we don't emit child binary_operators if parent is already a binary string construction
                if node.parent is None or node.parent.type != "binary_operator":
                    related_vars = _extract_related_variables(node)
                    _add_signal(
                        signal_type="string_construction",
                        name="binary_string_concatenation",
                        line=line_no,
                        evidence=node.text.decode("utf-8"),
                        related_variables=related_vars,
                    )

        # 5. FORMATTED STRING (f-string) CONSTRUCTION
        elif node.type in ("string", "formatted_string_expression", "f_string"):
            # Check if string contains interpolation child
            if any(c.type in ("interpolation", "formatted_string_expression") for c in node.children):
                related_vars = _extract_related_variables(node)
                _add_signal(
                    signal_type="formatted_string_construction",
                    name="f_string",
                    line=line_no,
                    evidence=node.text.decode("utf-8"),
                    related_variables=related_vars,
                )

        for child in node.children:
            _traverse_ast(child)

    _traverse_ast(tree.root_node)

    return {
        "language": "python",
        "parse_status": parse_status,
        "security_signals": signals,
    }
