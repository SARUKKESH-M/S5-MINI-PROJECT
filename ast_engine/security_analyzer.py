"""Static, deterministic security evidence extraction for Python source."""

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

from ast_engine.python_parser import parse_python_source

_SECRET_KEYWORDS = {"password", "passwd", "secret", "api_key", "apikey", "token", "access_token", "private_key", "credential", "auth"}
_DB_EXEC_NAMES = {"execute", "executemany", "executescript"}
_DYNAMIC_EXEC_NAMES = {"eval", "exec", "compile"}
_FILE_OP_SINKS = {
    "open",
    "io.open",
    "os.open",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "shutil.rmtree",
    "pathlib.Path.open",
    "Path.open",
}
_DESERIALIZATION_SINKS = {
    "pickle.loads",
    "pickle.load",
    "_pickle.loads",
    "_pickle.load",
    "cPickle.loads",
    "cPickle.load",
}
_NETWORK_OP_NAMES = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "urllib.request.urlopen"}
_IGNORED_VAR_NAMES = {"self", "cls", "True", "False", "None"}


def _is_file_op_target(target: str) -> bool:
    return target in _FILE_OP_SINKS


def _is_deserialization_target(target: str) -> bool:
    return target in _DESERIALIZATION_SINKS


def _check_has_errors(node: Any) -> bool:
    return node.has_error or node.type == "ERROR" or any(_check_has_errors(child) for child in node.children)


def _text(node: Optional[Any]) -> str:
    return node.text.decode("utf-8") if node is not None else ""


def _get_call_target(call_node: Any) -> Optional[str]:
    function = call_node.child_by_field_name("function")
    return _text(function) or None


def _extract_related_variables(node: Optional[Any]) -> List[str]:
    values: List[str] = []
    seen: Set[str] = set()

    def walk(item: Any) -> None:
        if item.type == "identifier":
            value = _text(item)
            if value not in seen and value not in _IGNORED_VAR_NAMES:
                seen.add(value)
                values.append(value)
        for child in item.children:
            walk(child)

    if node is not None:
        walk(node)
    return values


def _call_arguments(call_node: Any) -> List[Any]:
    arguments = call_node.child_by_field_name("arguments")
    return list(arguments.named_children) if arguments is not None else []


def _is_string_literal(node: Optional[Any]) -> bool:
    return node is not None and node.type in {"string", "concatenated_string"} and "{" not in _text(node)


def _expression_kind(node: Optional[Any]) -> str:
    if node is None:
        return "missing"
    if _is_string_literal(node):
        return "literal"
    if node.type in {"string", "concatenated_string"}:
        return "f_string"
    text = _text(node)
    if node.type == "binary_operator":
        return "string_concatenation" if "+" in text else "percent_formatting"
    if node.type == "call" and (_get_call_target(node) or "").endswith(".format"):
        return "format_call"
    if node.type in {"list", "tuple"}:
        return "argument_vector"
    return "dynamic_expression"


def _is_parameterized_query(query_node: Optional[Any], argument_nodes: List[Any]) -> bool:
    if not _is_string_literal(query_node) or len(argument_nodes) < 2:
        return False
    return any(token in _text(query_node) for token in ("?", "%s", "%(", ":", "$1")) and argument_nodes[1].type in {"tuple", "list", "dictionary", "identifier"}


def _has_shell_true(argument_nodes: List[Any]) -> bool:
    return any(node.type == "keyword_argument" and _text(node).replace(" ", "") == "shell=True" for node in argument_nodes)


def _is_command_target(target: str) -> bool:
    return target in {"os.system", "os.popen"} or target.startswith("os.spawn") or target in {
        "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"
    }


def _secret_like(name: str) -> bool:
    return any(keyword in name.lower() for keyword in _SECRET_KEYWORDS)


def analyze_security_structure(source_code: str, file_path: str = "") -> Dict[str, Any]:
    """Extract file-scoped, deterministic security evidence without executing source."""
    try:
        tree = parse_python_source(source_code)
    except Exception:
        return {"language": "python", "parse_status": "error", "file_path": file_path, "security_signals": []}

    signals: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, int]] = set()

    def add_signal(signal_type: str, category: str, severity: str, confidence: str, name: str,
                   line: int, evidence: str, related_variables: List[str], message: str,
                   assessment: Optional[Dict[str, Any]] = None) -> None:
        key = (signal_type, name, line)
        if key in seen:
            return
        seen.add(key)
        clean_evidence = evidence.strip().replace("\r\n", " ").replace("\n", " ")
        if len(clean_evidence) > 240:
            clean_evidence = clean_evidence[:237] + "..."
        stable_input = "|".join((file_path, str(line), category, signal_type, name, clean_evidence))
        signals.append({
            "evidence_id": hashlib.sha256(stable_input.encode("utf-8")).hexdigest(), "file_path": file_path,
            "line": line, "category": category, "signal_type": signal_type, "severity": severity,
            "confidence": confidence, "call_name": name, "name": name, "evidence": clean_evidence,
            "related_variables": related_variables, "argument_assessment": assessment or {}, "message": message,
        })

    def inspect_module_secrets(root_node: Any) -> None:
        for stmt in root_node.children:
            if stmt.type in {"function_definition", "async_function_definition", "class_definition"}:
                continue
            assigns: List[Any] = []
            if stmt.type == "expression_statement":
                for c in stmt.children:
                    if c.type == "assignment":
                        assigns.append(c)
            elif stmt.type == "assignment":
                assigns.append(stmt)
            for a in assigns:
                left = a.child_by_field_name("left")
                right = a.child_by_field_name("right")
                if left is not None and right is not None and left.type == "identifier":
                    target = _text(left).strip()
                    if _secret_like(target) and right.type == "string":
                        line = a.start_point[0] + 1
                        add_signal(
                            "possible_hardcoded_secret",
                            "credential_management",
                            "medium",
                            "medium",
                            target,
                            line,
                            f"{target} assigned a string literal",
                            [target],
                            "A secret-like variable is assigned a string literal.",
                        )

    def inspect_function(function_node: Any) -> None:
        parameters = set(_extract_related_variables(function_node.child_by_field_name("parameters")))
        aliases = {name for name in parameters if _secret_like(name)}
        credential_reported = False

        # Collect local assignments within this function: var_name -> [(assign_node, right_node)]
        local_assignments: Dict[str, List[Tuple[Any, Any]]] = {}

        def collect_assignments(n: Any) -> None:
            if n.type == "assignment":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and right is not None and left.type == "identifier":
                    vname = _text(left).strip()
                    if vname:
                        local_assignments.setdefault(vname, []).append((n, right))
            for c in n.children:
                if c.type not in {"function_definition", "async_function_definition", "class_definition"}:
                    collect_assignments(c)

        collect_assignments(function_node)

        def walk(node: Any) -> None:
            nonlocal credential_reported
            line = node.start_point[0] + 1
            if node.type == "assignment":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                target = _text(left).strip()
                if left is not None and right is not None:
                    if _secret_like(target) and right.type == "string":
                        add_signal("possible_hardcoded_secret", "credential_management", "medium", "medium", target, line,
                                   f"{target} assigned a string literal", [target], "A secret-like variable is assigned a string literal.")
                    if target and _secret_like(target) and set(_extract_related_variables(right)) & aliases:
                        aliases.add(target)
            if node.type == "dictionary" and aliases and not credential_reported:
                used_aliases = set(_extract_related_variables(node)) & aliases
                if "authorization" in _text(node).lower() and used_aliases:
                    add_signal("credential_propagation_to_authorization_sink", "credential_handling", "medium", "medium",
                               "Authorization header", line, _text(node), sorted(used_aliases),
                               "A secret-like parameter is propagated to an Authorization header.",
                               {"flow": "parameter_to_secret_like_variable_to_authorization_header"})
                    credential_reported = True
            if node.type == "call":
                target, arguments = _get_call_target(node), _call_arguments(node)
                related = _extract_related_variables(node)
                if target and target.split(".")[-1] in _DB_EXEC_NAMES:
                    query_node = arguments[0] if arguments else None
                    query_kind = _expression_kind(query_node)
                    eval_node = query_node

                    if query_node is not None and query_node.type == "identifier":
                        vname = _text(query_node).strip()
                        if vname not in parameters:
                            preceding = [a for a in local_assignments.get(vname, []) if a[0].end_byte <= node.start_byte]
                            if len(preceding) == 1:
                                eval_node = preceding[0][1]
                                query_kind = _expression_kind(eval_node)

                    parameterized = _is_parameterized_query(eval_node, arguments)
                    if not parameterized and query_kind != "literal":
                        severity = "high" if query_kind in {"string_concatenation", "f_string", "percent_formatting", "format_call"} else "medium"
                        add_signal("unsafe_database_execution", "sql_injection", severity, "high" if severity == "high" else "medium", target, line, _text(node), related,
                                   "A database query is dynamically constructed or cannot be verified as parameterized.",
                                   {"query_kind": query_kind, "parameterized": False, "dynamic_value_present": True})
                elif target and _is_command_target(target):
                    command_node = arguments[0] if arguments else None
                    command_kind, shell_true = _expression_kind(command_node), _has_shell_true(arguments)
                    dynamic = command_kind not in {"literal", "argument_vector"}
                    if shell_true or dynamic:
                        severity, confidence, message = "critical", "high", "Command execution uses a shell or dynamically constructed command."
                    elif command_kind == "argument_vector":
                        severity, confidence, message = "medium", "medium", "External command execution uses an argument vector; shell injection was not detected."
                    else:
                        severity, confidence, message = "medium", "medium", "Direct command execution call detected."
                    add_signal("command_execution_call", "command_execution", severity, confidence, target, line, _text(node), related, message,
                               {"command_kind": command_kind, "shell": shell_true, "dynamic_value_present": dynamic})
                elif target and target in _DYNAMIC_EXEC_NAMES:
                    expression_kind = _expression_kind(arguments[0] if arguments else None)
                    add_signal("dynamic_code_execution", "dynamic_code_execution", "critical" if expression_kind != "literal" else "high", "high", target, line, _text(node), related,
                               "Dynamic code execution is invoked.", {"expression_kind": expression_kind, "dynamic_value_present": expression_kind != "literal"})
                elif target and _is_file_op_target(target):
                    path_node = arguments[0] if arguments else None
                    if path_node is not None:
                        path_kind = _expression_kind(path_node)
                        if path_kind != "literal" and path_kind != "missing":
                            if path_kind in {"string_concatenation", "f_string", "percent_formatting", "format_call"}:
                                severity, confidence = "high", "high"
                            else:
                                severity, confidence = "medium", "medium"
                            add_signal(
                                "path_traversal_call",
                                "path_traversal",
                                severity,
                                confidence,
                                target,
                                line,
                                _text(node),
                                related,
                                "A file operation path is dynamically constructed or cannot be verified as static.",
                                {"path_kind": path_kind, "dynamic_value_present": True},
                            )
                elif target and _is_deserialization_target(target):
                    add_signal(
                        "insecure_deserialization_call",
                        "insecure_deserialization",
                        "critical",
                        "high",
                        target,
                        line,
                        _text(node),
                        related,
                        "Insecure object deserialization is invoked on potentially untrusted input.",
                        {"deserializer": target, "untrusted_input": True},
                    )
            for child in node.children:
                if child.type not in {"function_definition", "async_function_definition", "class_definition"}:
                    walk(child)

        walk(function_node)

    inspect_module_secrets(tree.root_node)

    def traverse(node: Any) -> None:
        if node.type in {"function_definition", "async_function_definition"}:
            inspect_function(node)
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    return {"language": "python", "parse_status": "has_errors" if _check_has_errors(tree.root_node) else "success", "file_path": file_path, "security_signals": signals}
