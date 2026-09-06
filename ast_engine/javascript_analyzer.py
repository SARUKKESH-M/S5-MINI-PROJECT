"""JavaScript AST Structural Analyzer for CodeSentinel.

Converts raw Tree-sitter JavaScript AST into a structured, deterministic, JSON-serializable dictionary.
Treats source code strictly as static data without dynamic execution or side-effects.
"""

from typing import Any, Dict, List, Optional, Set
from ast_engine.javascript_parser import parse_javascript_source


def _check_has_errors(node: Any) -> bool:
    """Recursively check if the AST contains error nodes."""
    if node.has_error or node.type == "ERROR":
        return True
    return any(_check_has_errors(child) for child in node.children)


def _extract_imports(root_node: Any) -> List[str]:
    """Extract imported module names from import statements and require calls."""
    imports: List[str] = []
    seen: Set[str] = set()

    def _walk(node: Any) -> None:
        # ES6 import statement: import foo from 'bar';
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node:
                raw_text = source_node.text.decode("utf-8").strip("'\"`")
                if raw_text and raw_text not in seen:
                    seen.add(raw_text)
                    imports.append(raw_text)

        # CommonJS require call: const x = require('./lib');
        elif node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node and fn_node.text.decode("utf-8") == "require":
                args_node = node.child_by_field_name("arguments")
                if args_node and args_node.children:
                    for arg in args_node.children:
                        if arg.type in ("string", "string_fragment", "template_string"):
                            raw_text = arg.text.decode("utf-8").strip("'\"`")
                            if raw_text and raw_text not in seen:
                                seen.add(raw_text)
                                imports.append(raw_text)

        for child in node.children:
            _walk(child)

    _walk(root_node)
    return imports


def _derive_anonymous_name(node: Any) -> str:
    """Derive variable or property name for arrow functions or function expressions."""
    parent = node.parent
    if parent:
        if parent.type == "variable_declarator":
            name_node = parent.child_by_field_name("name")
            if name_node:
                return name_node.text.decode("utf-8")
        elif parent.type == "assignment_expression":
            left_node = parent.child_by_field_name("left")
            if left_node:
                return left_node.text.decode("utf-8")
        elif parent.type == "pair":
            key_node = parent.child_by_field_name("key")
            if key_node:
                return key_node.text.decode("utf-8")

    if node.type == "function_expression":
        fn_name = node.child_by_field_name("name")
        if fn_name:
            return fn_name.text.decode("utf-8")

    return "<anonymous>"


def _extract_parameters(func_node: Any) -> List[str]:
    """Extract parameter names from JavaScript function nodes."""
    params: List[str] = []
    params_node = func_node.child_by_field_name("parameters") or func_node.child_by_field_name("parameter")
    if not params_node:
        return params

    if params_node.type == "identifier":
        params.append(params_node.text.decode("utf-8"))
        return params

    for child in params_node.children:
        if child.type == "identifier":
            params.append(child.text.decode("utf-8"))
        elif child.type == "assignment_pattern":
            left = child.child_by_field_name("left")
            if left and left.type == "identifier":
                params.append(left.text.decode("utf-8"))
        elif child.type == "rest_pattern":
            for c in child.children:
                if c.type == "identifier":
                    params.append(c.text.decode("utf-8"))
                    break

    return params


def _extract_calls(func_node: Any) -> List[str]:
    """Extract call targets within a function body."""
    calls: List[str] = []
    seen: Set[str] = set()

    def _walk(node: Any) -> None:
        if node.type == "call_expression":
            fn_child = node.child_by_field_name("function")
            if fn_child:
                call_str = fn_child.text.decode("utf-8")
                if call_str not in seen:
                    seen.add(call_str)
                    calls.append(call_str)
        for child in node.children:
            _walk(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk(body_node)
    return calls


def _extract_assignments(func_node: Any) -> List[str]:
    """Extract variable assignment targets within a function body."""
    targets: List[str] = []
    seen: Set[str] = set()

    def _walk(node: Any) -> None:
        if node.type == "variable_declarator":
            name_child = node.child_by_field_name("name")
            if name_child and name_child.type == "identifier":
                t = name_child.text.decode("utf-8")
                if t not in seen:
                    seen.add(t)
                    targets.append(t)
        elif node.type == "assignment_expression":
            left_child = node.child_by_field_name("left")
            if left_child and left_child.type == "identifier":
                t = left_child.text.decode("utf-8")
                if t not in seen:
                    seen.add(t)
                    targets.append(t)
        for child in node.children:
            _walk(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk(body_node)
    return targets


def _extract_control_flow(func_node: Any) -> Dict[str, int]:
    """Extract counts of control flow constructs inside function body."""
    counts = {
        "if_statements": 0,
        "for_loops": 0,
        "while_loops": 0,
        "try_blocks": 0,
        "switch_statements": 0,
    }

    def _walk(node: Any) -> None:
        if node.type == "if_statement":
            counts["if_statements"] += 1
        elif node.type in ("for_statement", "for_in_statement", "for_of_statement"):
            counts["for_loops"] += 1
        elif node.type in ("while_statement", "do_statement"):
            counts["while_loops"] += 1
        elif node.type == "try_statement":
            counts["try_blocks"] += 1
        elif node.type == "switch_statement":
            counts["switch_statements"] += 1

        for child in node.children:
            _walk(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk(body_node)
    return counts


def _extract_operations(func_node: Any) -> Dict[str, int]:
    """Extract operational statement counts inside function body."""
    ops = {
        "binary_expressions": 0,
        "string_literals": 0,
        "comparisons": 0,
        "function_calls": 0,
        "attribute_calls": 0,
    }

    def _walk(node: Any) -> None:
        if node.type == "binary_expression":
            ops["binary_expressions"] += 1
            op_text = node.text.decode("utf-8")
            if any(sym in op_text for sym in ("===", "!==", "==", "!=", "<", ">", "<=", ">=")):
                ops["comparisons"] += 1
        elif node.type in ("string", "template_string"):
            ops["string_literals"] += 1
        elif node.type == "call_expression":
            fn_child = node.child_by_field_name("function")
            if fn_child:
                if fn_child.type == "identifier":
                    ops["function_calls"] += 1
                elif fn_child.type == "member_expression":
                    ops["attribute_calls"] += 1

        for child in node.children:
            _walk(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk(body_node)
    return ops


def _extract_return_count(func_node: Any) -> int:
    """Count return statements inside a function body."""
    count = 0

    def _walk(node: Any) -> None:
        nonlocal count
        if node.type == "return_statement":
            count += 1
        for child in node.children:
            _walk(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk(body_node)
    return count


def analyze_javascript_structure(source_code: str) -> Dict[str, Any]:
    """Analyze JavaScript source code and return a structured JSON-serializable representation.

    Supports function declarations, function expressions, arrow functions, class methods,
    and class declarations with accurate 1-indexed line spans and nested scope support.
    """
    try:
        tree = parse_javascript_source(source_code)
    except Exception as err:
        return {
            "language": "javascript",
            "parse_status": "error",
            "error_detail": str(err),
            "classes": [],
            "functions": [],
            "imports": [],
        }

    has_errors = _check_has_errors(tree.root_node)
    parse_status = "has_errors" if has_errors else "success"

    imports = _extract_imports(tree.root_node)
    classes_list: List[Dict[str, Any]] = []
    functions_list: List[Dict[str, Any]] = []

    def _traverse_structure(node: Any, current_class: Optional[str] = None) -> None:
        # Class Declaration
        if node.type == "class_declaration":
            name_node = node.child_by_field_name("name")
            class_name = name_node.text.decode("utf-8") if name_node else "UnknownClass"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            methods: List[Dict[str, Any]] = []
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    if child.type == "method_definition":
                        m_name_node = child.child_by_field_name("name")
                        m_name = m_name_node.text.decode("utf-8") if m_name_node else "anonymous"
                        m_async = any(c.type == "async" for c in child.children)
                        methods.append({"name": m_name, "is_async": m_async})

            classes_list.append({
                "name": class_name,
                "start_line": start_line,
                "end_line": end_line,
                "methods": methods,
            })

            if body_node:
                for child in body_node.children:
                    _traverse_structure(child, current_class=class_name)
            return

        # Method Definition (inside class)
        if node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8") if name_node else "anonymous"
            is_async = any(child.type == "async" for child in node.children)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            functions_list.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": True,
                "class_name": current_class,
                "parameters": _extract_parameters(node),
                "return_statement_count": _extract_return_count(node),
                "start_line": start_line,
                "end_line": end_line,
                "calls": _extract_calls(node),
                "assignments": _extract_assignments(node),
                "control_flow": _extract_control_flow(node),
                "operations": _extract_operations(node),
            })

            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _traverse_structure(child, current_class=current_class)
            return

        # Function Declaration
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8") if name_node else "<anonymous>"
            is_async = any(child.type == "async" for child in node.children)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            functions_list.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": current_class is not None,
                "class_name": current_class,
                "parameters": _extract_parameters(node),
                "return_statement_count": _extract_return_count(node),
                "start_line": start_line,
                "end_line": end_line,
                "calls": _extract_calls(node),
                "assignments": _extract_assignments(node),
                "control_flow": _extract_control_flow(node),
                "operations": _extract_operations(node),
            })

            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _traverse_structure(child, current_class=current_class)
            return

        # Arrow Function or Function Expression
        if node.type in ("arrow_function", "function_expression"):
            func_name = _derive_anonymous_name(node)
            is_async = any(child.type == "async" for child in node.children)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            functions_list.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": current_class is not None,
                "class_name": current_class,
                "parameters": _extract_parameters(node),
                "return_statement_count": _extract_return_count(node),
                "start_line": start_line,
                "end_line": end_line,
                "calls": _extract_calls(node),
                "assignments": _extract_assignments(node),
                "control_flow": _extract_control_flow(node),
                "operations": _extract_operations(node),
            })

            body_node = node.child_by_field_name("body")
            if body_node:
                if body_node.type == "statement_block":
                    for child in body_node.children:
                        _traverse_structure(child, current_class=current_class)
                else:
                    _traverse_structure(body_node, current_class=current_class)
            return

        for child in node.children:
            _traverse_structure(child, current_class=current_class)

    _traverse_structure(tree.root_node)

    return {
        "language": "javascript",
        "parse_status": parse_status,
        "classes": classes_list,
        "functions": functions_list,
        "imports": imports,
    }
