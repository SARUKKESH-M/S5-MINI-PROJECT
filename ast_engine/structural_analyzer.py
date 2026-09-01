"""AST Structural Analyzer for CodeSentinel.

Converts raw Tree-sitter AST into a structured, deterministic, JSON-serializable dictionary.
Treats source code strictly as static data without dynamic execution or side-effects.
"""

from typing import Any, Dict, List, Optional, Set
from ast_engine.python_parser import parse_python_source


def _check_has_errors(node: Any) -> bool:
    """Recursively check if the AST contains error nodes."""
    if node.has_error or node.type == "ERROR":
        return True
    return any(_check_has_errors(child) for child in node.children)


def _extract_imports(root_node: Any) -> List[str]:
    """Extract imported module names from import statements."""
    imports: List[str] = []
    seen: Set[str] = set()

    def _walk_imports(node: Any) -> None:
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    mod_name = child.text.decode("utf-8")
                    if mod_name not in seen:
                        seen.add(mod_name)
                        imports.append(mod_name)
                elif child.type == "aliased_import":
                    name_child = child.child_by_field_name("name")
                    if name_child:
                        mod_name = name_child.text.decode("utf-8")
                        if mod_name not in seen:
                            seen.add(mod_name)
                            imports.append(mod_name)
        elif node.type == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            if module_node:
                mod_name = module_node.text.decode("utf-8")
                if mod_name not in seen:
                    seen.add(mod_name)
                    imports.append(mod_name)
            else:
                for child in node.children:
                    if child.type in ("dotted_name", "relative_module"):
                        mod_name = child.text.decode("utf-8")
                        if mod_name not in seen:
                            seen.add(mod_name)
                            imports.append(mod_name)
                        break

        for child in node.children:
            _walk_imports(child)

    _walk_imports(root_node)
    return imports


def _extract_parameters(func_node: Any) -> List[str]:
    """Extract function parameter names from a function_definition node."""
    params: List[str] = []
    params_node = func_node.child_by_field_name("parameters")
    if not params_node:
        return params

    for child in params_node.children:
        if child.type == "identifier":
            params.append(child.text.decode("utf-8"))
        elif child.type in ("default_parameter", "typed_parameter", "typed_default_parameter"):
            name_node = child.child_by_field_name("name")
            if name_node:
                params.append(name_node.text.decode("utf-8"))
        elif child.type in ("list_splat_pattern", "dictionary_splat_pattern"):
            params.append(child.text.decode("utf-8"))

    return params


def _extract_calls(func_node: Any) -> List[str]:
    """Extract function and method call targets within a function body."""
    calls: List[str] = []
    seen: Set[str] = set()

    def _walk_calls(node: Any) -> None:
        if node.type == "call":
            func_child = node.child_by_field_name("function")
            if func_child:
                call_str = func_child.text.decode("utf-8")
                if call_str not in seen:
                    seen.add(call_str)
                    calls.append(call_str)

        for child in node.children:
            _walk_calls(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk_calls(body_node)

    return calls


def _extract_assignments(func_node: Any) -> List[str]:
    """Extract assigned variable names within a function body."""
    assignments: List[str] = []
    seen: Set[str] = set()

    def _walk_assigns(node: Any) -> None:
        if node.type == "assignment":
            left_node = node.child_by_field_name("left")
            if left_node:
                if left_node.type == "identifier":
                    var_name = left_node.text.decode("utf-8")
                    if var_name not in seen:
                        seen.add(var_name)
                        assignments.append(var_name)
                else:
                    for child in left_node.children:
                        if child.type == "identifier":
                            var_name = child.text.decode("utf-8")
                            if var_name not in seen:
                                seen.add(var_name)
                                assignments.append(var_name)

        for child in node.children:
            _walk_assigns(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk_assigns(body_node)

    return assignments


def _extract_control_flow(func_node: Any) -> Dict[str, int]:
    """Count control-flow constructs inside a function body."""
    cf_counts = {
        "if": 0,
        "for": 0,
        "while": 0,
        "try": 0,
        "except": 0,
        "with": 0,
    }

    def _walk_cf(node: Any) -> None:
        if node.type == "if_statement":
            cf_counts["if"] += 1
        elif node.type == "for_statement":
            cf_counts["for"] += 1
        elif node.type == "while_statement":
            cf_counts["while"] += 1
        elif node.type == "try_statement":
            cf_counts["try"] += 1
        elif node.type == "except_clause":
            cf_counts["except"] += 1
        elif node.type == "with_statement":
            cf_counts["with"] += 1

        for child in node.children:
            _walk_cf(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk_cf(body_node)

    return cf_counts


def _extract_operations(func_node: Any) -> Dict[str, int]:
    """Count basic syntactic operations inside a function body."""
    ops = {
        "binary_expressions": 0,
        "string_literals": 0,
        "function_calls": 0,
        "attribute_calls": 0,
        "comparisons": 0,
    }

    def _walk_ops(node: Any) -> None:
        if node.type == "binary_operator":
            ops["binary_expressions"] += 1
        elif node.type == "string":
            ops["string_literals"] += 1
        elif node.type == "comparison_operator":
            ops["comparisons"] += 1
        elif node.type == "call":
            func_child = node.child_by_field_name("function")
            if func_child:
                if func_child.type == "identifier":
                    ops["function_calls"] += 1
                elif func_child.type == "attribute":
                    ops["attribute_calls"] += 1

        for child in node.children:
            _walk_ops(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk_ops(body_node)

    return ops


def _extract_return_count(func_node: Any) -> int:
    """Count return statements inside a function body."""
    count = 0

    def _walk_returns(node: Any) -> None:
        nonlocal count
        if node.type == "return_statement":
            count += 1
        for child in node.children:
            _walk_returns(child)

    body_node = func_node.child_by_field_name("body")
    if body_node:
        _walk_returns(body_node)

    return count


def analyze_python_structure(source_code: str) -> Dict[str, Any]:
    """Analyze Python source code and return a structured JSON-serializable representation."""
    try:
        tree = parse_python_source(source_code)
    except Exception as err:
        return {
            "language": "python",
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
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            class_name = name_node.text.decode("utf-8") if name_node else "UnknownClass"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            methods: List[Dict[str, Any]] = []
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    if child.type == "function_definition":
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

        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8") if name_node else "anonymous"
            is_async = any(child.type == "async" for child in node.children)
            is_method = current_class is not None
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            parameters = _extract_parameters(node)
            calls = _extract_calls(node)
            assignments = _extract_assignments(node)
            control_flow = _extract_control_flow(node)
            operations = _extract_operations(node)
            return_count = _extract_return_count(node)

            functions_list.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": is_method,
                "class_name": current_class,
                "parameters": parameters,
                "return_statement_count": return_count,
                "start_line": start_line,
                "end_line": end_line,
                "calls": calls,
                "assignments": assignments,
                "control_flow": control_flow,
                "operations": operations,
            })

            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _traverse_structure(child, current_class=current_class)
            return

        for child in node.children:
            _traverse_structure(child, current_class=current_class)

    _traverse_structure(tree.root_node)

    return {
        "language": "python",
        "parse_status": parse_status,
        "classes": classes_list,
        "functions": functions_list,
        "imports": imports,
    }
