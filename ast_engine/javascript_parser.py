"""JavaScript AST Parser module using Tree-sitter for CodeSentinel.

Treats source code strictly as static text without executing or evaluating it.
"""

from typing import Any, Dict, List, Optional
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser, Tree

# Initialize JavaScript Language and Parser instance
_JS_LANGUAGE = Language(tsjavascript.language())
_PARSER = Parser(_JS_LANGUAGE)


def parse_javascript_source(source_code: str) -> Tree:
    """Parse JavaScript source code string into a Tree-sitter AST Tree.

    Source code is treated strictly as text. It is never executed or dynamically evaluated.
    Handles malformed source safely by returning the partial/error tree.
    """
    source_bytes = source_code.encode("utf-8")
    return _PARSER.parse(source_bytes)


def extract_javascript_function_names(source_code: str) -> List[Dict[str, Optional[Any]]]:
    """Traverse the JavaScript AST and extract structural function & method information.

    Returns a list of dicts with keys: 'name', 'is_async', 'is_method', 'class_name'.
    """
    tree = parse_javascript_source(source_code)
    extracted_functions: List[Dict[str, Optional[Any]]] = []

    def _walk_ast(node: Any, current_class: Optional[str] = None) -> None:
        if node.type == "class_declaration":
            name_node = node.child_by_field_name("name")
            class_name = name_node.text.decode("utf-8") if name_node else None
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _walk_ast(child, current_class=class_name)
            return

        if node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8") if name_node else None
            is_async = any(child.type == "async" for child in node.children)
            extracted_functions.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": True,
                "class_name": current_class,
            })
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _walk_ast(child, current_class=current_class)
            return

        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8") if name_node else None
            is_async = any(child.type == "async" for child in node.children)
            extracted_functions.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": current_class is not None,
                "class_name": current_class,
            })
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _walk_ast(child, current_class=current_class)
            return

        if node.type in ("arrow_function", "function_expression"):
            # Try to derive name from parent if variable assignment
            func_name = "<anonymous>"
            parent = node.parent
            if parent:
                if parent.type == "variable_declarator":
                    p_name = parent.child_by_field_name("name")
                    if p_name:
                        func_name = p_name.text.decode("utf-8")
                elif parent.type == "assignment_expression":
                    p_left = parent.child_by_field_name("left")
                    if p_left:
                        func_name = p_left.text.decode("utf-8")
                elif parent.type == "pair":
                    p_key = parent.child_by_field_name("key")
                    if p_key:
                        func_name = p_key.text.decode("utf-8")

            if func_name == "<anonymous>" and node.type == "function_expression":
                fn_name = node.child_by_field_name("name")
                if fn_name:
                    func_name = fn_name.text.decode("utf-8")

            is_async = any(child.type == "async" for child in node.children)
            extracted_functions.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": current_class is not None,
                "class_name": current_class,
            })
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _walk_ast(child, current_class=current_class)
            return

        for child in node.children:
            _walk_ast(child, current_class=current_class)

    _walk_ast(tree.root_node)
    return extracted_functions
