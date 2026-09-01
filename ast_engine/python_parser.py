"""Python AST Parser module using Tree-sitter for CodeSentinel.

Treats source code strictly as static text without executing or evaluating it.
"""

from typing import Any, Dict, List, Optional
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Tree

# Initialize Python Language and Parser instance
_PY_LANGUAGE = Language(tspython.language())
_PARSER = Parser(_PY_LANGUAGE)


def parse_python_source(source_code: str) -> Tree:
    """Parse Python source code string into a Tree-sitter AST Tree.

    Source code is treated strictly as text. It is never executed or dynamically evaluated.
    """
    source_bytes = source_code.encode("utf-8")
    return _PARSER.parse(source_bytes)


def extract_function_names(source_code: str) -> List[Dict[str, Optional[Any]]]:
    """Traverse the Python AST and extract structural function & method information.

    Returns a list of dicts with keys: 'name', 'is_async', 'is_method', 'class_name'.
    """
    tree = parse_python_source(source_code)
    extracted_functions: List[Dict[str, Optional[Any]]] = []

    def _walk_ast(node: Any, current_class: Optional[str] = None) -> None:
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            class_name = name_node.text.decode("utf-8") if name_node else None
            body_node = node.child_by_field_name("body")
            if body_node:
                for child in body_node.children:
                    _walk_ast(child, current_class=class_name)
            return

        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode("utf-8") if name_node else None
            is_async = any(child.type == "async" for child in node.children)
            is_method = current_class is not None

            extracted_functions.append({
                "name": func_name,
                "is_async": is_async,
                "is_method": is_method,
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
