"""Syntactic Source Pattern Registries for Python and JavaScript.

Frozen Specification: Phase 30C + Phase 30D-R.
Matches strictly approved syntactic sources without broad keyword or arbitrary receiver matching.
"""

from typing import Any, Optional
from ast_engine.taint.models import TaintSource


def _node_text(node: Optional[Any]) -> str:
    """Extract string text from a Tree-sitter AST node."""
    if node is None:
        return ""
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text or "")


# Approved Python source receivers and property roots
_PYTHON_REQUEST_RECEIVERS = {"request", "flask.request"}
_PYTHON_REQUEST_PROPERTIES = {"args", "form", "json", "data", "values", "params"}


def match_python_source(node: Any, file_path: str = "") -> Optional[TaintSource]:
    """Check if an AST node represents an approved Python taint source.

    Recognizes:
    - sys.argv, sys.argv[...]
    - request.{args,form,json,data,values,params} (and subscript / .get() calls)
    - flask.request.{args,form,json,data,values,params}
    """
    if node is None:
        return None

    line = node.start_point[0] + 1
    raw_text = _node_text(node).strip()

    # 1. CLI arguments: sys.argv or sys.argv[...]
    if raw_text == "sys.argv" or raw_text.startswith("sys.argv["):
        return TaintSource(
            name="sys.argv",
            category="cli_argument",
            line=line,
            file_path=file_path,
            ast_pattern=raw_text[:60],
        )

    # 2. Check for request / flask.request
    # Handled patterns:
    # attribute: request.args, request.data
    # subscript: request.args['id']
    # call: request.args.get('id')
    curr = node
    # If call to .get(...), inspect the function attribute
    if curr.type == "call":
        fn_node = curr.child_by_field_name("function")
        if fn_node and fn_node.type == "attribute":
            attr_name = _node_text(fn_node.child_by_field_name("attribute"))
            if attr_name == "get":
                curr = fn_node.child_by_field_name("object")

    # If subscript request.args[...], unwrap to object
    if curr and curr.type == "subscript":
        val_node = curr.child_by_field_name("value")
        if val_node:
            curr = val_node

    if curr and curr.type == "attribute":
        attr_name = _node_text(curr.child_by_field_name("attribute"))
        obj_node = curr.child_by_field_name("object")
        obj_text = _node_text(obj_node).strip()

        if attr_name in _PYTHON_REQUEST_PROPERTIES and obj_text in _PYTHON_REQUEST_RECEIVERS:
            source_name = f"{obj_text}.{attr_name}"
            return TaintSource(
                name=source_name,
                category="http_parameter",
                line=line,
                file_path=file_path,
                ast_pattern=raw_text[:60],
            )

    return None


_JS_REQUEST_RECEIVERS = {"req", "request"}
_JS_REQUEST_PROPERTIES = {"params", "query", "body"}
_JS_DOM_TARGET_RECEIVERS = {"e.target", "event.target", "elem", "element"}


def match_javascript_source(node: Any, file_path: str = "") -> Optional[TaintSource]:
    """Check if an AST node represents an approved JavaScript taint source.

    Recognizes:
    - req.{params,query,body}, request.{params,query,body} (and property / subscript access)
    - location.search, location.hash, window.location.search, window.location.hash
    - e.target.value, elem.value, element.value
    - document.getElementById(...).value
    """
    if node is None:
        return None

    line = node.start_point[0] + 1
    raw_text = _node_text(node).strip()

    # 1. Browser location inputs
    if raw_text in {
        "location.search", "location.hash",
        "window.location.search", "window.location.hash"
    }:
        return TaintSource(
            name=raw_text,
            category="browser_input",
            line=line,
            file_path=file_path,
            ast_pattern=raw_text,
        )

    # 2. DOM element value: document.getElementById(...).value
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        prop_text = _node_text(prop)
        if prop_text == "value":
            obj = node.child_by_field_name("object")
            if obj:
                obj_text = _node_text(obj).strip()
                if obj_text in _JS_DOM_TARGET_RECEIVERS:
                    return TaintSource(
                        name=f"{obj_text}.value",
                        category="dom_input",
                        line=line,
                        file_path=file_path,
                        ast_pattern=raw_text[:60],
                    )
                if obj.type == "call_expression":
                    fn = obj.child_by_field_name("function")
                    if fn and _node_text(fn).endswith("getElementById"):
                        return TaintSource(
                            name="document.getElementById(...).value",
                            category="dom_input",
                            line=line,
                            file_path=file_path,
                            ast_pattern=raw_text[:60],
                        )

    # 3. Request inputs (req.query, req.params, req.body)
    # Check if this node or any ancestor chain reaches req.{query,params,body}
    # Examples: req.query, req.query.id, req.query['id'], req.params.user
    curr = node
    # If subscript or sub-property access (e.g. req.query.foo or req.query['foo']), drill down
    while curr and curr.type in {"member_expression", "subscript_expression"}:
        if curr.type == "member_expression":
            obj = curr.child_by_field_name("object")
            prop = curr.child_by_field_name("property")
            obj_text = _node_text(obj).strip()
            prop_text = _node_text(prop).strip()
            if obj_text in _JS_REQUEST_RECEIVERS and prop_text in _JS_REQUEST_PROPERTIES:
                return TaintSource(
                    name=f"{obj_text}.{prop_text}",
                    category="http_parameter",
                    line=line,
                    file_path=file_path,
                    ast_pattern=raw_text[:60],
                )
            curr = obj
        elif curr.type == "subscript_expression":
            curr = curr.child_by_field_name("object")
        else:
            break

    return None
