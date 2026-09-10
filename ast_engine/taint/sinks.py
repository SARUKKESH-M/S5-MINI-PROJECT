"""Syntactic Sink Pattern Registries for Python and JavaScript.

Frozen Specification: Phase 30C + Phase 30D-R.
Matches approved syntactic sinks with precise sensitive argument indexing.
"""

from typing import Any, List, Optional, Set
from ast_engine.taint.models import TaintSink


def _node_text(node: Optional[Any]) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text or "")


# Python Sinks
_PY_DB_EXEC_NAMES = {"execute", "executemany", "executescript"}
_PY_COMMAND_TARGETS = {
    "os.system", "os.popen",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
}


def match_python_sink(call_node: Any, file_path: str = "") -> Optional[TaintSink]:
    """Inspect a Python call AST node and return an approved TaintSink if recognized."""
    if call_node is None or call_node.type != "call":
        return None

    line = call_node.start_point[0] + 1
    fn_node = call_node.child_by_field_name("function")
    target_str = _node_text(fn_node).strip()

    # 1. Database execution sink
    fn_leaf = target_str.split(".")[-1]
    if fn_leaf in _PY_DB_EXEC_NAMES:
        return TaintSink(
            name=target_str,
            category="sql_injection",
            line=line,
            file_path=file_path,
            target_arg_indices=(0,),
            ast_pattern=target_str,
        )

    # 2. Command execution sink
    if target_str in _PY_COMMAND_TARGETS or target_str.startswith("os.spawn"):
        return TaintSink(
            name=target_str,
            category="command_execution",
            line=line,
            file_path=file_path,
            target_arg_indices=(0,),
            ast_pattern=target_str,
        )

    return None


# JavaScript Sinks
_JS_SQL_RECEIVERS = {"db", "database", "client", "pool", "connection", "conn", "sequelize"}
_JS_SQL_METHODS = {"query", "execute"}


def match_javascript_call_sink(
    call_node: Any,
    file_path: str = "",
    cp_aliases: Optional[Set[str]] = None,
    cp_fn_aliases: Optional[Set[str]] = None,
) -> Optional[TaintSink]:
    """Inspect a JavaScript call_expression AST node and return an approved TaintSink if recognized."""
    if call_node is None or call_node.type != "call_expression":
        return None

    line = call_node.start_point[0] + 1
    fn_node = call_node.child_by_field_name("function")
    if not fn_node:
        return None

    # Member expression calls
    if fn_node.type == "member_expression":
        prop = fn_node.child_by_field_name("property")
        obj = fn_node.child_by_field_name("object")
        prop_str = _node_text(prop).strip()
        obj_str = _node_text(obj).strip()

        # Database sinks: db.query, sequelize.execute, knex.raw, prisma.$queryRaw
        if obj_str in _JS_SQL_RECEIVERS and prop_str in _JS_SQL_METHODS:
            return TaintSink(
                name=f"{obj_str}.{prop_str}",
                category="sql_injection",
                line=line,
                file_path=file_path,
                target_arg_indices=(0,),
                ast_pattern=f"{obj_str}.{prop_str}",
            )
        if obj_str == "knex" and prop_str == "raw":
            return TaintSink(
                name="knex.raw",
                category="sql_injection",
                line=line,
                file_path=file_path,
                target_arg_indices=(0,),
                ast_pattern="knex.raw",
            )
        if obj_str == "prisma" and prop_str in ("$queryRaw", "$executeRaw"):
            return TaintSink(
                name=f"prisma.{prop_str}",
                category="sql_injection",
                line=line,
                file_path=file_path,
                target_arg_indices=(0,),
                ast_pattern=f"prisma.{prop_str}",
            )

        # Command execution: cp.exec, cp.execSync, require("child_process").exec
        active_cp_aliases = cp_aliases or {"child_process"}
        if prop_str in ("exec", "execSync"):
            if obj_str in active_cp_aliases:
                return TaintSink(
                    name=f"{obj_str}.{prop_str}",
                    category="command_execution",
                    line=line,
                    file_path=file_path,
                    target_arg_indices=(0,),
                    ast_pattern=f"{obj_str}.{prop_str}",
                )
            if obj and obj.type == "call_expression":
                req_fn = obj.child_by_field_name("function")
                req_args = obj.child_by_field_name("arguments")
                if req_fn and _node_text(req_fn) == "require" and req_args:
                    arg_texts = [_node_text(c).strip("'\"`") for c in req_args.children if c.type not in ("(", ")", ",")]
                    if len(arg_texts) == 1 and arg_texts[0] == "child_process":
                        return TaintSink(
                            name=f'require("child_process").{prop_str}',
                            category="command_execution",
                            line=line,
                            file_path=file_path,
                            target_arg_indices=(0,),
                            ast_pattern=f'require("child_process").{prop_str}',
                        )

        # DOM XSS: insertAdjacentHTML(pos, value) - sensitive arg index 1
        if prop_str == "insertAdjacentHTML":
            return TaintSink(
                name="element.insertAdjacentHTML",
                category="xss",
                line=line,
                file_path=file_path,
                target_arg_indices=(1,),
                ast_pattern="insertAdjacentHTML",
            )

        # DOM XSS: document.write / document.writeln - sensitive arg index 0
        if obj_str == "document" and prop_str in ("write", "writeln"):
            return TaintSink(
                name=f"document.{prop_str}",
                category="xss",
                line=line,
                file_path=file_path,
                target_arg_indices=(0,),
                ast_pattern=f"document.{prop_str}",
            )

    # Identifier calls: destructured exec / execSync
    elif fn_node.type == "identifier":
        fn_name = _node_text(fn_node).strip()
        active_fn_aliases = cp_fn_aliases or set()
        if fn_name in active_fn_aliases:
            return TaintSink(
                name=fn_name,
                category="command_execution",
                line=line,
                file_path=file_path,
                target_arg_indices=(0,),
                ast_pattern=fn_name,
            )

    return None


def match_javascript_dom_assignment_sink(
    assignment_node: Any,
    file_path: str = "",
) -> Optional[TaintSink]:
    """Check if assignment_expression targets innerHTML or outerHTML."""
    if assignment_node is None or assignment_node.type != "assignment_expression":
        return None

    line = assignment_node.start_point[0] + 1
    left = assignment_node.child_by_field_name("left")
    if left and left.type == "member_expression":
        prop = left.child_by_field_name("property")
        prop_str = _node_text(prop).strip()
        if prop_str in ("innerHTML", "outerHTML"):
            return TaintSink(
                name=f"element.{prop_str}",
                category="xss",
                line=line,
                file_path=file_path,
                target_arg_indices=(0,),  # RHS evaluated
                ast_pattern=prop_str,
            )

    return None
