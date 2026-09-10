"""Tree-sitter JavaScript AST Taint Analysis Visitor and Propagation Engine.

Frozen Specification: Phase 30C + Phase 30D-R.
Performs intra-function and intra-file cross-function dataflow analysis for JavaScript.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from ast_engine.taint.engine import (
    MAX_CALL_DEPTH,
    build_argument_assessment,
    build_taint_trace,
    evaluate_value_against_sink,
    format_evidence_string,
)
from ast_engine.taint.models import (
    FunctionSummary,
    PropagationStep,
    ReturnDependency,
    SanitizerPattern,
    TaintSink,
    TaintSource,
    TaintState,
    TaintTrace,
    TaintValue,
    compose_states,
    join_states,
)
from ast_engine.taint.sanitizers import match_javascript_sanitizer
from ast_engine.taint.sinks import (
    match_javascript_call_sink,
    match_javascript_dom_assignment_sink,
)
from ast_engine.taint.sources import match_javascript_source
from ast_engine.taint.summaries import SummaryRegistry, compute_node_fingerprint


def _node_text(node: Optional[Any]) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text or "")


class JavaScriptTaintEngine:
    """Bounded intra-file taint analysis engine for JavaScript."""

    def __init__(
        self,
        root_node: Any,
        file_path: str = "",
        cp_aliases: Optional[Set[str]] = None,
        cp_fn_aliases: Optional[Set[str]] = None,
    ):
        self.root_node = root_node
        self.file_path = file_path
        self.cp_aliases = cp_aliases or {"child_process"}
        self.cp_fn_aliases = cp_fn_aliases or set()
        self.registry = SummaryRegistry(file_path=file_path)
        self._function_nodes: Dict[str, Any] = {}
        self._duplicate_functions: Set[str] = set()

        self._index_functions()
        self._build_summaries()

    def _index_functions(self) -> None:
        """Scan top-level functions, methods, and variable-assigned arrow functions."""
        def walk(n: Any, current_class: Optional[str] = None) -> None:
            if n.type == "class_declaration":
                name_node = n.child_by_field_name("name")
                c_name = _node_text(name_node).strip() if name_node else None
                body = n.child_by_field_name("body")
                if body:
                    for child in body.children:
                        walk(child, current_class=c_name)
                return

            if n.type == "method_definition":
                name_node = n.child_by_field_name("name")
                m_name = _node_text(name_node).strip() if name_node else None
                if m_name:
                    if m_name in self._function_nodes:
                        self._duplicate_functions.add(m_name)
                    else:
                        self._function_nodes[m_name] = (n, current_class)

            elif n.type == "function_declaration":
                name_node = n.child_by_field_name("name")
                f_name = _node_text(name_node).strip() if name_node else None
                if f_name:
                    if f_name in self._function_nodes:
                        self._duplicate_functions.add(f_name)
                    else:
                        self._function_nodes[f_name] = (n, current_class)

            elif n.type == "variable_declarator":
                val = n.child_by_field_name("value")
                if val and val.type in {"arrow_function", "function_expression"}:
                    name_node = n.child_by_field_name("name")
                    v_name = _node_text(name_node).strip() if name_node else None
                    if v_name:
                        if v_name in self._function_nodes:
                            self._duplicate_functions.add(v_name)
                        else:
                            self._function_nodes[v_name] = (val, current_class)

            for child in n.children:
                walk(child, current_class=current_class)

        walk(self.root_node)

    def _build_summaries(self) -> None:
        """Compute FunctionSummary for all unambiguously indexed JavaScript functions."""
        for fn_name, (fn_node, current_class) in list(self._function_nodes.items()):
            if fn_name in self._duplicate_functions:
                continue
            summary = self._summarize_function(fn_name, fn_node, current_class)
            self.registry.register(summary)

    def _summarize_function(
        self,
        name: str,
        fn_node: Any,
        current_class: Optional[str],
    ) -> FunctionSummary:
        """Extract input-to-return transfer dependencies for a single JavaScript function."""
        params_node = fn_node.child_by_field_name("parameters")
        param_names: List[str] = []
        if params_node:
            for c in params_node.children:
                if c.type == "identifier":
                    param_names.append(_node_text(c).strip())
                elif c.type == "assignment_pattern":
                    left = c.child_by_field_name("left")
                    if left:
                        param_names.append(_node_text(left).strip())

        param_index_map = {p: idx for idx, p in enumerate(param_names)}
        body = fn_node.child_by_field_name("body")
        if not body:
            return FunctionSummary(
                name=name,
                class_name=current_class,
                param_names=tuple(param_names),
                returns_static=True,
                return_dependencies=(),
                returns_unverified_dynamic=False,
                direct_sinks=(),
                fingerprint=compute_node_fingerprint(fn_node),
            )

        # Arrow function concise body: () => expr
        return_nodes: List[Any] = []
        direct_sinks: List[TaintSink] = []

        if body.type != "statement_block":
            # Concise body expression
            return_nodes.append(body)
        else:
            def scan_body(n: Any) -> None:
                if n.type == "return_statement":
                    return_nodes.append(n)
                elif n.type == "call_expression":
                    sink = match_javascript_call_sink(n, file_path=self.file_path, cp_aliases=self.cp_aliases, cp_fn_aliases=self.cp_fn_aliases)
                    if sink:
                        direct_sinks.append(sink)
                for child in n.children:
                    if child.type not in {"function_declaration", "function_expression", "arrow_function", "class_declaration"}:
                        scan_body(child)

            scan_body(body)

        if not return_nodes:
            return FunctionSummary(
                name=name,
                class_name=current_class,
                param_names=tuple(param_names),
                returns_static=True,
                return_dependencies=(),
                returns_unverified_dynamic=False,
                direct_sinks=tuple(direct_sinks),
                fingerprint=compute_node_fingerprint(fn_node),
            )

        return_deps: List[ReturnDependency] = []
        returns_static = True
        returns_unverified_dynamic = False

        for ret in return_nodes:
            expr = ret
            if ret.type == "return_statement":
                # Child 1 is usually the return expression
                expr = None
                for c in ret.children:
                    if c.type not in {"return", ";"}:
                        expr = c
                        break

            if expr is None:
                continue

            # Check static literal
            if expr.type in {"string", "number", "true", "false", "null", "undefined"}:
                continue
            if expr.type == "template_string" and not any(c.type == "template_substitution" for c in expr.children):
                continue

            returns_static = False

            # Check identifier matching parameter
            if expr.type == "identifier":
                ident_name = _node_text(expr).strip()
                if ident_name in param_index_map:
                    return_deps.append(ReturnDependency(param_index=param_index_map[ident_name], sanitizer=None))
                else:
                    returns_unverified_dynamic = True

            # Check sanitizer call: parseInt(x), Number(x), DOMPurify.sanitize(x)
            elif expr.type == "call_expression":
                san = match_javascript_sanitizer(expr)
                args_node = expr.child_by_field_name("arguments")
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")] if args_node else []
                if san and args and args[0].type == "identifier":
                    arg_name = _node_text(args[0]).strip()
                    if arg_name in param_index_map:
                        return_deps.append(ReturnDependency(param_index=param_index_map[arg_name], sanitizer=san))
                    else:
                        returns_unverified_dynamic = True
                else:
                    # Check call to another helper
                    fn_expr = expr.child_by_field_name("function")
                    helper_name = _node_text(fn_expr).strip().split(".")[-1]
                    if helper_name in self._function_nodes and helper_name not in self._duplicate_functions:
                        for arg_c in args:
                            if arg_c.type == "identifier" and _node_text(arg_c).strip() in param_index_map:
                                return_deps.append(ReturnDependency(param_index=param_index_map[_node_text(arg_c).strip()], sanitizer=None))
                    else:
                        returns_unverified_dynamic = True

            # Check binary + concatenation: "SELECT " + param
            elif expr.type == "binary_expression":
                leaves = self._collect_binary_leaves(expr)
                for leaf in leaves:
                    if leaf.type == "identifier":
                        leaf_name = _node_text(leaf).strip()
                        if leaf_name in param_index_map:
                            return_deps.append(ReturnDependency(param_index=param_index_map[leaf_name], sanitizer=None))
                        else:
                            returns_unverified_dynamic = True

            # Check template substitution: `SELECT ${param}`
            elif expr.type == "template_string":
                for c in expr.children:
                    if c.type == "template_substitution":
                        for sub in c.children:
                            if sub.type not in ("${", "}"):
                                if sub.type == "identifier" and _node_text(sub).strip() in param_index_map:
                                    return_deps.append(ReturnDependency(param_index=param_index_map[_node_text(sub).strip()], sanitizer=None))
                                else:
                                    returns_unverified_dynamic = True
            else:
                returns_unverified_dynamic = True

        return FunctionSummary(
            name=name,
            class_name=current_class,
            param_names=tuple(param_names),
            returns_static=returns_static and not return_deps and not returns_unverified_dynamic,
            return_dependencies=tuple(return_deps),
            returns_unverified_dynamic=returns_unverified_dynamic,
            direct_sinks=tuple(direct_sinks),
            fingerprint=compute_node_fingerprint(fn_node),
        )

    def _collect_binary_leaves(self, node: Any) -> List[Any]:
        leaves: List[Any] = []
        def _walk(n: Any) -> None:
            if n.type == "binary_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left:
                    _walk(left)
                if right:
                    _walk(right)
            else:
                leaves.append(n)
        _walk(node)
        return leaves

    def evaluate_sink_argument(
        self,
        sink_node: Any,
        arg_node: Any,
        local_scope_node: Optional[Any] = None,
        designated_params: Optional[Set[str]] = None,
    ) -> Optional[TaintTrace]:
        """Evaluate whether a JavaScript sink argument is TAINTED, SANITIZED, or STATIC."""
        # Determine sink
        sink = None
        if sink_node.type == "call_expression":
            sink = match_javascript_call_sink(sink_node, file_path=self.file_path, cp_aliases=self.cp_aliases, cp_fn_aliases=self.cp_fn_aliases)
        elif sink_node.type == "assignment_expression":
            sink = match_javascript_dom_assignment_sink(sink_node, file_path=self.file_path)

        if not sink:
            return None

        scope = local_scope_node or self._find_enclosing_function(sink_node) or self.root_node
        local_env = self._build_local_environment(
            scope,
            up_to_node=sink_node,
            designated_params=designated_params or set(),
        )

        val = self._evaluate_node(arg_node, local_env, call_stack=set(), depth=0)
        return build_taint_trace(sink, val, file_path=self.file_path)

    def refine_finding(
        self,
        line: int,
        sink_name: str,
        sink_category: str,
        arg_node: Any,
        baseline_signal_type: str,
        baseline_severity: str,
        baseline_evidence: str,
        sink_node: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Refine a baseline security signal using intra-file taint analysis.
        
        Returns a dict:
        - suppressed: bool
        - signal_type: str
        - severity: str
        - evidence: str
        - message: str (optional)
        - taint: dict (optional)
        """
        # Determine sink
        target_sink = None
        if sink_node is not None:
            if sink_node.type == "call_expression":
                target_sink = match_javascript_call_sink(sink_node, file_path=self.file_path, cp_aliases=self.cp_aliases, cp_fn_aliases=self.cp_fn_aliases)
            elif sink_node.type == "assignment_expression":
                target_sink = match_javascript_dom_assignment_sink(sink_node, file_path=self.file_path)

        if target_sink is None:
            curr = arg_node.parent
            while curr and curr.type not in ("call_expression", "assignment_expression"):
                curr = curr.parent
            if curr:
                if curr.type == "call_expression":
                    target_sink = match_javascript_call_sink(curr, file_path=self.file_path, cp_aliases=self.cp_aliases, cp_fn_aliases=self.cp_fn_aliases)
                elif curr.type == "assignment_expression":
                    target_sink = match_javascript_dom_assignment_sink(curr, file_path=self.file_path)

        if target_sink is None:
            target_sink = TaintSink(
                name=sink_name,
                category=sink_category,
                line=line,
                file_path=self.file_path,
                target_arg_indices=(0,),
                ast_pattern=sink_name,
            )

        scope = self._find_enclosing_function(arg_node) or self.root_node
        local_env = self._build_local_environment(scope, up_to_node=arg_node)
        val = self._evaluate_node(arg_node, local_env, call_stack=set(), depth=0)
        trace = build_taint_trace(target_sink, val, file_path=self.file_path)

        if trace is not None and trace.final_state in (TaintState.STATIC, TaintState.SANITIZED):
            return {"suppressed": True}

        if trace is not None and trace.final_state == TaintState.TAINTED:
            ev_str = format_evidence_string(trace.sink, list(trace.sources), list(trace.steps))
            assessment = build_argument_assessment(trace)
            return {
                "suppressed": False,
                "signal_type": baseline_signal_type,
                "severity": baseline_severity,
                "evidence": ev_str,
                "taint": assessment,
            }

        # UNVERIFIED_DYNAMIC or UNKNOWN: preserve baseline finding
        return {
            "suppressed": False,
            "signal_type": baseline_signal_type,
            "severity": baseline_severity,
            "evidence": baseline_evidence,
        }

    def _find_enclosing_function(self, node: Any) -> Optional[Any]:
        curr = node.parent
        while curr:
            if curr.type in {"function_declaration", "function_expression", "arrow_function", "method_definition"}:
                return curr
            curr = curr.parent
        return None

    def _build_local_environment(
        self,
        scope_node: Any,
        up_to_node: Optional[Any] = None,
        designated_params: Optional[Set[str]] = None,
    ) -> Dict[str, TaintValue]:
        env: Dict[str, TaintValue] = {}
        active_designated = designated_params or set()

        # Initialize parameters
        if scope_node.type in {"function_declaration", "function_expression", "arrow_function", "method_definition"}:
            params_node = scope_node.child_by_field_name("parameters")
            if params_node:
                for c in params_node.children:
                    p_name = ""
                    if c.type == "identifier":
                        p_name = _node_text(c).strip()
                    elif c.type == "assignment_pattern":
                        left = c.child_by_field_name("left")
                        if left:
                            p_name = _node_text(left).strip()
                    if p_name:
                        if p_name in active_designated:
                            src = TaintSource(
                                name=f"parameter:{p_name}",
                                category="designated_parameter",
                                line=c.start_point[0] + 1,
                                file_path=self.file_path,
                                ast_pattern=p_name,
                            )
                            env[p_name] = TaintValue(
                                state=TaintState.TAINTED,
                                sources=(src,),
                                steps=(PropagationStep("parameter", p_name, c.start_point[0] + 1, f"param {p_name} externally tainted"),),
                            )
                        else:
                            env[p_name] = TaintValue(state=TaintState.UNKNOWN)

        body = scope_node.child_by_field_name("body") if scope_node.type in {
            "function_declaration", "function_expression", "arrow_function", "method_definition"
        } else scope_node
        if not body:
            return env

        self._process_statement_block(body, env, up_to_node)
        return env

    def _process_statement_block(
        self,
        block_node: Any,
        env: Dict[str, TaintValue],
        up_to_node: Optional[Any] = None,
    ) -> None:
        children = block_node.children if hasattr(block_node, "children") else []
        for child in children:
            if up_to_node is not None and child.start_byte >= up_to_node.start_byte:
                break

            # const / let / var declarations
            if child.type in {"variable_declaration", "lexical_declaration"}:
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        self._process_declarator(decl, env)

            # Expression statement: assignment_expression
            elif child.type == "expression_statement":
                for c in child.children:
                    if c.type == "assignment_expression":
                        self._process_assignment(c, env)

            elif child.type == "assignment_expression":
                self._process_assignment(child, env)

            # Branch (if_statement)
            elif child.type == "if_statement":
                self._process_branch(child, env, up_to_node)

            # Loop (for, while, do)
            elif child.type in {"for_statement", "for_in_statement", "while_statement", "do_statement"}:
                self._process_loop(child, env, up_to_node)

    def _process_declarator(self, decl_node: Any, env: Dict[str, TaintValue]) -> None:
        name_node = decl_node.child_by_field_name("name")
        val_node = decl_node.child_by_field_name("value")
        if not name_node or not val_node:
            return

        line = decl_node.start_point[0] + 1
        var_name = _node_text(name_node).strip()
        if not var_name or name_node.type != "identifier":
            return

        evaluated_val = self._evaluate_node(val_node, env, call_stack=set(), depth=0)
        new_step = PropagationStep("assignment", var_name, line, f"{var_name} = {_node_text(val_node).strip()[:40]}")
        steps = evaluated_val.steps + (new_step,)

        env[var_name] = TaintValue(
            state=evaluated_val.state,
            sources=evaluated_val.sources,
            sanitizers=evaluated_val.sanitizers,
            steps=steps,
        )

    def _process_assignment(self, assign_node: Any, env: Dict[str, TaintValue]) -> None:
        left = assign_node.child_by_field_name("left")
        right = assign_node.child_by_field_name("right")
        if not left or not right:
            return

        line = assign_node.start_point[0] + 1
        var_name = _node_text(left).strip()
        if not var_name or left.type != "identifier":
            return

        evaluated_val = self._evaluate_node(right, env, call_stack=set(), depth=0)
        new_step = PropagationStep("assignment", var_name, line, f"{var_name} = {_node_text(right).strip()[:40]}")
        steps = evaluated_val.steps + (new_step,)

        env[var_name] = TaintValue(
            state=evaluated_val.state,
            sources=evaluated_val.sources,
            sanitizers=evaluated_val.sanitizers,
            steps=steps,
        )

    def _process_branch(
        self,
        if_node: Any,
        env: Dict[str, TaintValue],
        up_to_node: Optional[Any] = None,
    ) -> None:
        consequence = if_node.child_by_field_name("consequence")
        alternative = if_node.child_by_field_name("alternative")

        env_before = dict(env)
        env_a = dict(env_before)
        if consequence:
            self._process_statement_block(consequence, env_a, up_to_node)

        env_b = dict(env_before)
        if alternative:
            self._process_statement_block(alternative, env_b, up_to_node)

        all_keys = set(env_a.keys()) | set(env_b.keys()) | set(env_before.keys())
        for k in all_keys:
            val_a = env_a.get(k, env_before.get(k, TaintValue(state=TaintState.UNKNOWN)))
            val_b = env_b.get(k, env_before.get(k, TaintValue(state=TaintState.UNKNOWN)))

            merged_state = join_states(val_a.state, val_b.state)
            combined_sources = tuple(dict.fromkeys(val_a.sources + val_b.sources))
            combined_sanitizers = tuple(dict.fromkeys(val_a.sanitizers + val_b.sanitizers))
            combined_steps = val_a.steps + val_b.steps

            env[k] = TaintValue(
                state=merged_state,
                sources=combined_sources,
                sanitizers=combined_sanitizers,
                steps=combined_steps,
            )

    def _process_loop(
        self,
        loop_node: Any,
        env: Dict[str, TaintValue],
        up_to_node: Optional[Any] = None,
    ) -> None:
        body = loop_node.child_by_field_name("body")
        if not body:
            return

        env_before = dict(env)
        loop_env = dict(env)
        self._process_statement_block(body, loop_env, up_to_node)

        for k, v in loop_env.items():
            before_val = env_before.get(k, TaintValue(state=TaintState.UNKNOWN))
            if v.state != before_val.state or v.state != TaintState.STATIC:
                env[k] = TaintValue(
                    state=TaintState.UNVERIFIED_DYNAMIC,
                    sources=v.sources,
                    sanitizers=v.sanitizers,
                    steps=v.steps,
                )
            else:
                env[k] = v

    def _evaluate_node(
        self,
        node: Any,
        env: Dict[str, TaintValue],
        call_stack: Set[str],
        depth: int,
    ) -> TaintValue:
        if node is None:
            return TaintValue(state=TaintState.UNKNOWN)

        line = node.start_point[0] + 1

        # 1. Direct Source Match
        src = match_javascript_source(node, file_path=self.file_path)
        if src:
            step = PropagationStep("source", src.name, line, f"read source {src.name}")
            return TaintValue(state=TaintState.TAINTED, sources=(src,), steps=(step,))

        # 2. Literals
        if node.type in {"number", "true", "false", "null", "undefined"}:
            return TaintValue(state=TaintState.STATIC)

        if node.type == "string":
            return TaintValue(state=TaintState.STATIC)

        if node.type == "template_string":
            if not any(c.type == "template_substitution" for c in node.children):
                return TaintValue(state=TaintState.STATIC)
            return self._evaluate_template_string(node, env, call_stack, depth)

        # 3. Identifier
        if node.type == "identifier":
            var_name = _node_text(node).strip()
            if var_name in env:
                return env[var_name]
            return TaintValue(state=TaintState.UNKNOWN)

        # 4. Binary Expression (+)
        if node.type == "binary_expression":
            op = _node_text(node.child_by_field_name("operator")).strip()
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op == "+":
                val_l = self._evaluate_node(left, env, call_stack, depth)
                val_r = self._evaluate_node(right, env, call_stack, depth)
                res_state = compose_states(val_l.state, val_r.state)
                sources = tuple(dict.fromkeys(val_l.sources + val_r.sources))
                sanitizers = tuple(dict.fromkeys(val_l.sanitizers + val_r.sanitizers))
                steps = val_l.steps + val_r.steps
                return TaintValue(state=res_state, sources=sources, sanitizers=sanitizers, steps=steps)

        # 5. Call Expression
        if node.type == "call_expression":
            return self._evaluate_call(node, env, call_stack, depth)

        # 6. Member / Subscript Expression
        if node.type in {"member_expression", "subscript_expression"}:
            obj = node.child_by_field_name("object")
            return self._evaluate_node(obj, env, call_stack, depth)

        return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

    def _evaluate_template_string(
        self,
        node: Any,
        env: Dict[str, TaintValue],
        call_stack: Set[str],
        depth: int,
    ) -> TaintValue:
        res_state = TaintState.STATIC
        sources: List[TaintSource] = []
        sanitizers: List[SanitizerPattern] = []
        steps: List[PropagationStep] = []

        for c in node.children:
            if c.type == "template_substitution":
                for sub in c.children:
                    if sub.type not in ("${", "}"):
                        sub_val = self._evaluate_node(sub, env, call_stack, depth)
                        res_state = compose_states(res_state, sub_val.state)
                        sources.extend(sub_val.sources)
                        sanitizers.extend(sub_val.sanitizers)
                        steps.extend(sub_val.steps)

        return TaintValue(
            state=res_state,
            sources=tuple(dict.fromkeys(sources)),
            sanitizers=tuple(dict.fromkeys(sanitizers)),
            steps=tuple(steps),
        )

    def _evaluate_call(
        self,
        call_node: Any,
        env: Dict[str, TaintValue],
        call_stack: Set[str],
        depth: int,
    ) -> TaintValue:
        line = call_node.start_point[0] + 1
        fn_node = call_node.child_by_field_name("function")
        target_name = _node_text(fn_node).strip()
        args_node = call_node.child_by_field_name("arguments")
        args = [c for c in args_node.children if c.type not in ("(", ")", ",")] if args_node else []

        # 1. Category Sanitizer Check (e.g. DOMPurify.sanitize, Number, parseInt)
        san = match_javascript_sanitizer(call_node)
        if san and args:
            arg_val = self._evaluate_node(args[0], env, call_stack, depth)
            step = PropagationStep("sanitizer", san.name, line, f"{san.name}(...) applied")
            if arg_val.state in {TaintState.TAINTED, TaintState.STATIC}:
                return TaintValue(
                    state=TaintState.SANITIZED,
                    sources=arg_val.sources,
                    sanitizers=arg_val.sanitizers + (san,),
                    steps=arg_val.steps + (step,),
                )
            return TaintValue(
                state=arg_val.state,
                sources=arg_val.sources,
                sanitizers=arg_val.sanitizers + (san,),
                steps=arg_val.steps + (step,),
            )

        # 2. String conversion pass-through: String(x)
        if target_name == "String" and args:
            return self._evaluate_node(args[0], env, call_stack, depth)

        # 3. Same-File Function Summary Resolution
        fn_leaf = target_name.split(".")[-1]
        if fn_leaf in self._duplicate_functions:
            return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

        summary = self.registry.lookup(fn_leaf)
        if not summary:
            if target_name.startswith("this.") and len(target_name.split(".")) == 2:
                summary = self.registry.lookup(target_name.split(".")[1])

        if summary:
            if fn_leaf in call_stack or depth >= MAX_CALL_DEPTH:
                return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

            if summary.returns_static:
                return TaintValue(state=TaintState.STATIC)

            if summary.returns_unverified_dynamic:
                return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

            new_stack = set(call_stack) | {fn_leaf}
            res_state = TaintState.STATIC
            sources = []
            sanitizers = []
            steps = []

            for dep in summary.return_dependencies:
                if dep.param_index < len(args):
                    arg_c = args[dep.param_index]
                    arg_val = self._evaluate_node(arg_c, env, new_stack, depth + 1)
                    if dep.sanitizer:
                        res_state = compose_states(res_state, TaintState.SANITIZED)
                        sanitizers.append(dep.sanitizer)
                    else:
                        res_state = compose_states(res_state, arg_val.state)
                    sources.extend(arg_val.sources)
                    sanitizers.extend(arg_val.sanitizers)
                    steps.extend(arg_val.steps)

            call_step = PropagationStep("return_value", fn_leaf, line, f"call {fn_leaf}(...)")
            steps.append(call_step)

            return TaintValue(
                state=res_state,
                sources=tuple(dict.fromkeys(sources)),
                sanitizers=tuple(dict.fromkeys(sanitizers)),
                steps=tuple(steps),
            )

        return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)
