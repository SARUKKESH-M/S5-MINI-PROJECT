"""Tree-sitter Python AST Taint Analysis Visitor and Propagation Engine.

Frozen Specification: Phase 30C + Phase 30D-R.
Performs intra-function and intra-file cross-function dataflow analysis.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from ast_engine.taint.engine import (
    MAX_CALL_DEPTH,
    build_taint_trace,
    evaluate_value_against_sink,
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
from ast_engine.taint.sanitizers import match_python_sanitizer
from ast_engine.taint.sinks import match_python_sink
from ast_engine.taint.sources import match_python_source
from ast_engine.taint.summaries import SummaryRegistry, compute_node_fingerprint


def _node_text(node: Optional[Any]) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8") if isinstance(node.text, bytes) else str(node.text or "")


class PythonTaintEngine:
    """Bounded intra-file taint analysis engine for Python."""

    def __init__(self, root_node: Any, file_path: str = ""):
        self.root_node = root_node
        self.file_path = file_path
        self.registry = SummaryRegistry(file_path=file_path)
        self._function_nodes: Dict[str, Any] = {}
        self._duplicate_functions: Set[str] = set()

        self._index_functions()
        self._build_summaries()

    def _index_functions(self) -> None:
        """Scan top-level and class methods to index unambiguous function names."""
        def walk(n: Any, current_class: Optional[str] = None) -> None:
            if n.type == "class_definition":
                c_name = _node_text(n.child_by_field_name("name")) or None
                body = n.child_by_field_name("body")
                if body:
                    for child in body.children:
                        walk(child, current_class=c_name)
                return

            if n.type in {"function_definition", "async_function_definition"}:
                f_name = _node_text(n.child_by_field_name("name")).strip()
                if f_name:
                    if f_name in self._function_nodes:
                        self._duplicate_functions.add(f_name)
                    else:
                        self._function_nodes[f_name] = (n, current_class)

                    # Also index method under Class.method if inside class
                    if current_class:
                        fqn = f"{current_class}.{f_name}"
                        self._function_nodes[fqn] = (n, current_class)
                return

            for child in n.children:
                walk(child, current_class=current_class)

        walk(self.root_node)

    def _build_summaries(self) -> None:
        """Compute FunctionSummary for all unambiguously indexed functions."""
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
        """Extract input-to-return transfer dependencies for a single function."""
        params_node = fn_node.child_by_field_name("parameters")
        param_names: List[str] = []
        if params_node:
            for c in params_node.children:
                if c.type == "identifier":
                    param_names.append(_node_text(c).strip())
                elif c.type in {"default_parameter", "typed_parameter", "typed_default_parameter"}:
                    p_name = c.child_by_field_name("name")
                    if p_name:
                        param_names.append(_node_text(p_name).strip())

        # Discard self / cls from parameter index mapping if method
        analyzed_params = [p for p in param_names if p not in {"self", "cls"}]
        param_index_map = {p: idx for idx, p in enumerate(analyzed_params)}

        body = fn_node.child_by_field_name("body")
        if not body:
            return FunctionSummary(
                name=name,
                class_name=current_class,
                param_names=tuple(analyzed_params),
                returns_static=True,
                return_dependencies=(),
                returns_unverified_dynamic=False,
                direct_sinks=(),
                fingerprint=compute_node_fingerprint(fn_node),
            )

        return_nodes: List[Any] = []
        direct_sinks: List[TaintSink] = []

        def scan_body(n: Any) -> None:
            if n.type == "return_statement":
                return_nodes.append(n)
            elif n.type == "call":
                sink = match_python_sink(n, file_path=self.file_path)
                if sink:
                    direct_sinks.append(sink)
            for child in n.children:
                if child.type not in {"function_definition", "async_function_definition", "class_definition"}:
                    scan_body(child)

        scan_body(body)

        if not return_nodes:
            return FunctionSummary(
                name=name,
                class_name=current_class,
                param_names=tuple(analyzed_params),
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
            expr = ret.children[1] if len(ret.children) > 1 else None
            if expr is None:
                continue

            # Check if static literal
            if expr.type in {"string", "concatenated_string", "integer", "float", "true", "false", "none"}:
                if "{" not in _node_text(expr):
                    continue
                else:
                    returns_static = False

            returns_static = False

            # Check if identifier matching parameter
            if expr.type == "identifier":
                ident_name = _node_text(expr).strip()
                if ident_name in param_index_map:
                    return_deps.append(ReturnDependency(param_index=param_index_map[ident_name], sanitizer=None))
                else:
                    returns_unverified_dynamic = True

            # Check if call to sanitizer
            elif expr.type == "call":
                san = match_python_sanitizer(expr)
                args = expr.child_by_field_name("arguments")
                arg_children = [c for c in args.children if c.type not in ("(", ")", ",")] if args else []
                if san and arg_children and arg_children[0].type == "identifier":
                    arg_name = _node_text(arg_children[0]).strip()
                    if arg_name in param_index_map:
                        return_deps.append(ReturnDependency(param_index=param_index_map[arg_name], sanitizer=san))
                    else:
                        returns_unverified_dynamic = True
                else:
                    # Check if call to another helper
                    call_fn = expr.child_by_field_name("function")
                    helper_name = _node_text(call_fn).strip().split(".")[-1]
                    if helper_name in self._function_nodes and helper_name not in self._duplicate_functions:
                        # Depends on arguments passed to helper
                        for idx_arg, arg_c in enumerate(arg_children):
                            if arg_c.type == "identifier" and _node_text(arg_c).strip() in param_index_map:
                                return_deps.append(ReturnDependency(param_index=param_index_map[_node_text(arg_c).strip()], sanitizer=None))
                    else:
                        returns_unverified_dynamic = True

            # Check binary operator (e.g. "SELECT " + param)
            elif expr.type == "binary_operator":
                leaves = self._collect_binary_leaves(expr)
                for leaf in leaves:
                    if leaf.type == "identifier":
                        leaf_name = _node_text(leaf).strip()
                        if leaf_name in param_index_map:
                            return_deps.append(ReturnDependency(param_index=param_index_map[leaf_name], sanitizer=None))
                        else:
                            returns_unverified_dynamic = True
            else:
                returns_unverified_dynamic = True

        return FunctionSummary(
            name=name,
            class_name=current_class,
            param_names=tuple(analyzed_params),
            returns_static=returns_static and not return_deps and not returns_unverified_dynamic,
            return_dependencies=tuple(return_deps),
            returns_unverified_dynamic=returns_unverified_dynamic,
            direct_sinks=tuple(direct_sinks),
            fingerprint=compute_node_fingerprint(fn_node),
        )

    def _collect_binary_leaves(self, node: Any) -> List[Any]:
        leaves: List[Any] = []
        def _walk(n: Any) -> None:
            if n.type == "binary_operator":
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
        call_node: Any,
        arg_node: Any,
        local_scope_node: Optional[Any] = None,
        designated_params: Optional[Set[str]] = None,
    ) -> Optional[TaintTrace]:
        """Evaluate whether a sink's sensitive argument is TAINTED, SANITIZED, or STATIC.

        Returns an immutable TaintTrace with deterministic evidence if evaluated.
        """
        sink = match_python_sink(call_node, file_path=self.file_path)
        if not sink:
            return None

        # Build local environment up to call_node
        scope = local_scope_node or self._find_enclosing_function(call_node) or self.root_node
        local_env = self._build_local_environment(
            scope,
            up_to_node=call_node,
            designated_params=designated_params or set(),
        )

        val = self._evaluate_node(arg_node, local_env, call_stack=set(), depth=0)
        return build_taint_trace(sink, val, file_path=self.file_path)

    def _find_enclosing_function(self, node: Any) -> Optional[Any]:
        curr = node.parent
        while curr:
            if curr.type in {"function_definition", "async_function_definition"}:
                return curr
            curr = curr.parent
        return None

    def _build_local_environment(
        self,
        scope_node: Any,
        up_to_node: Optional[Any] = None,
        designated_params: Optional[Set[str]] = None,
    ) -> Dict[str, TaintValue]:
        """Build mapping of variable_name -> TaintValue strictly preceding up_to_node."""
        env: Dict[str, TaintValue] = {}
        active_designated = designated_params or set()

        # Initialize parameters
        if scope_node.type in {"function_definition", "async_function_definition"}:
            params_node = scope_node.child_by_field_name("parameters")
            if params_node:
                for c in params_node.children:
                    p_name = ""
                    if c.type == "identifier":
                        p_name = _node_text(c).strip()
                    elif c.type in {"default_parameter", "typed_parameter", "typed_default_parameter"}:
                        sub_name = c.child_by_field_name("name")
                        if sub_name:
                            p_name = _node_text(sub_name).strip()
                    if p_name and p_name not in {"self", "cls"}:
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

        # Sequential traversal of statements in scope_node body
        body = scope_node.child_by_field_name("body") if scope_node.type in {"function_definition", "async_function_definition"} else scope_node
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
        """Process linear statements, sequential assignments, and branch joins."""
        for child in block_node.children:
            if up_to_node is not None and child.start_byte >= up_to_node.start_byte:
                break

            # Handle assignment statements
            if child.type == "expression_statement":
                for c in child.children:
                    if c.type == "assignment":
                        self._process_assignment(c, env)
            elif child.type == "assignment":
                self._process_assignment(child, env)

            # Handle branches (if_statement)
            elif child.type == "if_statement":
                self._process_branch(child, env, up_to_node)

            # Handle loops (for_statement, while_statement) - one traversal
            elif child.type in {"for_statement", "while_statement"}:
                self._process_loop(child, env, up_to_node)

    def _process_assignment(self, assign_node: Any, env: Dict[str, TaintValue]) -> None:
        left = assign_node.child_by_field_name("left")
        right = assign_node.child_by_field_name("right")
        if left is None or right is None:
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
        """Merge variable states across branches using control-flow join operator (⊔)."""
        consequence = if_node.child_by_field_name("consequence")
        alternative = if_node.child_by_field_name("alternative")

        # Snapshot pre-branch environment
        env_before = dict(env)

        env_a = dict(env_before)
        if consequence:
            self._process_statement_block(consequence, env_a, up_to_node)

        env_b = dict(env_before)
        if alternative:
            # alternative child might be an 'else_clause' or another 'if_statement' (elif)
            alt_body = alternative.child_by_field_name("body") or alternative
            self._process_statement_block(alt_body, env_b, up_to_node)

        # Merge variables modified in either branch
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
        """One-pass traversal of loop body. Self-referential or dynamic updates collapse to UNVERIFIED_DYNAMIC."""
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
        """Recursively evaluate the TaintValue of an AST expression node."""
        if node is None:
            return TaintValue(state=TaintState.UNKNOWN)

        line = node.start_point[0] + 1

        # 1. Direct Source Match
        src = match_python_source(node, file_path=self.file_path)
        if src:
            step = PropagationStep("source", src.name, line, f"read source {src.name}")
            return TaintValue(state=TaintState.TAINTED, sources=(src,), steps=(step,))

        # 2. String, Integer, Float, Boolean Literals
        if node.type in {"integer", "float", "true", "false", "none"}:
            return TaintValue(state=TaintState.STATIC)

        if node.type in {"string", "concatenated_string"}:
            raw_text = _node_text(node)
            # If standard string literal without formatting substitutions
            if "{" not in raw_text:
                return TaintValue(state=TaintState.STATIC)
            # F-string containing interpolated expressions
            return self._evaluate_f_string(node, env, call_stack, depth)

        # 3. Identifier
        if node.type == "identifier":
            var_name = _node_text(node).strip()
            if var_name in env:
                return env[var_name]
            return TaintValue(state=TaintState.UNKNOWN)

        # 4. Binary Operator (+)
        if node.type == "binary_operator":
            op = _node_text(node.child_by_field_name("operator"))
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

            elif op == "%":
                # String percent formatting: "..." % var
                val_l = self._evaluate_node(left, env, call_stack, depth)
                val_r = self._evaluate_node(right, env, call_stack, depth)
                res_state = compose_states(val_l.state, val_r.state)
                sources = tuple(dict.fromkeys(val_l.sources + val_r.sources))
                sanitizers = tuple(dict.fromkeys(val_l.sanitizers + val_r.sanitizers))
                steps = val_l.steps + val_r.steps
                return TaintValue(state=res_state, sources=sources, sanitizers=sanitizers, steps=steps)

        # 5. Function Call Expression
        if node.type == "call":
            return self._evaluate_call(node, env, call_stack, depth)

        # 6. Subscript / Attribute
        if node.type == "subscript":
            val_expr = node.child_by_field_name("value")
            return self._evaluate_node(val_expr, env, call_stack, depth)

        if node.type == "attribute":
            obj_expr = node.child_by_field_name("object")
            return self._evaluate_node(obj_expr, env, call_stack, depth)

        return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

    def _evaluate_f_string(
        self,
        node: Any,
        env: Dict[str, TaintValue],
        call_stack: Set[str],
        depth: int,
    ) -> TaintValue:
        """Evaluate expressions inside a Python f-string node."""
        res_state = TaintState.STATIC
        sources: List[TaintSource] = []
        sanitizers: List[SanitizerPattern] = []
        steps: List[PropagationStep] = []

        for child in node.children:
            if child.type == "interpolation":
                for sub in child.children:
                    if sub.type not in ("{", "}"):
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
        """Evaluate a call node against category sanitizers or same-file function summaries."""
        line = call_node.start_point[0] + 1
        fn_node = call_node.child_by_field_name("function")
        target_name = _node_text(fn_node).strip()
        args_node = call_node.child_by_field_name("arguments")
        args = [c for c in args_node.children if c.type not in ("(", ")", ",")] if args_node else []

        # 1. Check Category Sanitizer Pattern (e.g. shlex.quote, int, html.escape)
        san = match_python_sanitizer(call_node)
        if san and args:
            arg_val = self._evaluate_node(args[0], env, call_stack, depth)
            step = PropagationStep("sanitizer", san.name, line, f"{san.name}(...) applied")
            # If the argument is TAINTED, it carries the sanitizer pattern
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

        # 2. String conversion pass-through (str, bytes)
        if target_name in {"str", "bytes"} and args:
            return self._evaluate_node(args[0], env, call_stack, depth)

        # 3. String .format(...) call
        if target_name.endswith(".format"):
            # Combine receiver string with argument expressions
            rec_obj = fn_node.child_by_field_name("object") if fn_node.type == "attribute" else None
            rec_val = self._evaluate_node(rec_obj, env, call_stack, depth)
            res_state = rec_val.state
            sources = list(rec_val.sources)
            sanitizers = list(rec_val.sanitizers)
            steps = list(rec_val.steps)

            for a in args:
                a_val = self._evaluate_node(a, env, call_stack, depth)
                res_state = compose_states(res_state, a_val.state)
                sources.extend(a_val.sources)
                sanitizers.extend(a_val.sanitizers)
                steps.extend(a_val.steps)

            return TaintValue(
                state=res_state,
                sources=tuple(dict.fromkeys(sources)),
                sanitizers=tuple(dict.fromkeys(sanitizers)),
                steps=tuple(steps),
            )

        # 3. Same-File Function Summary Resolution
        fn_leaf = target_name.split(".")[-1]
        if fn_leaf in self._duplicate_functions:
            return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

        summary = self.registry.lookup(fn_leaf)
        if not summary:
            # Check if method on self
            if target_name.startswith("self.") and len(target_name.split(".")) == 2:
                summary = self.registry.lookup(target_name.split(".")[1])

        if summary:
            # Cycle and depth checks
            if fn_leaf in call_stack or depth >= MAX_CALL_DEPTH:
                return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

            if summary.returns_static:
                return TaintValue(state=TaintState.STATIC)

            if summary.returns_unverified_dynamic:
                return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)

            # Evaluate caller arguments against return dependencies
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
                        # Helper sanitized this parameter
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

        # Unresolved external function call
        return TaintValue(state=TaintState.UNVERIFIED_DYNAMIC)
