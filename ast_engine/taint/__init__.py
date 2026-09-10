"""CodeSentinel Bounded Intra-File Taint Analysis Engine.

Frozen Specification: Phase 30C + Phase 30D-R.
Exports public models, lattice operators, and language-specific engines.
"""

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
from ast_engine.taint.engine import (
    MAX_CALL_DEPTH,
    build_argument_assessment,
    build_taint_trace,
    evaluate_value_against_sink,
    format_evidence_string,
)
from ast_engine.taint.python_engine import PythonTaintEngine
from ast_engine.taint.javascript_engine import JavaScriptTaintEngine

__all__ = [
    "TaintState",
    "TaintSource",
    "TaintSink",
    "SanitizerPattern",
    "PropagationStep",
    "ReturnDependency",
    "TaintValue",
    "TaintTrace",
    "FunctionSummary",
    "compose_states",
    "join_states",
    "MAX_CALL_DEPTH",
    "build_argument_assessment",
    "build_taint_trace",
    "evaluate_value_against_sink",
    "format_evidence_string",
    "PythonTaintEngine",
    "JavaScriptTaintEngine",
]
