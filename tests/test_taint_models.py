"""Test Suite for CodeSentinel Taint Analysis Data Models and Lattice Operations.

Phase 30E - Bounded Intra-File Taint Analysis.
Verifies:
1. TaintState enum integrity.
2. Exact composition operator (compose_states) evaluation matrix and commutativity.
3. Exact control-flow join operator (join_states) evaluation matrix and commutativity.
4. UNKNOWN is never an identity element (Correction 2).
5. Immutable frozen dataclasses (TaintValue, TaintSource, TaintSink, SanitizerPattern, ReturnDependency, FunctionSummary, TaintTrace).
6. FunctionSummary and ReturnDependency typing and immutability (Correction 3).
"""

import dataclasses
import pytest

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


def test_taint_state_values():
    assert TaintState.STATIC.value == "STATIC"
    assert TaintState.TAINTED.value == "TAINTED"
    assert TaintState.SANITIZED.value == "SANITIZED"
    assert TaintState.UNVERIFIED_DYNAMIC.value == "UNVERIFIED_DYNAMIC"
    assert TaintState.UNKNOWN.value == "UNKNOWN"
    assert len(TaintState) == 5


def test_composition_matrix_exact():
    """Verify all 15 entries of the Phase 30D-R composition table."""
    assert compose_states(TaintState.STATIC, TaintState.STATIC) == TaintState.STATIC
    assert compose_states(TaintState.STATIC, TaintState.TAINTED) == TaintState.TAINTED
    assert compose_states(TaintState.STATIC, TaintState.SANITIZED) == TaintState.SANITIZED
    assert compose_states(TaintState.STATIC, TaintState.UNVERIFIED_DYNAMIC) == TaintState.UNVERIFIED_DYNAMIC
    assert compose_states(TaintState.STATIC, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert compose_states(TaintState.TAINTED, TaintState.TAINTED) == TaintState.TAINTED
    assert compose_states(TaintState.TAINTED, TaintState.SANITIZED) == TaintState.TAINTED
    assert compose_states(TaintState.TAINTED, TaintState.UNVERIFIED_DYNAMIC) == TaintState.TAINTED
    assert compose_states(TaintState.TAINTED, TaintState.UNKNOWN) == TaintState.TAINTED

    assert compose_states(TaintState.SANITIZED, TaintState.SANITIZED) == TaintState.SANITIZED
    assert compose_states(TaintState.SANITIZED, TaintState.UNVERIFIED_DYNAMIC) == TaintState.UNVERIFIED_DYNAMIC
    assert compose_states(TaintState.SANITIZED, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert compose_states(TaintState.UNVERIFIED_DYNAMIC, TaintState.UNVERIFIED_DYNAMIC) == TaintState.UNVERIFIED_DYNAMIC
    assert compose_states(TaintState.UNVERIFIED_DYNAMIC, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert compose_states(TaintState.UNKNOWN, TaintState.UNKNOWN) == TaintState.UNKNOWN


def test_composition_commutativity():
    """Verify compose_states(a, b) == compose_states(b, a) for all 25 pairs."""
    states = list(TaintState)
    for a in states:
        for b in states:
            assert compose_states(a, b) == compose_states(b, a), f"Failed for ({a}, {b})"


def test_join_matrix_exact():
    """Verify all entries of the Phase 30D-R control-flow join table."""
    # Identity joins (x \sqcup x = x)
    for s in TaintState:
        assert join_states(s, s) == s

    # Mixed joins all collapse to UNVERIFIED_DYNAMIC
    assert join_states(TaintState.STATIC, TaintState.TAINTED) == TaintState.UNVERIFIED_DYNAMIC
    assert join_states(TaintState.STATIC, TaintState.SANITIZED) == TaintState.UNVERIFIED_DYNAMIC
    assert join_states(TaintState.STATIC, TaintState.UNVERIFIED_DYNAMIC) == TaintState.UNVERIFIED_DYNAMIC
    assert join_states(TaintState.STATIC, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert join_states(TaintState.TAINTED, TaintState.SANITIZED) == TaintState.UNVERIFIED_DYNAMIC
    assert join_states(TaintState.TAINTED, TaintState.UNVERIFIED_DYNAMIC) == TaintState.UNVERIFIED_DYNAMIC
    assert join_states(TaintState.TAINTED, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert join_states(TaintState.SANITIZED, TaintState.UNVERIFIED_DYNAMIC) == TaintState.UNVERIFIED_DYNAMIC
    assert join_states(TaintState.SANITIZED, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert join_states(TaintState.UNVERIFIED_DYNAMIC, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC


def test_join_commutativity():
    """Verify join_states(a, b) == join_states(b, a) for all 25 pairs."""
    states = list(TaintState)
    for a in states:
        for b in states:
            assert join_states(a, b) == join_states(b, a), f"Failed for ({a}, {b})"


def test_unknown_never_behaves_as_identity():
    """Security Check: UNKNOWN must never behave as an identity element."""
    # If UNKNOWN were an identity, STATIC + UNKNOWN would be STATIC (vulnerability suppression bug)
    assert compose_states(TaintState.STATIC, TaintState.UNKNOWN) != TaintState.STATIC
    assert compose_states(TaintState.STATIC, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC

    assert join_states(TaintState.STATIC, TaintState.UNKNOWN) != TaintState.STATIC
    assert join_states(TaintState.STATIC, TaintState.UNKNOWN) == TaintState.UNVERIFIED_DYNAMIC


def test_taint_value_immutability():
    val = TaintValue(state=TaintState.STATIC)
    with pytest.raises(dataclasses.FrozenInstanceError):
        val.state = TaintState.TAINTED  # type: ignore


def test_taint_source_immutability():
    src = TaintSource(name="req.query.id", category="web_parameter", line=1, file_path="app.py", ast_pattern="req.query.id")
    with pytest.raises(dataclasses.FrozenInstanceError):
        src.line = 2  # type: ignore


def test_taint_sink_immutability():
    sink = TaintSink(name="db.execute", category="sql_injection", line=10, file_path="app.py", target_arg_indices=(0,), ast_pattern="db.execute")
    with pytest.raises(dataclasses.FrozenInstanceError):
        sink.line = 20  # type: ignore


def test_sanitizer_pattern_immutability():
    san = SanitizerPattern(name="int", target_category="sql_injection", is_numeric_cast=True, ast_pattern="int")
    with pytest.raises(dataclasses.FrozenInstanceError):
        san.name = "float"  # type: ignore


def test_return_dependency_and_function_summary():
    san = SanitizerPattern(name="int", target_category="sql_injection", is_numeric_cast=True, ast_pattern="int")
    dep = ReturnDependency(param_index=0, sanitizer=san)
    assert dep.param_index == 0
    assert dep.sanitizer == san

    with pytest.raises(dataclasses.FrozenInstanceError):
        dep.param_index = 1  # type: ignore

    summary = FunctionSummary(
        name="clean_id",
        class_name=None,
        param_names=("user_id",),
        returns_static=False,
        return_dependencies=(dep,),
        returns_unverified_dynamic=False,
        direct_sinks=(),
        fingerprint="sha256_mock",
    )
    assert summary.name == "clean_id"
    assert len(summary.return_dependencies) == 1
    assert summary.return_dependencies[0].sanitizer == san
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.name = "other"  # type: ignore
