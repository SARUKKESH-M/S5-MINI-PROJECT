"""CodeSentinel Bounded Intra-File Taint Analysis - Core Data Models and Lattice.

Frozen Specification: Phase 30C + Phase 30D-R.
Immutable dataclasses and deterministic state lattice operators.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class TaintState(str, Enum):
    """Discrete security state in the bounded taint analysis lattice."""
    STATIC = "STATIC"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"
    UNVERIFIED_DYNAMIC = "UNVERIFIED_DYNAMIC"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class TaintSource:
    """Provenance of an untrusted user-controlled input."""
    name: str
    category: str
    line: int
    file_path: str = ""
    ast_pattern: str = ""


@dataclass(frozen=True)
class TaintSink:
    """Security-sensitive operation that may trigger a vulnerability if fed untrusted input."""
    name: str
    category: str
    line: int
    file_path: str = ""
    target_arg_indices: Tuple[int, ...] = (0,)
    ast_pattern: str = ""


@dataclass(frozen=True)
class SanitizerPattern:
    """Category-bound transformation that neutralizes a specific vulnerability category."""
    name: str
    target_category: str
    is_numeric_cast: bool = False
    ast_pattern: str = ""


@dataclass(frozen=True)
class PropagationStep:
    """Deterministic step in a taint propagation path."""
    step_type: str
    symbol: str
    line: int
    detail: str


@dataclass(frozen=True)
class ReturnDependency:
    """Relationship between a function parameter and its return value."""
    param_index: int
    sanitizer: Optional[SanitizerPattern] = None


@dataclass(frozen=True)
class TaintValue:
    """Analyzed security state of a variable or AST expression node."""
    state: TaintState
    sources: Tuple[TaintSource, ...] = ()
    sanitizers: Tuple[SanitizerPattern, ...] = ()
    steps: Tuple[PropagationStep, ...] = ()


@dataclass(frozen=True)
class TaintTrace:
    """Complete end-to-end evidence trace from source to sink."""
    sink: TaintSink
    final_state: TaintState
    sources: Tuple[TaintSource, ...] = ()
    sanitizers: Tuple[SanitizerPattern, ...] = ()
    steps: Tuple[PropagationStep, ...] = ()
    trace_id: str = ""


@dataclass(frozen=True)
class FunctionSummary:
    """Bounded intra-file function transfer summary."""
    name: str
    class_name: Optional[str] = None
    param_names: Tuple[str, ...] = ()
    returns_static: bool = False
    return_dependencies: Tuple[ReturnDependency, ...] = ()
    returns_unverified_dynamic: bool = False
    direct_sinks: Tuple[TaintSink, ...] = ()
    fingerprint: str = ""


def compose_states(state_a: TaintState, state_b: TaintState) -> TaintState:
    """Composition operator (⊕) for combining expressions (e.g. string concatenation).

    Commutative: compose_states(a, b) == compose_states(b, a).
    UNKNOWN is NOT an identity element; STATIC + UNKNOWN -> UNVERIFIED_DYNAMIC.
    """
    # Normalize order by value to enforce commutativity
    if state_a.value > state_b.value:
        state_a, state_b = state_b, state_a

    pair = (state_a, state_b)

    # Identical pairs
    if state_a == state_b:
        return state_a

    # Any combination with TAINTED produces TAINTED (taint infects compound expressions)
    if TaintState.TAINTED in pair:
        return TaintState.TAINTED

    # SANITIZED combinations (without TAINTED)
    if pair == (TaintState.SANITIZED, TaintState.STATIC):
        return TaintState.SANITIZED
    if pair == (TaintState.SANITIZED, TaintState.UNKNOWN):
        return TaintState.UNVERIFIED_DYNAMIC
    if pair == (TaintState.SANITIZED, TaintState.UNVERIFIED_DYNAMIC):
        return TaintState.UNVERIFIED_DYNAMIC

    # STATIC combinations
    if pair == (TaintState.STATIC, TaintState.UNKNOWN):
        return TaintState.UNVERIFIED_DYNAMIC
    if pair == (TaintState.STATIC, TaintState.UNVERIFIED_DYNAMIC):
        return TaintState.UNVERIFIED_DYNAMIC

    # UNKNOWN with UNVERIFIED_DYNAMIC
    if pair == (TaintState.UNKNOWN, TaintState.UNVERIFIED_DYNAMIC):
        return TaintState.UNVERIFIED_DYNAMIC

    return TaintState.UNVERIFIED_DYNAMIC


def join_states(state_a: TaintState, state_b: TaintState) -> TaintState:
    """Control-flow join operator (⊔) for merging branch states (e.g. if/else).

    Commutative: join_states(a, b) == join_states(b, a).
    UNKNOWN is NOT an identity element; join(STATIC, UNKNOWN) -> UNVERIFIED_DYNAMIC.
    """
    # Normalize order by value to enforce commutativity
    if state_a.value > state_b.value:
        state_a, state_b = state_b, state_a

    # Identical states merge to that state
    if state_a == state_b:
        return state_a

    # Conflicting or unproven states collapse safely to UNVERIFIED_DYNAMIC
    return TaintState.UNVERIFIED_DYNAMIC
