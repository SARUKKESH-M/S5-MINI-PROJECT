"""CodeSentinel Bounded Intra-File Taint Analysis - Base Coordination Engine.

Frozen Specification: Phase 30C + Phase 30D-R.
Handles category-aware sink evaluation, evidence string synthesis, and deterministic trace generation.
"""

import hashlib
from typing import Any, Dict, List, Optional
from ast_engine.taint.models import (
    TaintSink,
    TaintSource,
    TaintState,
    TaintTrace,
    TaintValue,
)

MAX_CALL_DEPTH = 3


def evaluate_value_against_sink(value: TaintValue, sink: TaintSink) -> TaintState:
    """Evaluate a TaintValue against an explicit sink category.

    Sanitizer matching is strictly category-bound.
    If value is tainted and has a matching category sanitizer, it evaluates to SANITIZED.
    If value has mismatched sanitizers, it remains TAINTED.
    """
    if value.state == TaintState.STATIC:
        return TaintState.STATIC

    # Check if an approved sanitizer matching the sink category was applied
    has_matching_sanitizer = any(
        s.target_category == sink.category for s in value.sanitizers
    )

    if has_matching_sanitizer:
        return TaintState.SANITIZED

    if value.state == TaintState.TAINTED:
        return TaintState.TAINTED

    if value.state == TaintState.SANITIZED:
        # Was sanitized for a different category, but tainted source remains unsafe for this sink
        if value.sources:
            return TaintState.TAINTED
        return TaintState.UNVERIFIED_DYNAMIC

    if value.state == TaintState.UNVERIFIED_DYNAMIC:
        return TaintState.UNVERIFIED_DYNAMIC

    return TaintState.UNKNOWN


def format_evidence_string(
    sink: TaintSink,
    sources: List[TaintSource],
    steps: List[Any],
) -> str:
    """Synthesize deterministic evidence string capped at 240 characters.

    Format:
    [Taint Flow] Source: <source> (line X) -> Flow: <step1> -> <step2> -> Sink: <sink> (line Y)
    """
    source_desc = f"{sources[0].name} (line {sources[0].line})" if sources else "unknown source"
    sink_desc = f"{sink.name} (line {sink.line})"

    if steps:
        flow_parts = [step.detail for step in steps]
        flow_str = " -> ".join(flow_parts)
        raw_evidence = f"[Taint Flow] Source: {source_desc} -> Flow: {flow_str} -> Sink: {sink_desc}"
    else:
        raw_evidence = f"[Taint Flow] Source: {source_desc} -> Sink: {sink_desc}"

    clean = raw_evidence.strip().replace("\r\n", " ").replace("\n", " ")
    if len(clean) > 240:
        clean = clean[:237] + "..."
    return clean


def build_taint_trace(
    sink: TaintSink,
    value: TaintValue,
    file_path: str = "",
) -> TaintTrace:
    """Construct an immutable TaintTrace with deterministic SHA-256 fingerprint."""
    final_state = evaluate_value_against_sink(value, sink)
    evidence_str = format_evidence_string(sink, list(value.sources), list(value.steps))

    stable_input = "|".join((
        file_path,
        str(sink.line),
        sink.category,
        sink.name,
        final_state.value,
        evidence_str,
    ))
    trace_id = hashlib.sha256(stable_input.encode("utf-8")).hexdigest()

    return TaintTrace(
        sink=sink,
        final_state=final_state,
        sources=value.sources,
        sanitizers=value.sanitizers,
        steps=value.steps,
        trace_id=trace_id,
    )


def build_argument_assessment(
    trace: TaintTrace,
    sanitizer_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Build Phase 31 compatible structured argument assessment metadata."""
    is_tainted = trace.final_state == TaintState.TAINTED
    is_sanitized = trace.final_state == TaintState.SANITIZED
    primary_source = trace.sources[0] if trace.sources else None

    return {
        "taint_flow_detected": is_tainted or is_sanitized,
        "taint_state": trace.final_state.value,
        "taint_source": primary_source.name if primary_source else None,
        "taint_source_line": primary_source.line if primary_source else None,
        "propagation_path": [step.detail for step in trace.steps],
        "is_sanitized": is_sanitized,
        "sanitizer_name": sanitizer_name,
        "trace_fingerprint": trace.trace_id,
    }
