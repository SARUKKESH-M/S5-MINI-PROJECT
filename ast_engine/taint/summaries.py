"""Function Summary Data Structures and Memoized Extraction Engine.

Frozen Specification: Phase 30C + Phase 30D-R.
Computes compact, bounded function summaries for intra-file call resolution.
"""

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple
from ast_engine.taint.models import FunctionSummary, ReturnDependency, SanitizerPattern, TaintSink


MAX_SUMMARIZED_FUNCTIONS_PER_FILE = 50


def compute_node_fingerprint(node: Any) -> str:
    """Compute deterministic SHA-256 fingerprint of an AST node's bytes."""
    node_bytes = node.text if isinstance(node.text, bytes) else str(node.text or "").encode("utf-8")
    return hashlib.sha256(node_bytes).hexdigest()


class SummaryRegistry:
    """Intra-run memoized cache of function summaries for a single file analysis."""

    def __init__(self, file_path: str = ""):
        self.file_path = file_path
        self._summaries: Dict[str, FunctionSummary] = {}
        self._analyzed_count = 0

    def register(self, summary: FunctionSummary) -> None:
        if self._analyzed_count < MAX_SUMMARIZED_FUNCTIONS_PER_FILE:
            self._summaries[summary.name] = summary
            self._analyzed_count += 1

    def lookup(self, name: str) -> Optional[FunctionSummary]:
        return self._summaries.get(name)

    def has(self, name: str) -> bool:
        return name in self._summaries

    @property
    def all_summaries(self) -> Dict[str, FunctionSummary]:
        return dict(self._summaries)
