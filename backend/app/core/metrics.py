"""
CodeSentinel — Step 6T-8: Observability & Structured Internal Metrics

Provides structured, secret-safe metric aggregation for platform observability.
Tracks request counts, analysis outcomes, security gate decisions, and cache statistics.
"""

import threading
from typing import Any, Dict


class MetricsCollector:
    """Thread-safe, secret-sanitized structured metrics collector for CodeSentinel."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters = {
            "analysis_requests_total": 0,
            "analysis_success_total": 0,
            "analysis_failed_total": 0,
            "decisions_allow_total": 0,
            "decisions_review_total": 0,
            "decisions_block_total": 0,
            "cache_hits_total": 0,
            "cache_misses_total": 0,
            "health_checks_total": 0
        }
        self._last_analysis_duration_ms: float = 0.0

    def increment(self, metric_name: str, count: int = 1) -> None:
        """Increments a counter metric by name."""
        with self._lock:
            if metric_name in self._counters:
                self._counters[metric_name] += max(0, count)

    def record_duration(self, duration_ms: float) -> None:
        """Records the duration of the last security analysis run in milliseconds."""
        with self._lock:
            self._last_analysis_duration_ms = round(max(0.0, float(duration_ms)), 2)

    def record_decision(self, decision: str) -> None:
        """Records a security gate decision outcome."""
        dec_clean = str(decision).upper() if decision else ""
        with self._lock:
            if dec_clean == "ALLOW":
                self._counters["decisions_allow_total"] += 1
            elif dec_clean == "REVIEW":
                self._counters["decisions_review_total"] += 1
            elif dec_clean == "BLOCK":
                self._counters["decisions_block_total"] += 1

    def get_summary(self) -> Dict[str, Any]:
        """Returns snapshot of current metrics summary."""
        with self._lock:
            summary = dict(self._counters)
            summary["last_analysis_duration_ms"] = self._last_analysis_duration_ms
            return summary

    def reset(self) -> None:
        """Resets metric counters (used for test isolation)."""
        with self._lock:
            for k in self._counters:
                self._counters[k] = 0
            self._last_analysis_duration_ms = 0.0


# Global metrics collector instance singleton
metrics_collector = MetricsCollector()
