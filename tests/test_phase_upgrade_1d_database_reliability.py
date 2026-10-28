"""Test Suite for CodeSentinel Upgrade 1D — Database Connection Reliability.

Validates:
1. Deterministic connection closure on success and exceptions (file-backed).
2. Clean file and directory deletion on Windows without requiring manual gc.collect().
3. In-memory database compatibility (:memory: and URI-based memory).
4. Timeout consistency: PRAGMA busy_timeout returns 10000 ms.
5. Batch finding insertion: 0, 1, 50, and 250 findings via executemany with exact semantics.
6. Transaction atomicity: complete rollback on failure during save_analysis.
7. Persistence error handling and bounded retry for transient SQLite lock errors.
8. Concurrent PR commit reservation safety (BEGIN IMMEDIATE) and idempotency.
"""

import os
import shutil
import sqlite3
import tempfile
import threading
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from backend.analysis.storage.store import AnalysisStore, _DB_INIT_LOCK, _INITIALIZED_DATABASES
from backend.analysis.repository_orchestrator import _safely_persist_repository_analysis
from backend.analysis.orchestrator import _safely_persist_analysis


# =============================================================================
# 1. Connection Lifecycle & Windows File Descriptor Cleanup
# =============================================================================

def test_deterministic_connection_closure_success():
    """Verify file-backed connection closes immediately upon exiting with block on success."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_lifecycle.db")

    try:
        store = AnalysisStore(db_path=db_path)
        with store._get_connection() as conn:
            assert isinstance(conn, sqlite3.Connection)
            conn.execute("SELECT 1;")
            active_conn = conn

        # After exiting with block, active_conn must be closed
        with pytest.raises(sqlite3.ProgrammingError, match="Cannot operate on a closed database"):
            active_conn.execute("SELECT 1;")

    finally:
        # Crucial Windows check: Must delete cleanly WITHOUT gc.collect()!
        shutil.rmtree(temp_dir)
        assert not os.path.exists(temp_dir)


def test_deterministic_connection_closure_on_exception():
    """Verify file-backed connection closes immediately when an exception occurs."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_exc_lifecycle.db")

    try:
        store = AnalysisStore(db_path=db_path)
        active_conn = None
        with pytest.raises(RuntimeError, match="Injected operational failure"):
            with store._get_connection() as conn:
                active_conn = conn
                raise RuntimeError("Injected operational failure")

        assert active_conn is not None
        with pytest.raises(sqlite3.ProgrammingError, match="Cannot operate on a closed database"):
            active_conn.execute("SELECT 1;")

    finally:
        shutil.rmtree(temp_dir)
        assert not os.path.exists(temp_dir)


# =============================================================================
# 2. In-Memory Database Compatibility (:memory: and URI)
# =============================================================================

def test_in_memory_database_pure_memory_retention():
    """Verify that pure :memory: database preserves tables across multiple store calls."""
    store = AnalysisStore(db_path=":memory:")
    try:
        record = {
            "analysis_id": "mem_analysis_1",
            "status": "completed",
            "summary": {"total_findings": 0},
            "findings": [],
        }
        store.save_analysis(record)
        retrieved = store.get_analysis("mem_analysis_1")
        assert retrieved is not None
        assert retrieved["analysis_id"] == "mem_analysis_1"
        assert retrieved["status"] == "completed"
    finally:
        store.close()


def test_in_memory_database_uri_mode():
    """Verify that URI-based memory databases (file:mem?mode=memory&cache=shared) work cleanly."""
    uri_path = "file:upg1d_test_mem?mode=memory&cache=shared"
    store = AnalysisStore(db_path=uri_path)
    try:
        record = {
            "analysis_id": "uri_mem_analysis_1",
            "status": "completed",
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "finding_id": "f_1",
                    "title": "SQL Injection",
                    "description": "Raw query interpolation",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "CWE-89",
                    "evidence": [{"document_id": "app.py", "line_start": 42}],
                }
            ],
        }
        store.save_analysis(record)
        retrieved = store.get_analysis("uri_mem_analysis_1")
        assert retrieved is not None
        assert retrieved["finding_count"] == 1
        assert len(retrieved["findings"]) == 1
        assert retrieved["findings"][0]["title"] == "SQL Injection"
    finally:
        store.close()


# =============================================================================
# 3. Timeout Consistency: PRAGMA busy_timeout = 10000
# =============================================================================

def test_busy_timeout_aligned_to_10_seconds():
    """Verify that sqlite3 connection has PRAGMA busy_timeout configured to 10,000 ms."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_timeout.db")

    try:
        store = AnalysisStore(db_path=db_path)
        with store._get_connection() as conn:
            timeout_ms = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
            assert int(timeout_ms) == 10000, f"Expected busy_timeout 10000ms, got {timeout_ms}ms"

    finally:
        shutil.rmtree(temp_dir)


# =============================================================================
# 4. Batch Finding Insertion: 0, 1, 50, 250 findings via executemany
# =============================================================================

@pytest.mark.parametrize("finding_count", [0, 1, 50, 250])
def test_batch_finding_insertion_scales_correctly(finding_count: int):
    """Verify that save_analysis preserves all fields, evidence JSON, and counts for varying finding counts."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, f"test_batch_{finding_count}.db")

    try:
        store = AnalysisStore(db_path=db_path)
        test_findings = [
            {
                "finding_id": f"batch_f_{i}",
                "title": f"Vulnerability {i}",
                "description": f"Detailed description for issue {i}",
                "severity": "high" if i % 2 == 0 else "medium",
                "confidence": "high",
                "category": f"CWE-{100 + i}",
                "evidence": [{"document_id": f"src/mod_{i}.py", "line_start": i * 10}],
            }
            for i in range(1, finding_count + 1)
        ]

        analysis_payload = {
            "analysis_id": f"analysis_batch_{finding_count}",
            "status": "completed",
            "summary": {"total_findings": finding_count, "test_batch": True},
            "findings": test_findings,
            "repository": {"owner": "testorg", "repository": "testrepo"},
            "review_status": "allow" if finding_count == 0 else "block",
        }

        saved = store.save_analysis(analysis_payload)
        assert saved["analysis_id"] == f"analysis_batch_{finding_count}"

        retrieved = store.get_analysis(f"analysis_batch_{finding_count}")
        assert retrieved is not None
        assert retrieved["finding_count"] == finding_count
        assert len(retrieved["findings"]) == finding_count

        if finding_count > 0:
            finding_map = {f["finding_id"]: f for f in retrieved["findings"]}
            assert f"batch_f_1" in finding_map
            first_f = finding_map["batch_f_1"]
            assert first_f["title"] == "Vulnerability 1"
            assert isinstance(first_f["evidence"], list)
            assert first_f["evidence"][0]["document_id"] == "src/mod_1.py"

            assert f"batch_f_{finding_count}" in finding_map
            last_f = finding_map[f"batch_f_{finding_count}"]
            assert last_f["title"] == f"Vulnerability {finding_count}"
            assert last_f["evidence"][0]["line_start"] == finding_count * 10

    finally:
        shutil.rmtree(temp_dir)


# =============================================================================
# 5. Transaction Atomicity: Complete Rollback on Save Failure
# =============================================================================

def test_save_analysis_rolls_back_atomically_on_failure():
    """Verify that an error during save_analysis rolls back both analyses and findings."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_rollback.db")

    try:
        store = AnalysisStore(db_path=db_path)

        # Baseline: Save a valid initial analysis
        initial = {
            "analysis_id": "atomic_target",
            "status": "completed",
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "finding_id": "initial_f1",
                    "title": "Initial",
                    "description": "Initial desc",
                    "severity": "low",
                    "confidence": "high",
                    "category": "CWE-20",
                    "evidence": [],
                }
            ],
        }
        store.save_analysis(initial)

        attempt_payload = {
            "analysis_id": "atomic_target",
            "status": "completed",
            "summary": {"total_findings": 1},
            "findings": [
                {
                    "finding_id": "corrupt_f1",
                    "title": "Corrupt",
                    "description": "Corrupt desc",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "CWE-89",
                    "evidence": [],
                }
            ],
        }

        # Install a SQLite abort trigger that fails when inserting corrupt finding
        with store._get_connection() as conn:
            conn.execute(
                "CREATE TRIGGER abort_corrupt_finding BEFORE INSERT ON findings WHEN NEW.finding_id = 'corrupt_f1' "
                "BEGIN SELECT RAISE(ABORT, 'injected transaction abort'); END;"
            )

        with pytest.raises(sqlite3.IntegrityError, match="injected transaction abort"):
            store.save_analysis(attempt_payload)

        # Verify atomic rollback: previous analysis state must be preserved
        rechecked = store.get_analysis("atomic_target")
        assert rechecked is not None
        assert rechecked["finding_count"] == 1
        assert rechecked["findings"][0]["finding_id"] == "initial_f1"

    finally:
        shutil.rmtree(temp_dir)


# =============================================================================
# 6. Persistence Error Handling & Transient Lock Retries
# =============================================================================

def test_safely_persist_repository_analysis_retries_transient_lock(caplog):
    """Verify _safely_persist_repository_analysis retries on transient lock and logs warning."""
    import logging
    caplog.set_level(logging.WARNING)

    report_payload = {
        "analysis_id": "retry_repo_analysis",
        "status": "completed",
        "summary": {"total_findings": 0},
        "findings": [],
        "repository": {"repository": "repo-retry"},
        "review_status": "allow",
    }

    call_count = 0
    original_save = AnalysisStore.save_analysis

    def flakey_save(self, record):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise sqlite3.OperationalError("database is locked")
        return original_save(self, record)

    with patch.object(AnalysisStore, "save_analysis", flakey_save):
        success = _safely_persist_repository_analysis(
            report_payload,
            db_path=":memory:",
            max_retries=2,
            base_backoff_sec=0.01,
        )

    assert success is True
    assert call_count == 2
    assert "Transient SQLite lock persisting analysis retry_repo_analysis" in caplog.text


def test_safely_persist_repository_analysis_aborts_on_permanent_error(caplog):
    """Verify _safely_persist_repository_analysis does not retry on permanent error and logs error."""
    import logging
    caplog.set_level(logging.ERROR)

    report_payload = {
        "analysis_id": "perm_repo_analysis",
        "status": "completed",
        "summary": {},
        "findings": [],
    }

    call_count = 0

    def fail_save(self, record):
        nonlocal call_count
        call_count += 1
        raise sqlite3.IntegrityError("CHECK constraint failed")

    with patch.object(AnalysisStore, "save_analysis", fail_save):
        success = _safely_persist_repository_analysis(
            report_payload,
            db_path=":memory:",
            max_retries=2,
            base_backoff_sec=0.01,
        )

    assert success is False
    assert call_count == 1  # No retries on permanent integrity error
    assert "Unexpected error persisting repository analysis perm_repo_analysis" in caplog.text


def test_safely_persist_analysis_retries_transient_lock(caplog):
    """Verify _safely_persist_analysis (single-file) retries on transient lock and logs warning."""
    import logging
    caplog.set_level(logging.WARNING)

    result_payload = {
        "analysis_id": "single_retry_analysis",
        "status": "completed",
        "summary": {},
        "findings": [],
    }

    call_count = 0
    original_save = AnalysisStore.save_analysis

    def flakey_save(self, record):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise sqlite3.OperationalError("database table is busy")
        return original_save(self, record)

    with patch.object(AnalysisStore, "save_analysis", flakey_save):
        success = _safely_persist_analysis(
            result_payload,
            db_path=":memory:",
            max_retries=2,
            base_backoff_sec=0.01,
        )

    assert success is True
    assert call_count == 2
    assert "Transient SQLite lock persisting analysis single_retry_analysis" in caplog.text


# =============================================================================
# 7. Concurrent Reservation Safety (BEGIN IMMEDIATE) & Idempotency
# =============================================================================

def test_concurrent_pr_commit_reservations_begin_immediate():
    """Verify concurrent workers competing for the same PR commit resolve deterministically without deadlock."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_concurrent_res.db")

    try:
        # Pre-initialize store
        _ = AnalysisStore(db_path=db_path)

        results = []
        errors = []

        valid_40_sha = "1234567890abcdef1234567890abcdef12345678"

        def worker(worker_id: int):
            try:
                store = AnalysisStore(db_path=db_path)
                acquired, reason, analysis_id = store.reserve_pr_commit_analysis(
                    owner="testowner",
                    repository="testrepo",
                    pr_number=101,
                    head_sha=valid_40_sha,
                    ttl_seconds=60,
                )
                results.append((worker_id, acquired, reason))
            except Exception as e:
                errors.append((worker_id, type(e).__name__, str(e)))

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Zero deadlocks or unhandled exceptions
        assert len(errors) == 0, f"Concurrent reservation errors: {errors}"
        assert len(results) == 6

        # Exactly ONE worker must have acquired the reservation ('reserved')
        acquisitions = [r for r in results if r[1] is True and r[2] == "reserved"]
        assert len(acquisitions) == 1, f"Expected exactly 1 reservation winner, got: {acquisitions}"

        # All other 5 contenders must have received 'in_progress'
        losses = [r for r in results if r[1] is False and r[2] == "in_progress"]
        assert len(losses) == 5

    finally:
        shutil.rmtree(temp_dir)


class _MockConnWrapper:
    def __init__(self, real_conn, fail_mode=None):
        self._real = real_conn
        self._fail_mode = fail_mode

    def execute(self, sql, *args, **kwargs):
        if str(sql).strip().upper() == "BEGIN IMMEDIATE;":
            if self._fail_mode == "lock":
                raise sqlite3.OperationalError("database is locked")
            elif self._fail_mode == "active":
                raise sqlite3.OperationalError("cannot start a transaction within a transaction")
            elif self._fail_mode == "io":
                raise sqlite3.OperationalError("disk I/O error")
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_begin_immediate_lock_returns_in_progress():
    """Verify that a database lock during BEGIN IMMEDIATE returns (False, 'in_progress', None)."""
    from contextlib import contextmanager
    store = AnalysisStore(db_path=":memory:")
    valid_40_sha = "abcdef1234567890abcdef1234567890abcdef12"

    orig_get_conn = store._get_connection

    @contextmanager
    def mock_get_conn():
        with orig_get_conn() as real_conn:
            yield _MockConnWrapper(real_conn, fail_mode="lock")

    store._get_connection = mock_get_conn
    acquired, reason, analysis_id = store.reserve_pr_commit_analysis(
        owner="testowner",
        repository="testrepo",
        pr_number=102,
        head_sha=valid_40_sha,
    )

    assert acquired is False
    assert reason == "in_progress"
    assert analysis_id is None


def test_begin_immediate_already_in_transaction_passes():
    """Verify that 'cannot start a transaction' passes and allows reservation to succeed."""
    from contextlib import contextmanager
    store = AnalysisStore(db_path=":memory:")
    valid_40_sha = "abcdef1234567890abcdef1234567890abcdef13"

    orig_get_conn = store._get_connection

    @contextmanager
    def mock_get_conn():
        with orig_get_conn() as real_conn:
            yield _MockConnWrapper(real_conn, fail_mode="active")

    store._get_connection = mock_get_conn
    acquired, reason, analysis_id = store.reserve_pr_commit_analysis(
        owner="testowner",
        repository="testrepo",
        pr_number=103,
        head_sha=valid_40_sha,
    )

    assert acquired is True
    assert reason == "reserved"


def test_begin_immediate_unexpected_error_reraised():
    """Verify that unexpected sqlite3.OperationalError during BEGIN IMMEDIATE is re-raised."""
    from contextlib import contextmanager
    store = AnalysisStore(db_path=":memory:")
    valid_40_sha = "abcdef1234567890abcdef1234567890abcdef14"

    orig_get_conn = store._get_connection

    @contextmanager
    def mock_get_conn():
        with orig_get_conn() as real_conn:
            yield _MockConnWrapper(real_conn, fail_mode="io")

    store._get_connection = mock_get_conn
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        store.reserve_pr_commit_analysis(
            owner="testowner",
            repository="testrepo",
            pr_number=104,
            head_sha=valid_40_sha,
        )


def test_persistence_logging_does_not_leak_raw_exception_or_path(caplog):
    """Verify warning and error logs do not contain raw exception strings, database paths, or queries."""
    import logging
    caplog.set_level(logging.DEBUG)

    sensitive_leak_token = "SECRET_DB_PATH_USER_CREDENTIAL"
    report_payload = {
        "analysis_id": "leak_test_analysis",
        "status": "completed",
        "summary": {},
        "findings": [],
    }

    # Simulate error containing sensitive path token
    def leak_save(self, record):
        raise sqlite3.OperationalError(f"unable to open database file: /home/admin/{sensitive_leak_token}/db.sqlite")

    with patch.object(AnalysisStore, "save_analysis", leak_save):
        success = _safely_persist_repository_analysis(
            report_payload,
            db_path=":memory:",
            max_retries=1,
            base_backoff_sec=0.01,
        )

    assert success is False
    # Log must contain the safe error summary with exception class name
    assert "Failed to persist repository analysis leak_test_analysis due to SQLite operational error (OperationalError)" in caplog.text
    # Log MUST NOT contain the sensitive path token or raw error text
    assert sensitive_leak_token not in caplog.text
    assert "/home/admin" not in caplog.text

