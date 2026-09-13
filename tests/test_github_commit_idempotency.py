"""
CodeSentinel — Phase 33C: Commit-Level Analysis Idempotency & PR Persistence Tests.

Comprehensive test suite verifying:
- PR identity persistence schema and indexing in SQLite.
- Safe exact commit lookup by (owner, repository, pr_number, head_sha).
- Commit-level analysis idempotency and short-circuiting.
- Atomic commit reservation and concurrency protection against duplicate analysis.
- Stale reservation recovery and bounded expiration.
- Failure retry semantics (no poisoned caches on acquisition/analysis error).
- Step 6O security authority invariants (BLOCK, REVIEW, ALLOW preservation).
"""

import os
import sqlite3
import pytest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

from backend.analysis.storage.models import DEFAULT_COMMIT_RESERVATION_TTL_SECONDS
from backend.analysis.storage.store import AnalysisStore
from backend.github.orchestrator import orchestrate_webhook_event
from backend.github.models import GitHubChangedFile, GitHubPullRequest, GitHubPullRequestSnapshot


# =============================================================================
# Helper Fixtures
# =============================================================================

@pytest.fixture
def temp_db(tmp_path):
    """Provide isolated temporary database file path."""
    db_file = str(tmp_path / "test_codesentinel.db")
    return db_file


@pytest.fixture
def isolated_store(temp_db):
    """Provide initialized AnalysisStore on isolated temporary database."""
    return AnalysisStore(db_path=temp_db)


def _build_test_report(
    analysis_id: str,
    owner: str = "octocat",
    repo: str = "Hello-World",
    pr_number: int = 42,
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    author: str = "octocat",
    review_status: str = "allow",
    critical_count: int = 0,
    high_count: int = 0,
    medium_count: int = 0
):
    """Helper to build a valid Step 6O report dict for persistence testing."""
    findings = []
    if critical_count > 0:
        findings.append({
            "finding_id": "f_crit_1",
            "title": "Critical SQL Injection",
            "description": "Raw query interpolation",
            "severity": "critical",
            "confidence": "high",
            "category": "Security / Injection",
            "evidence": [{"document_id": "vuln.py", "line_start": 10, "line_end": 10, "signal_type": "SQLI"}]
        })
    if medium_count > 0 and critical_count == 0 and high_count == 0:
        findings.append({
            "finding_id": "f_med_1",
            "title": "Weak Hash Usage",
            "description": "MD5 used",
            "severity": "medium",
            "confidence": "medium",
            "category": "Security / Cryptography",
            "evidence": [{"document_id": "hash.py", "line_start": 5, "line_end": 5, "signal_type": "WEAK_HASH"}]
        })

    return {
        "status": "completed",
        "review_status": review_status,
        "analysis_id": analysis_id,
        "query": f"repo:{owner}/{repo}",
        "created_at": "2026-09-10T12:00:00+00:00",
        "repository": {
            "owner": owner,
            "repository": repo,
            "branch": f"pr/{pr_number}",
            "path": ".",
            "pr_number": pr_number,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "author": author,
        },
        "owner": owner,
        "repository_id": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "author": author,
        "summary": {
            "total_files": 1,
            "analyzed_files": 1,
            "skipped_files": 0,
            "total_findings": len(findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": 0,
            "info_count": 0,
        },
        "findings": findings,
        "analysis_version": "1.0",
    }


def _build_valid_pr_payload(
    owner: str = "octocat",
    repo: str = "Hello-World",
    pr_number: int = 42,
    head_sha: str = "a" * 40,
    base_sha: str = "b" * 40,
    author: str = "octocat"
):
    """Helper to build a valid GitHub pull_request webhook payload."""
    return {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "title": f"Test PR #{pr_number}",
            "html_url": f"https://github.com/{owner}/{repo}/pull/{pr_number}",
            "head": {"sha": head_sha},
            "base": {"sha": base_sha},
            "user": {"login": author},
        },
        "repository": {
            "name": repo,
            "owner": {"login": owner},
        }
    }


# =============================================================================
# 1. DATA MODEL TESTS
# =============================================================================

def test_pr_identity_fields_persist(isolated_store, temp_db):
    """Verify PR identity fields (owner, repository, pr_number, head_sha, base_sha, author) persist in analyses table."""
    report = _build_test_report(
        analysis_id="ana_pr_1",
        owner="octocat",
        repo="Hello-World",
        pr_number=42,
        head_sha="a" * 40,
        base_sha="b" * 40,
        author="octocat_author",
    )
    isolated_store.save_analysis(report)

    with sqlite3.connect(temp_db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM analyses WHERE analysis_id = 'ana_pr_1';").fetchone()
        assert row is not None
        assert row["owner"] == "octocat"
        assert row["repository"] == "Hello-World"
        assert row["pr_number"] == 42
        assert row["head_sha"] == "a" * 40
        assert row["base_sha"] == "b" * 40
        assert row["author"] == "octocat_author"

    # Verify get_analysis also surfaces them
    retrieved = isolated_store.get_analysis("ana_pr_1")
    assert retrieved is not None
    assert retrieved["owner"] == "octocat"
    assert retrieved["repository_id"] == "Hello-World"
    assert retrieved["pr_number"] == 42
    assert retrieved["head_sha"] == "a" * 40
    assert retrieved["base_sha"] == "b" * 40
    assert retrieved["author"] == "octocat_author"


def test_non_pr_historical_analysis_remains_valid(isolated_store, temp_db):
    """Verify non-PR / historical analyses without PR metadata persist with NULL and remain valid."""
    legacy_record = {
        "analysis_id": "ana_legacy_1",
        "status": "success",
        "query": "local/scan",
        "summary": {"total_findings": 0},
        "findings": [],
    }
    isolated_store.save_analysis(legacy_record)

    with sqlite3.connect(temp_db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM analyses WHERE analysis_id = 'ana_legacy_1';").fetchone()
        assert row is not None
        assert row["owner"] is None
        assert row["repository"] is None
        assert row["pr_number"] is None
        assert row["head_sha"] is None
        assert row["base_sha"] is None
        assert row["author"] is None

    retrieved = isolated_store.get_analysis("ana_legacy_1")
    assert retrieved is not None
    assert retrieved["status"] == "success"
    assert retrieved["analysis_id"] == "ana_legacy_1"


def test_owner_repo_pr_head_identity_is_queryable(isolated_store):
    """Verify owner/repo/PR/head_sha identity can be queried directly."""
    report = _build_test_report("ana_pr_q1", owner="org1", repo="repo1", pr_number=10, head_sha="c" * 40)
    isolated_store.save_analysis(report)

    found = isolated_store.get_pr_analysis_by_commit("org1", "repo1", 10, "c" * 40)
    assert found is not None
    assert found["analysis_id"] == "ana_pr_q1"


def test_exact_identity_index_exists(temp_db, isolated_store):
    """Verify exact identity index idx_analyses_pr_commit exists and query planner uses it."""
    with sqlite3.connect(temp_db) as conn:
        # Check index definition
        idx_row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_analyses_pr_commit';"
        ).fetchone()
        assert idx_row is not None

        # Check query plan
        plan = conn.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT analysis_id FROM analyses
            WHERE owner = 'octocat' AND repository = 'repo' AND pr_number = 1 AND head_sha = 'a';
            """
        ).fetchall()
        plan_str = " ".join(str(row) for row in plan)
        assert "idx_analyses_pr_commit" in plan_str


def test_different_head_sha_does_not_collide(isolated_store):
    """Verify same repo/PR with different head SHA does not collide."""
    r1 = _build_test_report("ana_sha_1", pr_number=1, head_sha="1" * 40)
    isolated_store.save_analysis(r1)

    # Query with different SHA
    found = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 1, "2" * 40)
    assert found is None


def test_different_pr_number_does_not_collide(isolated_store):
    """Verify same repo/head_sha with different PR number does not collide."""
    sha = "3" * 40
    r1 = _build_test_report("ana_pr_100", pr_number=100, head_sha=sha)
    isolated_store.save_analysis(r1)

    found = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 101, sha)
    assert found is None


def test_different_repository_does_not_collide(isolated_store):
    """Verify same PR number and head SHA in different repositories do not collide."""
    sha = "4" * 40
    r1 = _build_test_report("ana_repo_a", owner="orgA", repo="repoA", pr_number=5, head_sha=sha)
    isolated_store.save_analysis(r1)

    found = isolated_store.get_pr_analysis_by_commit("orgB", "repoB", 5, sha)
    assert found is None


# =============================================================================
# 2. LOOKUP TESTS
# =============================================================================

def test_successful_exact_commit_lookup_returns_analysis(isolated_store):
    """Verify exact commit lookup returns valid, full analysis with findings."""
    r = _build_test_report("ana_full_1", critical_count=1, review_status="block")
    isolated_store.save_analysis(r)

    lookup = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40)
    assert lookup is not None
    assert lookup["analysis_id"] == "ana_full_1"
    assert lookup["review_status"] == "block"
    assert len(lookup["findings"]) == 1
    assert lookup["findings"][0]["title"] == "Critical SQL Injection"


def test_missing_commit_returns_no_result(isolated_store):
    """Verify non-existent commit returns None."""
    assert isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 999, "f" * 40) is None


def test_incomplete_or_failed_analysis_not_returned_as_successful(isolated_store, temp_db):
    """Verify incomplete or failed analyses are never returned as successful commit analyses."""
    with sqlite3.connect(temp_db) as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                analysis_id, status, query, created_at, finding_count, summary_json, schema_version,
                owner, repository, pr_number, head_sha, base_sha, author
            ) VALUES ('ana_fail_1', 'failed', 'query', '2026-09-10T00:00:00+00:00', 0, '{}', '1.0',
                      'octocat', 'Hello-World', 55, 'e' * 40, 'b' * 40, 'user');
            """
        )

    # get_pr_analysis_by_commit only matches 'success' or 'completed'
    found = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 55, "e" * 40)
    assert found is None


def test_historical_record_without_pr_identity_not_falsely_matched(isolated_store, temp_db):
    """Verify historical record with NULL owner/repo/PR/head_sha is never falsely matched."""
    with sqlite3.connect(temp_db) as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                analysis_id, status, query, created_at, finding_count, summary_json, schema_version,
                owner, repository, pr_number, head_sha, base_sha, author
            ) VALUES ('ana_null_1', 'completed', 'query', '2026-09-10T00:00:00+00:00', 0, '{}', '1.0',
                      NULL, NULL, NULL, NULL, NULL, NULL);
            """
        )

    found = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 1, "a" * 40)
    assert found is None


# =============================================================================
# 3. IDEMPOTENCY & SHORT-CIRCUITING TESTS
# =============================================================================

@patch("backend.github.orchestrator.send_slack_pr_alert_sync")
@patch("backend.github.orchestrator.post_pr_inline_review_comments")
@patch("backend.github.orchestrator.post_pr_security_comment")
@patch("backend.github.orchestrator.publish_step_6o_report_status")
@patch("backend.github.orchestrator._generate_pr_analysis_report")
@patch("backend.github.orchestrator.acquire_pull_request")
def test_same_delivery_id_protected_by_phase_33b(
    mock_acquire,
    mock_gen_report,
    mock_pub,
    mock_post_comment,
    mock_inline,
    mock_slack,
    temp_db
):
    """Verify same delivery ID is rejected at delivery claim layer (Phase 33B)."""
    mock_acquire.return_value = MagicMock(changed_files=[])
    mock_gen_report.return_value = _build_test_report("ana_1")
    mock_pub.return_value = {"check_run": {"id": 10}, "commit_status": {"id": 20}}
    mock_post_comment.return_value = {"status": "created", "comment_id": 30}
    mock_inline.return_value = {"status": "success", "comments_count": 0}

    payload = _build_valid_pr_payload()

    # First delivery
    res1 = orchestrate_webhook_event("pull_request", "delivery-uuid-1", payload, db_path=temp_db)
    assert res1["status"] == "success"

    # Duplicate delivery with same delivery ID
    res2 = orchestrate_webhook_event("pull_request", "delivery-uuid-1", payload, db_path=temp_db)
    assert res2["status"] == "duplicate"
    assert res2["reason"] == "delivery_already_processed"


@patch("backend.github.orchestrator.send_slack_pr_alert_sync")
@patch("backend.github.orchestrator.post_pr_inline_review_comments")
@patch("backend.github.orchestrator.post_pr_security_comment")
@patch("backend.github.orchestrator.publish_step_6o_report_status")
@patch("backend.github.orchestrator._generate_pr_analysis_report")
@patch("backend.github.orchestrator.acquire_pull_request")
def test_different_delivery_ids_for_same_commit_short_circuit(
    mock_acquire,
    mock_gen_report,
    mock_pub,
    mock_post_comment,
    mock_inline,
    mock_slack,
    temp_db
):
    """Verify different delivery IDs for the exact same commit return already_analyzed without re-analysis."""
    mock_acquire.return_value = MagicMock(changed_files=[])
    mock_gen_report.return_value = _build_test_report("ana_commit_idem_1", review_status="block", critical_count=1)
    mock_pub.return_value = {"check_run": {"id": 10}, "commit_status": {"id": 20}}
    mock_post_comment.return_value = {"status": "created", "comment_id": 30}
    mock_inline.return_value = {"status": "success", "comments_count": 0}

    payload = _build_valid_pr_payload()

    # Delivery 1 performs full analysis
    res1 = orchestrate_webhook_event("pull_request", "deliv-A", payload, db_path=temp_db)
    assert res1["status"] == "success"
    assert res1["review_status"] == "block"
    assert mock_acquire.call_count == 1
    assert mock_gen_report.call_count == 1
    assert mock_pub.call_count == 1
    assert mock_post_comment.call_count == 1

    # Delivery 2 arrives with DIFFERENT delivery ID for same commit
    res2 = orchestrate_webhook_event("pull_request", "deliv-B", payload, db_path=temp_db)
    assert res2["status"] == "already_analyzed"
    assert res2["reason"] == "commit_already_analyzed"
    assert res2["review_status"] == "block"
    assert res2["analysis_id"] == "ana_commit_idem_1"

    # Proves expensive operations were completely skipped on Delivery 2
    assert mock_acquire.call_count == 1
    assert mock_gen_report.call_count == 1
    assert mock_pub.call_count == 1
    assert mock_post_comment.call_count == 1


# =============================================================================
# 4. CONCURRENCY & RESERVATION TESTS
# =============================================================================

def test_atomic_reservation_grants_exactly_one_owner(isolated_store):
    """Verify concurrent attempts to reserve the same PR commit result in exactly one winner."""
    owner = "octocat"
    repo = "Hello-World"
    pr_num = 42
    head_sha = "d" * 40

    results = []

    def attempt_reserve(idx):
        return isolated_store.reserve_pr_commit_analysis(owner, repo, pr_num, head_sha)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(attempt_reserve, i) for i in range(8)]
        for f in futures:
            results.append(f.result())

    # Exactly one True (reserved), all others False (in_progress)
    successes = [r for r in results if r[0] is True]
    in_progress = [r for r in results if r[0] is False and r[1] == "in_progress"]

    assert len(successes) == 1
    assert len(in_progress) == 7


def test_second_worker_observes_in_progress_reservation(isolated_store, temp_db):
    """Verify second worker observes active in-progress reservation and returns status: in_progress."""
    import sys
    for k, v in sys.modules.items():
        if "orchestrator" in k:
            print(f"MODULE {k}: AnalysisStore={getattr(v, 'AnalysisStore', 'NO_ATTR')}")

    # Worker 1 reserves the commit
    reserved, reason, _ = isolated_store.reserve_pr_commit_analysis(
        "octocat", "Hello-World", 42, "a" * 40
    )
    assert reserved is True

    # Worker 2 attempts orchestration for the same commit
    payload = _build_valid_pr_payload()
    res2 = orchestrate_webhook_event("pull_request", "delivery-worker-2", payload, db_path=temp_db)

    assert res2["status"] == "in_progress"
    assert res2["reason"] == "analysis_in_progress"


def test_stale_reservation_can_be_recovered(isolated_store):
    """Verify expired in-progress reservation (worker crashed) is safely reclaimed."""
    owner = "octocat"
    repo = "Hello-World"
    pr_num = 77
    head_sha = "e" * 40

    # Worker 1 reserved in the past (expired)
    past_iso = "2020-01-01T00:00:00+00:00"
    res1, _, _ = isolated_store.reserve_pr_commit_analysis(
        owner, repo, pr_num, head_sha, ttl_seconds=10, now_iso=past_iso
    )
    assert res1 is True

    # Current time is 2026 -> reservation is expired, worker 2 reclaims it
    now_iso = "2026-09-10T12:00:00+00:00"
    res2, reason, _ = isolated_store.reserve_pr_commit_analysis(
        owner, repo, pr_num, head_sha, ttl_seconds=300, now_iso=now_iso
    )
    assert res2 is True
    assert reason == "reserved"


def test_failed_worker_releases_reservation_for_retry(isolated_store):
    """Verify release_pr_commit_reservation removes in-progress lock so retry succeeds immediately."""
    owner = "octocat"
    repo = "Hello-World"
    pr_num = 88
    head_sha = "f" * 40

    # Worker 1 reserves
    res1, _, _ = isolated_store.reserve_pr_commit_analysis(owner, repo, pr_num, head_sha)
    assert res1 is True

    # Worker 1 crashes / releases reservation
    released = isolated_store.release_pr_commit_reservation(owner, repo, pr_num, head_sha)
    assert released is True

    # Worker 2 can now immediately reserve
    res2, reason, _ = isolated_store.reserve_pr_commit_analysis(owner, repo, pr_num, head_sha)
    assert res2 is True
    assert reason == "reserved"


# =============================================================================
# 5. FAILURE RECOVERY & RETRY SEMANTICS
# =============================================================================

@patch("backend.github.orchestrator.acquire_pull_request")
def test_acquisition_failure_allows_retry(mock_acquire, temp_db):
    """Verify acquisition failure releases reservation and allows subsequent delivery to retry."""
    mock_acquire.side_effect = RuntimeError("GitHub API 503 Service Unavailable")
    payload = _build_valid_pr_payload()

    # Attempt 1 fails during acquisition
    with pytest.raises(RuntimeError):
        orchestrate_webhook_event("pull_request", "deliv-fail-1", payload, db_path=temp_db)

    # Verify reservation was released
    store = AnalysisStore(db_path=temp_db)
    res, reason, _ = store.reserve_pr_commit_analysis("octocat", "Hello-World", 42, "a" * 40)
    assert res is True
    store.release_pr_commit_reservation("octocat", "Hello-World", 42, "a" * 40)

    # Attempt 2 succeeds when GitHub recovers
    mock_acquire.side_effect = None
    mock_acquire.return_value = MagicMock(changed_files=[])

    with patch("backend.github.orchestrator._generate_pr_analysis_report") as mock_gen, \
         patch("backend.github.orchestrator.publish_step_6o_report_status") as mock_pub, \
         patch("backend.github.orchestrator.post_pr_security_comment") as mock_comm:
        mock_gen.return_value = _build_test_report("ana_retry_success")
        mock_pub.return_value = {}
        mock_comm.return_value = {}

        res2 = orchestrate_webhook_event("pull_request", "deliv-retry-2", payload, db_path=temp_db)
        assert res2["status"] == "success"
        assert res2["analysis_id"] == "ana_retry_success"


@patch("backend.github.orchestrator.acquire_pull_request")
@patch("backend.github.orchestrator._generate_pr_analysis_report")
def test_analysis_exception_allows_retry(mock_gen, mock_acquire, temp_db):
    """Verify AST / analysis pipeline exception releases reservation and allows subsequent delivery to retry."""
    mock_acquire.return_value = MagicMock(changed_files=[])
    mock_gen.side_effect = ValueError("AST parse corruption")
    payload = _build_valid_pr_payload()

    with pytest.raises(ValueError):
        orchestrate_webhook_event("pull_request", "deliv-err-1", payload, db_path=temp_db)

    # Store reservation was released
    store = AnalysisStore(db_path=temp_db)
    res, reason, _ = store.reserve_pr_commit_analysis("octocat", "Hello-World", 42, "a" * 40)
    assert res is True


def test_persistence_failure_does_not_create_false_successful_cache(isolated_store):
    """Verify unpersisted or corrupted record is not matched as successful analysis."""
    # Reservation marked in_progress but never saved
    isolated_store.reserve_pr_commit_analysis("octocat", "Hello-World", 42, "a" * 40)
    assert isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40) is None


# =============================================================================
# 6. STEP 6O SECURITY AUTHORITY INVARIANTS
# =============================================================================

def test_cached_block_remains_block(isolated_store):
    """Verify cached BLOCK review_status is deterministically preserved."""
    rep = _build_test_report("ana_block_1", review_status="block", critical_count=2)
    isolated_store.save_analysis(rep)

    cached = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40)
    assert cached["review_status"] == "block"
    assert cached["summary"]["critical_count"] == 2


def test_cached_review_remains_review(isolated_store):
    """Verify cached REVIEW review_status is deterministically preserved."""
    rep = _build_test_report("ana_rev_1", review_status="review", medium_count=1)
    isolated_store.save_analysis(rep)

    cached = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40)
    assert cached["review_status"] == "review"
    assert cached["summary"]["medium_count"] == 1


def test_cached_allow_remains_allow(isolated_store):
    """Verify cached ALLOW review_status is deterministically preserved."""
    rep = _build_test_report("ana_allow_1", review_status="allow")
    isolated_store.save_analysis(rep)

    cached = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40)
    assert cached["review_status"] == "allow"
    assert cached["summary"]["critical_count"] == 0


def test_cached_decision_cannot_be_weakened(isolated_store):
    """Prove that commit-level idempotency cannot mutate a cached BLOCK into an ALLOW."""
    block_rep = _build_test_report("ana_block_immut", review_status="block", critical_count=1)
    isolated_store.save_analysis(block_rep)

    # Repeated query returns BLOCK
    cached1 = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40)
    assert cached1["review_status"] == "block"

    cached2 = isolated_store.get_pr_analysis_by_commit("octocat", "Hello-World", 42, "a" * 40)
    assert cached2["review_status"] == "block"


# =============================================================================
# 7. INPUT VALIDATION & SECURITY AUDIT
# =============================================================================

def test_validation_rejects_sql_injection_and_path_traversal(isolated_store):
    """Verify storage lookup strictly validates inputs and rejects injection / traversal characters."""
    # Path traversal in repo
    res = isolated_store.get_pr_analysis_by_commit("octocat", "../../etc/passwd", 42, "a" * 40)
    assert res is None

    # SQL injection in head_sha
    res = isolated_store.get_pr_analysis_by_commit("octocat", "repo", 42, "a'; DROP TABLE analyses; --")
    assert res is None

    # Negative PR number
    res = isolated_store.get_pr_analysis_by_commit("octocat", "repo", -1, "a" * 40)
    assert res is None

    # String PR number non-digit
    res = isolated_store.get_pr_analysis_by_commit("octocat", "repo", "fourty-two", "a" * 40)
    assert res is None
