"""Persistent Storage Engine for CodeSentinel Analysis Results.

Uses local persistent SQLite database (`backend/data/codesentinel.db`) with tables:
  - `analyses`: Stores analysis metadata, status, query, UTC creation timestamp, and summary.
  - `findings`: Stores individual findings linked to `analysis_id` with foreign key CASCADE.

Provides idempotent saving, single retrieval, paginated listing, findings retrieval,
and cascade deletion.
"""

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple
from backend.analysis.storage.models import (
    ANALYSIS_SCHEMA_VERSION,
    DEFAULT_COMMIT_RESERVATION_TTL_SECONDS,
    DEFAULT_DELIVERY_TTL_SECONDS,
    DEFAULT_TIME_WINDOW,
    VALID_REASON_CODES,
    VALID_TIME_WINDOWS,
    UserRecord,
    UserRole,
    UserStatus,
    create_analysis_record,
    create_suppression_record,
    get_utc_now_iso,
    normalize_email,
    parse_time_window,
    sanitize_finding_record,
    validate_reason_payload,
    validate_utc_iso_timestamp,
)


def _validate_pr_identity(owner: Any, repository: Any, pr_number: Any, head_sha: Any) -> Tuple[str, str, int, str]:
    """Validate PR identity parameters using existing GitHub validators without module-level circular imports."""
    try:
        from backend.github.validator import (
            validate_webhook_owner,
            validate_webhook_repo,
            validate_pr_number,
            validate_commit_sha,
        )
    except ImportError:
        try:
            from github.validator import (
                validate_webhook_owner,
                validate_webhook_repo,
                validate_pr_number,
                validate_commit_sha,
            )
        except ImportError:
            import re
            _UNSAFE = re.compile(r"[\x00;&|$\`<>\"\']")
            _OWNER_REPO = re.compile(r"^[a-zA-Z0-9_.-]+$")
            _COMMIT = re.compile(r"^[a-fA-F0-9]{40}$")
            owner_s = str(owner).strip()
            repo_s = str(repository).strip()
            if repo_s.lower().endswith(".git"):
                repo_s = repo_s[:-4]
            if _UNSAFE.search(owner_s) or ".." in owner_s or "/" in owner_s or "\\" in owner_s or not _OWNER_REPO.match(owner_s):
                raise ValueError("Invalid owner")
            if _UNSAFE.search(repo_s) or ".." in repo_s or "/" in repo_s or "\\" in repo_s or not _OWNER_REPO.match(repo_s):
                raise ValueError("Invalid repo")
            if isinstance(pr_number, bool):
                raise ValueError("PR number cannot be a boolean")
            pr_val = int(str(pr_number).strip())
            if pr_val <= 0 or pr_val > 1_000_000_000:
                raise ValueError("Invalid PR")
            sha_s = str(head_sha).strip().lower()
            if not _COMMIT.match(sha_s):
                raise ValueError("Invalid SHA")
            return owner_s, repo_s, pr_val, sha_s

    clean_owner = validate_webhook_owner(str(owner))
    clean_repo = validate_webhook_repo(str(repository))
    clean_pr = validate_pr_number(pr_number)
    clean_head = validate_commit_sha(str(head_sha))
    return clean_owner, clean_repo, clean_pr, clean_head


def _validate_optional_sha(sha: Any) -> Optional[str]:
    """Validates an optional commit SHA string."""
    if not sha:
        return None
    try:
        try:
            from backend.github.validator import validate_commit_sha
        except ImportError:
            from github.validator import validate_commit_sha
        return validate_commit_sha(str(sha))
    except Exception:
        return None


def compute_finding_fingerprint(
    repository_id: str,
    rule_signal: str,
    cwe_id: Optional[str],
    file_path: str,
) -> str:
    """Compute legacy (v1) deterministic, repository-scoped finding fingerprint."""
    norm_repo = str(repository_id or "default").strip().lower()
    norm_rule = str(rule_signal or "unknown").strip().lower()
    norm_cwe = str(cwe_id or "").strip().lower()
    norm_path = str(file_path or "").strip().replace("\\", "/").lower()
    payload = f"{norm_repo}:{norm_rule}:{norm_cwe}:{norm_path}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def compute_finding_fingerprint_v2(
    repository_id: str,
    finding: Dict[str, Any],
) -> str:
    """Compute granular, line-resilient v2 finding fingerprint with occurrence discriminator.

    Canonical hash input:
        norm_repo:norm_path:norm_rule:norm_cwe:norm_scope:norm_sink_name:structural_discriminator
    """
    if not isinstance(finding, dict):
        return ""

    norm_repo = str(repository_id or "default").strip().lower()

    evidence = finding.get("evidence", [])
    ev = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) else {}

    raw_path = finding.get("file_path") or ev.get("document_id") or "unknown"
    norm_path = str(raw_path).strip().replace("\\", "/")
    # If path contains a line suffix like "path/to/file.py:123", strip the line number
    if ":" in norm_path:
        base_part, suffix = norm_path.rsplit(":", 1)
        if suffix.isdigit():
            norm_path = base_part
    norm_path = norm_path.lower()

    raw_rule = ev.get("signal_type") or finding.get("category") or "unknown"
    norm_rule = str(raw_rule).strip().lower()

    raw_cwe = finding.get("category") or ""
    norm_cwe = str(raw_cwe).strip().lower()

    # Scope resolution: function/method/class or module
    raw_scope = (
        finding.get("scope")
        or finding.get("function_name")
        or ev.get("scope")
        or ev.get("function_name")
        or "<module>"
    )
    norm_scope = str(raw_scope).strip() or "<module>"

    # Sink identifier: sink_name, call_name, or signal_name
    raw_sink = (
        ev.get("sink_name")
        or ev.get("signal_name")
        or ev.get("call_name")
        or finding.get("sink_name")
        or finding.get("call_name")
        or "unknown"
    )
    norm_sink_name = str(raw_sink).strip() or "unknown"

    # Structural discriminator: occurrence index within enclosing scope
    # Defaults to 0 if not provided
    occ = finding.get("occurrence_index")
    if occ is None:
        occ = ev.get("occurrence_index", 0)
    try:
        structural_discriminator = int(occ)
    except (ValueError, TypeError):
        structural_discriminator = 0

    canonical_input = f"{norm_repo}:{norm_path}:{norm_rule}:{norm_cwe}:{norm_scope}:{norm_sink_name}:{structural_discriminator}"
    return hashlib.sha256(canonical_input.encode("utf-8")).hexdigest()[:32]


def is_suppression_active(status: str, expires_at: Optional[str]) -> bool:
    """Evaluate whether a suppression record is currently active (derived expiration).

    Never persists EXPIRED in SQLite.
    Fails closed: malformed or past expires_at returns False.
    """
    if str(status).upper() != "ACTIVE":
        return False
    if not expires_at:
        return True

    try:
        from datetime import datetime, timezone
        clean_exp = str(expires_at).strip().replace("Z", "+00:00")
        exp_dt = datetime.fromisoformat(clean_exp)
        if exp_dt.tzinfo is None:
            return False
        exp_utc = exp_dt.astimezone(timezone.utc)
        now_utc = datetime.now(timezone.utc)
        return now_utc < exp_utc
    except Exception:
        return False


def get_default_db_path() -> str:
    """Return default persistent SQLite database file path."""
    custom_path = os.environ.get("CODESENTINEL_DB_PATH")
    if custom_path:
        os.makedirs(os.path.dirname(os.path.abspath(custom_path)), exist_ok=True)
        return os.path.abspath(custom_path)
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    data_dir = os.path.join(backend_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "codesentinel.db")


_DB_INIT_LOCK = threading.Lock()
_INITIALIZED_DATABASES: Dict[str, float] = {}


def reset_database_initialization_cache() -> None:
    """Reset the database initialization cache (useful for isolated tests)."""
    with _DB_INIT_LOCK:
        _INITIALIZED_DATABASES.clear()


class AnalysisStore:
    """Storage manager for saving and retrieving security analysis records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_default_db_path()
        self.initialize()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection with foreign keys and WAL enabled."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        if self.db_path != ":memory:":
            try:
                conn.execute("PRAGMA synchronous = NORMAL;")
            except sqlite3.OperationalError:
                pass
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self, force: bool = False) -> None:
        """Initialize database directory, tables, indexes, and additive schema columns.

        Guarded so that schema DDL and migrations execute once per process per database identity,
        while safely re-initializing if a database file was deleted or recreated.
        """
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        is_memory = self.db_path == ":memory:"
        norm_path = ":memory:" if is_memory else os.path.normcase(os.path.abspath(self.db_path))

        if not force and not is_memory:
            with _DB_INIT_LOCK:
                if os.path.exists(norm_path):
                    current_mtime = os.path.getmtime(norm_path)
                    cached_mtime = _INITIALIZED_DATABASES.get(norm_path)
                    if cached_mtime is not None and cached_mtime == current_mtime:
                        return

        with _DB_INIT_LOCK:
            if not force and not is_memory and os.path.exists(norm_path):
                current_mtime = os.path.getmtime(norm_path)
                cached_mtime = _INITIALIZED_DATABASES.get(norm_path)
                if cached_mtime is not None and cached_mtime == current_mtime:
                    return

            with self._get_connection() as conn:
                if not is_memory:
                    try:
                        conn.execute("PRAGMA journal_mode = WAL;")
                        conn.execute("PRAGMA synchronous = NORMAL;")
                    except sqlite3.OperationalError:
                        pass

                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS analyses (
                        analysis_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        query TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        finding_count INTEGER NOT NULL,
                        summary_json TEXT NOT NULL,
                        schema_version TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        finding_id TEXT NOT NULL,
                        analysis_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence TEXT NOT NULL,
                        category TEXT NOT NULL,
                        evidence_json TEXT NOT NULL,
                        PRIMARY KEY (analysis_id, finding_id),
                        FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS false_positives (
                        suppression_id TEXT PRIMARY KEY,
                        analysis_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        repository_id TEXT NOT NULL,
                        finding_fingerprint TEXT NOT NULL,
                        cwe_id TEXT,
                        rule_signal TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        line_number INTEGER,
                        status TEXT NOT NULL DEFAULT 'ACTIVE',
                        reason TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS webhook_deliveries (
                        delivery_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS pr_commit_reservations (
                        commit_key TEXT PRIMARY KEY,
                        owner TEXT NOT NULL,
                        repository TEXT NOT NULL,
                        pr_number INTEGER NOT NULL,
                        head_sha TEXT NOT NULL,
                        status TEXT NOT NULL,
                        analysis_id TEXT,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        google_sub TEXT UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        full_name TEXT,
                        profile_picture TEXT,
                        role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('ADMIN', 'USER')),
                        status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_login TEXT,
                        created_by TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);
                    CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_fp_repo_fingerprint ON false_positives(repository_id, finding_fingerprint);
                    CREATE INDEX IF NOT EXISTS idx_fp_analysis_finding ON false_positives(analysis_id, finding_id);
                    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_expires_at ON webhook_deliveries(expires_at);
                    CREATE INDEX IF NOT EXISTS idx_commit_reservations_lookup ON pr_commit_reservations(owner, repository, pr_number, head_sha);
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        revoked_at TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL;
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
                    CREATE INDEX IF NOT EXISTS idx_users_status_role ON users(status, role);
                    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);
                """)

                # Additive Phase 31 schema migration for false_positives
                table_info = conn.execute("PRAGMA table_info(false_positives);").fetchall()
                existing_cols = {row["name"] for row in table_info}

                if "fingerprint_version" not in existing_cols:
                    conn.execute("ALTER TABLE false_positives ADD COLUMN fingerprint_version INTEGER NOT NULL DEFAULT 1;")
                if "finding_fingerprint_v2" not in existing_cols:
                    conn.execute("ALTER TABLE false_positives ADD COLUMN finding_fingerprint_v2 TEXT DEFAULT NULL;")
                if "reason_code" not in existing_cols:
                    conn.execute("ALTER TABLE false_positives ADD COLUMN reason_code TEXT NOT NULL DEFAULT 'FALSE_POSITIVE';")
                if "expires_at" not in existing_cols:
                    conn.execute("ALTER TABLE false_positives ADD COLUMN expires_at TEXT DEFAULT NULL;")

                # Additive Phase 31 indexes
                conn.executescript("""
                    CREATE INDEX IF NOT EXISTS idx_fp_repo_v2 ON false_positives(repository_id, finding_fingerprint_v2, status);
                    CREATE INDEX IF NOT EXISTS idx_fp_repo_v1 ON false_positives(repository_id, finding_fingerprint, status);
                """)

                # Additive Phase 32 indexes for Security Analytics V2
                conn.executescript("""
                    CREATE INDEX IF NOT EXISTS idx_findings_category_severity ON findings(category, severity);
                    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                    CREATE INDEX IF NOT EXISTS idx_fp_status_reason ON false_positives(status, reason_code);
                    CREATE INDEX IF NOT EXISTS idx_fp_created_at ON false_positives(created_at DESC);
                """)

                # Additive Phase 33C schema migration for analyses
                analyses_info = conn.execute("PRAGMA table_info(analyses);").fetchall()
                analyses_cols = {row["name"] for row in analyses_info}

                if "owner" not in analyses_cols:
                    conn.execute("ALTER TABLE analyses ADD COLUMN owner TEXT DEFAULT NULL;")
                if "repository" not in analyses_cols:
                    conn.execute("ALTER TABLE analyses ADD COLUMN repository TEXT DEFAULT NULL;")
                if "pr_number" not in analyses_cols:
                    conn.execute("ALTER TABLE analyses ADD COLUMN pr_number INTEGER DEFAULT NULL;")
                if "head_sha" not in analyses_cols:
                    conn.execute("ALTER TABLE analyses ADD COLUMN head_sha TEXT DEFAULT NULL;")
                if "base_sha" not in analyses_cols:
                    conn.execute("ALTER TABLE analyses ADD COLUMN base_sha TEXT DEFAULT NULL;")
                if "author" not in analyses_cols:
                    conn.execute("ALTER TABLE analyses ADD COLUMN author TEXT DEFAULT NULL;")

                # Additive Phase 33C index for exact PR commit lookup
                conn.executescript("""
                    CREATE INDEX IF NOT EXISTS idx_analyses_pr_commit ON analyses(owner, repository, pr_number, head_sha);
                """)

                # Additive Phase A3 schema migration for users
                users_info = conn.execute("PRAGMA table_info(users);").fetchall()
                users_cols = {row["name"] for row in users_info}

                if "google_sub" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT DEFAULT NULL;")
                if "full_name" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT NULL;")
                if "profile_picture" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT DEFAULT NULL;")
                if "role" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'USER';")
                if "status" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';")
                if "created_at" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT '';")
                if "updated_at" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';")
                if "last_login" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT DEFAULT NULL;")
                if "created_by" not in users_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN created_by TEXT DEFAULT NULL;")

                conn.executescript("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL;
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
                    CREATE INDEX IF NOT EXISTS idx_users_status_role ON users(status, role);
                """)

            if not is_memory and os.path.exists(norm_path):
                _INITIALIZED_DATABASES[norm_path] = os.path.getmtime(norm_path)


    def save_analysis(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Idempotently save or update analysis result and its associated findings.

        If an analysis with the same analysis_id already exists, it and its findings
        are replaced safely without creating duplicate records.
        """
        if not isinstance(analysis_result, dict) or analysis_result.get("status") not in ("success", "completed"):
            return analysis_result

        analysis_id = str(analysis_result.get("analysis_id", ""))
        if not analysis_id:
            return analysis_result

        query = str(analysis_result.get("query", ""))
        status = str(analysis_result.get("status", "success"))
        created_at = str(analysis_result.get("created_at") or get_utc_now_iso())
        analysis_result["created_at"] = created_at

        raw_summary = analysis_result.get("summary", {})
        summary = dict(raw_summary) if isinstance(raw_summary, dict) else {}
        if isinstance(analysis_result.get("repository"), dict):
            summary["_repository"] = analysis_result["repository"]
        if analysis_result.get("review_status"):
            summary["_review_status"] = str(analysis_result["review_status"])

        # Preserve sanitized, bounded author identity if present
        raw_author = (
            analysis_result.get("author")
            or (analysis_result.get("repository", {}).get("author") if isinstance(analysis_result.get("repository"), dict) else None)
            or (raw_summary.get("_author") if isinstance(raw_summary, dict) else None)
            or (raw_summary.get("author") if isinstance(raw_summary, dict) else None)
        )
        if raw_author and isinstance(raw_author, str) and raw_author.strip():
            summary["_author"] = raw_author.strip()[:100]

        # Extract PR / Commit identity fields if present
        raw_repo_obj = analysis_result.get("repository") if isinstance(analysis_result.get("repository"), dict) else {}
        raw_owner = (
            analysis_result.get("owner")
            or raw_repo_obj.get("owner")
            or (summary.get("_repository", {}).get("owner") if isinstance(summary.get("_repository"), dict) else None)
        )
        raw_repo = (
            analysis_result.get("repository_id")
            or (analysis_result.get("repository") if isinstance(analysis_result.get("repository"), str) else None)
            or raw_repo_obj.get("name")
            or raw_repo_obj.get("repository")
            or (summary.get("_repository", {}).get("name") if isinstance(summary.get("_repository"), dict) else None)
            or (summary.get("_repository", {}).get("repository") if isinstance(summary.get("_repository"), dict) else None)
        )
        raw_pr = (
            analysis_result.get("pr_number")
            or raw_repo_obj.get("pr_number")
            or (summary.get("_repository", {}).get("pr_number") if isinstance(summary.get("_repository"), dict) else None)
        )
        raw_head = (
            analysis_result.get("head_sha")
            or raw_repo_obj.get("head_sha")
            or (summary.get("_repository", {}).get("head_sha") if isinstance(summary.get("_repository"), dict) else None)
        )
        raw_base = (
            analysis_result.get("base_sha")
            or raw_repo_obj.get("base_sha")
            or (summary.get("_repository", {}).get("base_sha") if isinstance(summary.get("_repository"), dict) else None)
        )

        clean_owner = None
        clean_repo = None
        clean_pr = None
        clean_head = None
        clean_base = None

        if raw_owner and raw_repo and raw_pr is not None and raw_head:
            try:
                clean_owner, clean_repo, clean_pr, clean_head = _validate_pr_identity(
                    raw_owner, raw_repo, raw_pr, raw_head
                )
                if raw_base:
                    clean_base = _validate_optional_sha(raw_base)
            except Exception:
                clean_owner, clean_repo, clean_pr, clean_head = None, None, None, None

        clean_author = str(raw_author).strip()[:100] if (raw_author and isinstance(raw_author, str) and raw_author.strip()) else None

        raw_findings = analysis_result.get("findings", [])
        if not isinstance(raw_findings, list):
            raw_findings = []

        sanitized_findings = [sanitize_finding_record(f) for f in raw_findings if isinstance(f, dict)]

        record = create_analysis_record(
            analysis_id=analysis_id,
            status=status,
            query=query,
            summary=summary,
            created_at=created_at,
        )

        with self._get_connection() as conn:
            # Delete existing analysis findings for idempotency
            conn.execute("DELETE FROM findings WHERE analysis_id = ?;", (analysis_id,))
            conn.execute("DELETE FROM analyses WHERE analysis_id = ?;", (analysis_id,))

            # Insert analysis record with explicit PR identity fields
            conn.execute(
                """
                INSERT INTO analyses (
                    analysis_id, status, query, created_at, finding_count, summary_json, schema_version,
                    owner, repository, pr_number, head_sha, base_sha, author
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    record["analysis_id"],
                    record["status"],
                    record["query"],
                    record["created_at"],
                    record["finding_count"],
                    json.dumps(record["summary"]),
                    record["schema_version"],
                    clean_owner,
                    clean_repo,
                    clean_pr,
                    clean_head,
                    clean_base,
                    clean_author,
                ),
            )

            # Insert findings
            for idx, f in enumerate(sanitized_findings, start=1):
                f_id = f["finding_id"] or f"finding_{idx}"
                conn.execute(
                    """
                    INSERT INTO findings (
                        finding_id, analysis_id, title, description, severity, confidence, category, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        f_id,
                        analysis_id,
                        f["title"],
                        f["description"],
                        f["severity"],
                        f["confidence"],
                        f["category"],
                        json.dumps(f["evidence"]),
                    ),
                )

            # If valid PR commit identity, complete the reservation atomically
            if clean_owner and clean_repo and clean_pr is not None and clean_head:
                commit_key = f"{clean_owner.lower()}/{clean_repo.lower()}:{clean_pr}:{clean_head.lower()}"
                conn.execute(
                    """
                    INSERT INTO pr_commit_reservations (
                        commit_key, owner, repository, pr_number, head_sha, status, analysis_id, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, '9999-12-31T23:59:59+00:00')
                    ON CONFLICT(commit_key) DO UPDATE SET
                        status = 'completed',
                        analysis_id = excluded.analysis_id,
                        expires_at = '9999-12-31T23:59:59+00:00';
                    """,
                    (commit_key, clean_owner, clean_repo, clean_pr, clean_head, analysis_id, created_at)
                )

        return analysis_result

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full single analysis record by analysis_id including findings."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM analyses WHERE analysis_id = ?;", (str(analysis_id),)
            ).fetchone()

            if not row:
                return None

            findings_rows = conn.execute(
                "SELECT * FROM findings WHERE analysis_id = ? ORDER BY finding_id ASC;", (str(analysis_id),)
            ).fetchall()

            # Query all active suppressions for this analysis or matching repository
            fp_rows = conn.execute(
                "SELECT * FROM false_positives WHERE analysis_id = ? AND status = 'ACTIVE';",
                (str(analysis_id),),
            ).fetchall()
            fp_map = {r["finding_id"]: dict(r) for r in fp_rows}

            # Map repository-wide suppressions by v1 and v2 fingerprints for cross-analysis matching
            summary_raw = json.loads(row["summary_json"]) if row["summary_json"] else {}
            repo_meta = summary_raw.get("_repository", {}) if isinstance(summary_raw, dict) else {}
            repo_name = repo_meta.get("repository") or repo_meta.get("repo_name") if isinstance(repo_meta, dict) else None
            repo_fp_v1_map = {}
            repo_fp_v2_map = {}
            if repo_name:
                repo_rows = conn.execute(
                    "SELECT * FROM false_positives WHERE repository_id = ? AND status = 'ACTIVE';",
                    (str(repo_name),),
                ).fetchall()
                for r in repo_rows:
                    if r["finding_fingerprint_v2"]:
                        repo_fp_v2_map[r["finding_fingerprint_v2"]] = dict(r)
                    if r["fingerprint_version"] == 1 and r["finding_fingerprint"]:
                        repo_fp_v1_map[r["finding_fingerprint"]] = dict(r)

            # Pre-compute file findings count for legacy ambiguity checks
            findings_by_file_rule = {}
            for f_row in findings_rows:
                try:
                    f_ev = json.loads(f_row["evidence_json"])
                except Exception:
                    f_ev = []
                primary_ev = f_ev[0] if f_ev and isinstance(f_ev[0], dict) else {}
                r_sig = primary_ev.get("signal_type") or f_row["category"] or "unknown"
                f_p = primary_ev.get("document_id") or "unknown"
                c_id = f_row["category"] or ""
                group_key = (f_p.replace("\\", "/").lower(), r_sig.lower(), c_id.lower())
                findings_by_file_rule[group_key] = findings_by_file_rule.get(group_key, 0) + 1

            findings = []
            for f_row in findings_rows:
                f_id = f_row["finding_id"]
                fp_info = fp_map.get(f_id)
                try:
                    f_ev = json.loads(f_row["evidence_json"])
                except Exception:
                    f_ev = []
                primary_ev = f_ev[0] if f_ev and isinstance(f_ev[0], dict) else {}
                r_sig = primary_ev.get("signal_type") or f_row["category"] or "unknown"
                f_p = primary_ev.get("document_id") or "unknown"
                c_id = f_row["category"] or ""
                group_key = (f_p.replace("\\", "/").lower(), r_sig.lower(), c_id.lower())

                # If no direct finding_id suppression match, check repository-level fingerprints
                if not fp_info and repo_name:
                    synth_f = {
                        "category": c_id,
                        "file_path": f_p,
                        "scope": primary_ev.get("scope") or primary_ev.get("function_name"),
                        "sink_name": primary_ev.get("sink_name") or primary_ev.get("signal_name"),
                        "occurrence_index": primary_ev.get("occurrence_index", 0),
                        "evidence": f_ev,
                    }
                    f_v2 = compute_finding_fingerprint_v2(repo_name, synth_f)
                    f_v1 = compute_finding_fingerprint(repo_name, r_sig, c_id, f_p)
                    if f_v2 in repo_fp_v2_map:
                        fp_info = dict(repo_fp_v2_map[f_v2])
                    elif f_v1 in repo_fp_v1_map:
                        fp_info = dict(repo_fp_v1_map[f_v1])

                is_active = False
                is_exp = False
                leg_ambig = False

                if fp_info:
                    exp_ts = fp_info.get("expires_at")
                    is_active = is_suppression_active(fp_info.get("status", "ACTIVE"), exp_ts)
                    if exp_ts and not is_active and fp_info.get("status") == "ACTIVE":
                        is_exp = True

                    # Check if legacy v1 record is ambiguous (more than 1 finding in same file with same rule)
                    if fp_info.get("fingerprint_version") == 1:
                        if findings_by_file_rule.get(group_key, 0) > 1:
                            leg_ambig = True
                            is_active = False  # Fail closed on legacy ambiguity

                    # Attach derived metadata to feedback object
                    fp_info["is_expired"] = is_exp
                    fp_info["legacy_ambiguous"] = leg_ambig
                elif repo_name and findings_by_file_rule.get(group_key, 0) > 1:
                    # Also check if any legacy suppression matches this group_key to mark ambiguous
                    f_v1 = compute_finding_fingerprint(repo_name, r_sig, c_id, f_p)
                    if f_v1 in repo_fp_v1_map:
                        leg_ambig = True
                        fp_info = dict(repo_fp_v1_map[f_v1])
                        fp_info["is_expired"] = False
                        fp_info["legacy_ambiguous"] = True
                        is_active = False

                findings.append({
                    "finding_id": f_id,
                    "title": f_row["title"],
                    "description": f_row["description"],
                    "severity": f_row["severity"],
                    "confidence": f_row["confidence"],
                    "category": f_row["category"],
                    "evidence": json.loads(f_row["evidence_json"]),
                    "is_false_positive": is_active,
                    "feedback": fp_info,
                })

            summary = json.loads(row["summary_json"])
            repo_meta = summary.pop("_repository", None) if isinstance(summary, dict) else None
            review_stat = summary.pop("_review_status", None) if isinstance(summary, dict) else None
            author = summary.pop("_author", None) if isinstance(summary, dict) else None

            res = {
                "status": row["status"],
                "analysis_id": row["analysis_id"],
                "query": row["query"],
                "created_at": row["created_at"],
                "finding_count": row["finding_count"],
                "summary": summary,
                "findings": findings,
                "provider": "mock",
                "analysis_version": row["schema_version"],
            }
            if repo_meta:
                res["repository"] = repo_meta
            if review_stat:
                res["review_status"] = review_stat
            if author:
                res["author"] = author

            # Attach explicit PR identity fields if present on row
            row_keys = row.keys()
            if "owner" in row_keys and row["owner"]:
                res["owner"] = row["owner"]
            if "repository" in row_keys and row["repository"]:
                res["repository_id"] = row["repository"]
            if "pr_number" in row_keys and row["pr_number"] is not None:
                res["pr_number"] = row["pr_number"]
            if "head_sha" in row_keys and row["head_sha"]:
                res["head_sha"] = row["head_sha"]
            if "base_sha" in row_keys and row["base_sha"]:
                res["base_sha"] = row["base_sha"]

            return res

    def list_analyses(self, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve paginated list of analysis records."""
        safe_limit = 20 if limit is None or int(limit) <= 0 else min(100, int(limit))
        safe_offset = 0 if offset is None or int(offset) < 0 else int(offset)

        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?;",
                (safe_limit, safe_offset),
            ).fetchall()

            results = []
            for row in rows:
                results.append({
                    "analysis_id": row["analysis_id"],
                    "status": row["status"],
                    "query": row["query"],
                    "created_at": row["created_at"],
                    "finding_count": row["finding_count"],
                    "summary": json.loads(row["summary_json"]),
                })
            return results

    def get_findings(self, analysis_id: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieve list of findings for a specific analysis_id."""
        analysis = self.get_analysis(analysis_id)
        if analysis is None:
            return None
        return analysis.get("findings", [])

    def count_analyses(self) -> int:
        """Return total count of analyses stored in database."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM analyses;").fetchone()
            return row["cnt"] if row else 0

    def delete_analysis(self, analysis_id: str) -> bool:
        """Delete an analysis and its cascade findings. Returns True if found & deleted."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM analyses WHERE analysis_id = ?;", (str(analysis_id),))
            return cursor.rowcount > 0

    def record_false_positive(
        self,
        analysis_id: str,
        finding_id: str,
        reason: Optional[str] = None,
        repository_id: Optional[str] = None,
        reason_code: Optional[str] = "FALSE_POSITIVE",
        expires_at: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Record or reactivate false-positive feedback for a specific finding (Phase 31)."""
        # Validate reason taxonomy and comments server-side
        valid_reason_code, valid_reason = validate_reason_payload(reason_code, reason)

        # Validate UTC ISO 8601 expiration timestamp (must be strictly future if provided)
        valid_expires_at = validate_utc_iso_timestamp(expires_at, must_be_future=True) if expires_at else None

        with self._get_connection() as conn:
            finding_row = conn.execute(
                "SELECT * FROM findings WHERE analysis_id = ? AND finding_id = ?;",
                (str(analysis_id), str(finding_id)),
            ).fetchone()
            if not finding_row:
                return None

            analysis_row = conn.execute(
                "SELECT * FROM analyses WHERE analysis_id = ?;", (str(analysis_id),)
            ).fetchone()

            # Determine repo identity
            repo_id = repository_id
            if not repo_id and analysis_row:
                try:
                    summary = json.loads(analysis_row["summary_json"])
                    repo_meta = summary.get("_repository")
                    if isinstance(repo_meta, dict):
                        repo_id = repo_meta.get("repository") or repo_meta.get("repo_name")
                    elif isinstance(repo_meta, str):
                        repo_id = repo_meta
                except Exception:
                    pass
            if not repo_id:
                repo_id = "default"

            # Parse evidence for fingerprinting
            try:
                evidence = json.loads(finding_row["evidence_json"])
            except Exception:
                evidence = []
            ev = evidence[0] if evidence and isinstance(evidence[0], dict) else {}

            rule_signal = ev.get("signal_type") or finding_row["category"] or "security_finding"
            file_path = ev.get("document_id") or "unknown"
            line_number = ev.get("line_start")
            cwe_id = finding_row["category"]

            # Compute legacy v1 fingerprint
            v1_fingerprint = compute_finding_fingerprint(
                repository_id=repo_id,
                rule_signal=rule_signal,
                cwe_id=cwe_id,
                file_path=file_path,
            )

            # Reconstruct synthetic finding dict for v2 computation
            finding_dict_for_v2 = {
                "file_path": file_path,
                "category": cwe_id,
                "scope": ev.get("scope") or ev.get("function_name"),
                "sink_name": ev.get("sink_name") or ev.get("signal_name") or ev.get("call_name"),
                "call_name": ev.get("sink_name") or ev.get("signal_name") or ev.get("call_name"),
                "occurrence_index": ev.get("occurrence_index", 0),
                "evidence": evidence,
            }
            v2_fingerprint = compute_finding_fingerprint_v2(
                repository_id=repo_id,
                finding=finding_dict_for_v2,
            )

            existing = conn.execute(
                "SELECT * FROM false_positives WHERE analysis_id = ? AND finding_id = ?;",
                (str(analysis_id), str(finding_id)),
            ).fetchone()

            now = get_utc_now_iso()

            if existing:
                conn.execute(
                    """
                    UPDATE false_positives
                    SET status = 'ACTIVE',
                        reason = ?,
                        updated_at = ?,
                        repository_id = ?,
                        finding_fingerprint = ?,
                        finding_fingerprint_v2 = ?,
                        fingerprint_version = 2,
                        reason_code = ?,
                        expires_at = ?
                    WHERE suppression_id = ?;
                    """,
                    (
                        valid_reason,
                        now,
                        str(repo_id),
                        v1_fingerprint,
                        v2_fingerprint,
                        valid_reason_code,
                        valid_expires_at,
                        existing["suppression_id"],
                    ),
                )
                suppression_id = existing["suppression_id"]
            else:
                suppression_id = f"supp_{uuid.uuid4().hex[:12]}"
                rec = create_suppression_record(
                    suppression_id=suppression_id,
                    analysis_id=str(analysis_id),
                    finding_id=str(finding_id),
                    repository_id=str(repo_id),
                    finding_fingerprint=v1_fingerprint,
                    rule_signal=str(rule_signal),
                    file_path=str(file_path),
                    cwe_id=str(cwe_id) if cwe_id else None,
                    line_number=line_number,
                    status="ACTIVE",
                    reason=valid_reason,
                    created_at=now,
                    updated_at=now,
                    fingerprint_version=2,
                    finding_fingerprint_v2=v2_fingerprint,
                    reason_code=valid_reason_code,
                    expires_at=valid_expires_at,
                )
                conn.execute(
                    """
                    INSERT INTO false_positives (
                        suppression_id, analysis_id, finding_id, repository_id,
                        finding_fingerprint, cwe_id, rule_signal, file_path,
                        line_number, status, reason, created_at, updated_at,
                        fingerprint_version, finding_fingerprint_v2, reason_code, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        rec["suppression_id"],
                        rec["analysis_id"],
                        rec["finding_id"],
                        rec["repository_id"],
                        rec["finding_fingerprint"],
                        rec["cwe_id"],
                        rec["rule_signal"],
                        rec["file_path"],
                        rec["line_number"],
                        rec["status"],
                        rec["reason"],
                        rec["created_at"],
                        rec["updated_at"],
                        rec["fingerprint_version"],
                        rec["finding_fingerprint_v2"],
                        rec["reason_code"],
                        rec["expires_at"],
                    ),
                )

            updated = conn.execute(
                "SELECT * FROM false_positives WHERE suppression_id = ?;", (suppression_id,)
            ).fetchone()
            return dict(updated) if updated else None

    def get_false_positive(self, analysis_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve false-positive record for a specific finding."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM false_positives WHERE analysis_id = ? AND finding_id = ?;",
                (str(analysis_id), str(finding_id)),
            ).fetchone()
            return dict(row) if row else None

    def revoke_false_positive(self, analysis_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        """Revoke a previously marked false positive (marks as REVOKED without deleting history)."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM false_positives WHERE analysis_id = ? AND finding_id = ?;",
                (str(analysis_id), str(finding_id)),
            ).fetchone()
            if not row:
                return None

            now = get_utc_now_iso()
            conn.execute(
                "UPDATE false_positives SET status = 'REVOKED', updated_at = ? WHERE suppression_id = ?;",
                (now, row["suppression_id"]),
            )
            updated = conn.execute(
                "SELECT * FROM false_positives WHERE suppression_id = ?;", (row["suppression_id"],)
            ).fetchone()
            return dict(updated) if updated else None

    def list_false_positives(
        self,
        repository_id: Optional[str] = None,
        status: Optional[str] = "ACTIVE",
    ) -> List[Dict[str, Any]]:
        """List false-positive records with optional repository and status filtering."""
        with self._get_connection() as conn:
            query = "SELECT * FROM false_positives"
            params: List[Any] = []
            conditions = []
            if repository_id:
                conditions.append("repository_id = ?")
                params.append(str(repository_id))
            if status:
                conditions.append("status = ?")
                params.append(str(status).upper())

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY created_at DESC;"

            rows = conn.execute(query, tuple(params)).fetchall()
            return [dict(r) for r in rows]

    def is_finding_suppressed(
        self,
        repository_id: str,
        finding: Dict[str, Any],
        all_file_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """Check whether a finding matches an active suppression for a repository (Phase 31).

        Lookup order:
        1. Compute v2 fingerprint and search for active v2 suppression.
        2. If active v2 found: evaluate derived expiration (active => True, expired => False).
        3. If no active v2 found: evaluate legacy v1 fallback.
           - If all_file_findings is provided and >1 finding matches the v1 fingerprint:
             FAIL CLOSED (return False; ambiguous legacy record).
           - Otherwise, if single active v1 found: evaluate derived expiration.
        Fails closed on any error or missing data.
        """
        if not repository_id or not isinstance(finding, dict):
            return False

        try:
            fp_v2 = compute_finding_fingerprint_v2(repository_id, finding)

            evidence = finding.get("evidence", [])
            ev = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) else {}
            rule_signal = ev.get("signal_type") or finding.get("category") or "security_finding"
            file_path = ev.get("document_id") or finding.get("file_path") or "unknown"
            cwe_id = finding.get("category")

            fp_v1 = compute_finding_fingerprint(
                repository_id=repository_id,
                rule_signal=rule_signal,
                cwe_id=cwe_id,
                file_path=file_path,
            )

            with self._get_connection() as conn:
                # 1. Check v2 Granular Fingerprint
                if fp_v2:
                    row_v2 = conn.execute(
                        """
                        SELECT expires_at FROM false_positives
                        WHERE repository_id = ? AND finding_fingerprint_v2 = ? AND status = 'ACTIVE'
                        LIMIT 1;
                        """,
                        (str(repository_id), fp_v2),
                    ).fetchone()

                    if row_v2:
                        return is_suppression_active("ACTIVE", row_v2["expires_at"])

                # 2. Legacy v1 Fallback Check
                row_v1 = conn.execute(
                    """
                    SELECT expires_at FROM false_positives
                    WHERE repository_id = ? AND finding_fingerprint = ? AND status = 'ACTIVE'
                    LIMIT 1;
                    """,
                    (str(repository_id), fp_v1),
                ).fetchone()

                if row_v1:
                    # Ambiguity Guard: if multiple findings in this file share the v1 signature, fail closed
                    if all_file_findings:
                        matching_count = sum(
                            1 for f in all_file_findings
                            if compute_finding_fingerprint(
                                repository_id=repository_id,
                                rule_signal=(f.get("evidence", [{}])[0].get("signal_type") if f.get("evidence") else None) or f.get("category") or "security_finding",
                                cwe_id=f.get("category"),
                                file_path=(f.get("evidence", [{}])[0].get("document_id") if f.get("evidence") else None) or f.get("file_path") or "unknown",
                            ) == fp_v1
                        )
                        if matching_count > 1:
                            return False  # Ambiguous legacy record fails closed

                    return is_suppression_active("ACTIVE", row_v1["expires_at"])

                return False
        except Exception:
            return False

    def get_developer_analytics(
        self,
        limit: int = 20,
        repository: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Aggregate developer security activity from persistent analysis records."""
        safe_limit = 20 if limit is None or int(limit) <= 0 else min(100, int(limit))
        target_repo = str(repository).strip().lower() if repository else None

        # Resolve optional time window
        cutoff_iso = None
        if time_window:
            _, cutoff_iso = parse_time_window(time_window)

        with self._get_connection() as conn:
            if cutoff_iso:
                rows = conn.execute(
                    "SELECT * FROM analyses WHERE created_at >= ? ORDER BY created_at DESC;",
                    (cutoff_iso,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM analyses ORDER BY created_at DESC;").fetchall()

        dev_stats: Dict[str, Dict[str, Any]] = {}

        for row in rows:
            try:
                summary = json.loads(row["summary_json"])
            except Exception:
                continue

            repo_meta = summary.get("_repository")
            repo_name = ""
            if isinstance(repo_meta, dict):
                owner = str(repo_meta.get("owner", "") or "")
                r_name = str(repo_meta.get("repository", "") or "")
                if owner and r_name:
                    repo_name = f"{owner}/{r_name}"
                else:
                    repo_name = r_name or owner or ""
            elif isinstance(repo_meta, str):
                repo_name = repo_meta

            # Repository filtering if specified
            if target_repo:
                candidates = [repo_name.lower()]
                if isinstance(repo_meta, dict):
                    if repo_meta.get("repository"):
                        candidates.append(str(repo_meta["repository"]).lower())
                    if repo_meta.get("name"):
                        candidates.append(str(repo_meta["name"]).lower())
                if not any(target_repo == c or target_repo in c for c in candidates if c):
                    continue

            author = summary.get("_author") or (repo_meta.get("author") if isinstance(repo_meta, dict) else None)
            if not author or not isinstance(author, str) or not author.strip():
                continue

            author_clean = author.strip()
            if author_clean.lower() in ("none", "null", "unknown", ""):
                continue

            if author_clean not in dev_stats:
                dev_stats[author_clean] = {
                    "developer": author_clean,
                    "total_analyses": 0,
                    "total_findings": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "block_count": 0,
                    "review_count": 0,
                    "allow_count": 0,
                    "repositories": set(),
                    "last_activity": str(row["created_at"]),
                }

            entry = dev_stats[author_clean]
            entry["total_analyses"] += 1
            entry["total_findings"] += int(row["finding_count"] or 0)
            entry["critical_count"] += int(summary.get("critical_count", 0) or 0)
            entry["high_count"] += int(summary.get("high_count", 0) or 0)
            entry["medium_count"] += int(summary.get("medium_count", 0) or 0)
            entry["low_count"] += int(summary.get("low_count", 0) or 0)

            review_stat = str(summary.get("_review_status", "")).lower()
            if review_stat == "block":
                entry["block_count"] += 1
            elif review_stat == "review":
                entry["review_count"] += 1
            elif review_stat == "allow":
                entry["allow_count"] += 1

            if repo_name:
                entry["repositories"].add(repo_name)

            if str(row["created_at"]) > entry["last_activity"]:
                entry["last_activity"] = str(row["created_at"])

        results = []
        for d in dev_stats.values():
            results.append({
                "developer": d["developer"],
                "total_analyses": d["total_analyses"],
                "total_findings": d["total_findings"],
                "critical_count": d["critical_count"],
                "high_count": d["high_count"],
                "medium_count": d["medium_count"],
                "low_count": d["low_count"],
                "block_count": d["block_count"],
                "review_count": d["review_count"],
                "allow_count": d["allow_count"],
                "repositories": sorted(list(d["repositories"])),
                "last_activity": d["last_activity"],
            })

        # Deterministic ordering: critical DESC, high DESC, total_findings DESC, total_analyses DESC, developer ASC
        results.sort(
            key=lambda item: (
                -item["critical_count"],
                -item["high_count"],
                -item["total_findings"],
                -item["total_analyses"],
                item["developer"].lower(),
            )
        )
        return results[:safe_limit]

    # ========================================================================
    # Phase 32B: Security Analytics V2 Aggregation Methods
    # ========================================================================

    def get_analytics_summary(
        self,
        time_window: Optional[str] = DEFAULT_TIME_WINDOW,
        repository_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compute consolidated security analytics summary.

        Observational only: Does NOT mutate state, gate decisions, or findings.
        Returns:
            total_analyses, total_findings, severity breakdown (critical, high, medium,
            low, info), gate/review status distribution (allow, block, review),
            active_suppressions, expired_suppressions, and time_window metadata.
        """
        window_name, cutoff_iso = parse_time_window(time_window)
        target_repo = str(repository_id).strip().lower() if repository_id else None

        with self._get_connection() as conn:
            # Query analyses in time window
            if cutoff_iso:
                analysis_rows = conn.execute(
                    "SELECT analysis_id, created_at, finding_count, summary_json FROM analyses WHERE created_at >= ? ORDER BY created_at DESC;",
                    (cutoff_iso,),
                ).fetchall()
            else:
                analysis_rows = conn.execute(
                    "SELECT analysis_id, created_at, finding_count, summary_json FROM analyses ORDER BY created_at DESC;"
                ).fetchall()

            matching_analysis_ids = []
            review_statuses = {"allow": 0, "block": 0, "review": 0, "unknown": 0}

            for row in analysis_rows:
                try:
                    summary = json.loads(row["summary_json"])
                except Exception:
                    summary = {}

                # Repository matching if repository_id is requested
                if target_repo:
                    repo_meta = summary.get("_repository")
                    candidates = []
                    if isinstance(repo_meta, dict):
                        owner = str(repo_meta.get("owner", "") or "").lower()
                        r_name = str(repo_meta.get("repository", "") or repo_meta.get("name", "") or "").lower()
                        if owner and r_name:
                            candidates.append(f"{owner}/{r_name}")
                        if r_name:
                            candidates.append(r_name)
                    elif isinstance(repo_meta, str):
                        candidates.append(repo_meta.lower())

                    if not any(target_repo == c or target_repo in c for c in candidates if c):
                        continue

                matching_analysis_ids.append(row["analysis_id"])

                rev_stat = str(summary.get("_review_status", "")).lower()
                if rev_stat in review_statuses:
                    review_statuses[rev_stat] += 1
                else:
                    review_statuses["unknown"] += 1

            total_analyses = len(matching_analysis_ids)
            severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            total_findings = 0

            if matching_analysis_ids:
                # Query finding aggregates using parameterized chunking to stay well under SQLite parameter limits
                chunk_size = 500
                for i in range(0, len(matching_analysis_ids), chunk_size):
                    chunk = matching_analysis_ids[i : i + chunk_size]
                    placeholders = ",".join("?" for _ in chunk)
                    f_rows = conn.execute(
                        f"""
                        SELECT LOWER(severity) AS sev, COUNT(*) AS cnt
                        FROM findings
                        WHERE analysis_id IN ({placeholders})
                        GROUP BY LOWER(severity);
                        """,
                        chunk,
                    ).fetchall()
                    for f_row in f_rows:
                        s_name = f_row["sev"]
                        cnt = int(f_row["cnt"])
                        if s_name in severities:
                            severities[s_name] += cnt
                        else:
                            severities[s_name] = cnt
                        total_findings += cnt

            # Suppression statistics (active, expired derived at query-time)
            fp_query = "SELECT status, expires_at FROM false_positives"
            fp_params: List[Any] = []
            fp_conditions = []
            if target_repo:
                fp_conditions.append("LOWER(repository_id) = ?")
                fp_params.append(target_repo)
            if cutoff_iso:
                fp_conditions.append("created_at >= ?")
                fp_params.append(cutoff_iso)

            if fp_conditions:
                fp_query += " WHERE " + " AND ".join(fp_conditions)

            fp_rows = conn.execute(fp_query, tuple(fp_params)).fetchall()
            active_suppressions = 0
            expired_suppressions = 0
            revoked_suppressions = 0

            for fp in fp_rows:
                status = str(fp["status"]).upper()
                if status == "REVOKED":
                    revoked_suppressions += 1
                elif status == "ACTIVE":
                    if is_suppression_active(status, fp["expires_at"]):
                        active_suppressions += 1
                    else:
                        expired_suppressions += 1

        return {
            "time_window": window_name,
            "cutoff_timestamp": cutoff_iso,
            "repository_id": repository_id,
            "total_analyses": total_analyses,
            "total_findings": total_findings,
            "severities": severities,
            "review_status_distribution": review_statuses,
            "suppressions": {
                "active_count": active_suppressions,
                "expired_count": expired_suppressions,
                "revoked_count": revoked_suppressions,
            },
        }

    def get_vulnerability_analytics(
        self,
        time_window: Optional[str] = DEFAULT_TIME_WINDOW,
        repository_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Aggregate findings by category/vulnerability type with severity breakdown.

        Deterministic ordering: finding_count DESC, critical_count DESC, high_count DESC, category ASC.
        Bounded result set.
        """
        safe_limit = 20 if limit is None or int(limit) <= 0 else min(100, int(limit))
        window_name, cutoff_iso = parse_time_window(time_window)
        target_repo = str(repository_id).strip().lower() if repository_id else None

        with self._get_connection() as conn:
            # 1. Gather analysis_ids matching time window and optional repository
            if cutoff_iso:
                analysis_rows = conn.execute(
                    "SELECT analysis_id, summary_json FROM analyses WHERE created_at >= ?;",
                    (cutoff_iso,),
                ).fetchall()
            else:
                analysis_rows = conn.execute(
                    "SELECT analysis_id, summary_json FROM analyses;"
                ).fetchall()

            matching_analysis_ids = []
            for row in analysis_rows:
                if target_repo:
                    try:
                        summary = json.loads(row["summary_json"])
                    except Exception:
                        summary = {}
                    repo_meta = summary.get("_repository")
                    candidates = []
                    if isinstance(repo_meta, dict):
                        owner = str(repo_meta.get("owner", "") or "").lower()
                        r_name = str(repo_meta.get("repository", "") or repo_meta.get("name", "") or "").lower()
                        if owner and r_name:
                            candidates.append(f"{owner}/{r_name}")
                        if r_name:
                            candidates.append(r_name)
                    elif isinstance(repo_meta, str):
                        candidates.append(repo_meta.lower())

                    if not any(target_repo == c or target_repo in c for c in candidates if c):
                        continue

                matching_analysis_ids.append(row["analysis_id"])

            if not matching_analysis_ids:
                return []

            # 2. Aggregate findings across matching analyses
            # Group by category and compute counts per severity level
            vuln_map: Dict[str, Dict[str, Any]] = {}
            chunk_size = 500

            for i in range(0, len(matching_analysis_ids), chunk_size):
                chunk = matching_analysis_ids[i : i + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT
                        category,
                        LOWER(severity) AS sev,
                        COUNT(*) AS cnt
                    FROM findings
                    WHERE analysis_id IN ({placeholders})
                    GROUP BY category, LOWER(severity);
                    """,
                    chunk,
                ).fetchall()

                for r in rows:
                    cat = str(r["category"] or "General Security")
                    sev = str(r["sev"] or "unknown").lower()
                    cnt = int(r["cnt"])

                    if cat not in vuln_map:
                        vuln_map[cat] = {
                            "category": cat,
                            "finding_count": 0,
                            "critical_count": 0,
                            "high_count": 0,
                            "medium_count": 0,
                            "low_count": 0,
                            "info_count": 0,
                        }

                    entry = vuln_map[cat]
                    entry["finding_count"] += cnt
                    key = f"{sev}_count"
                    if key in entry:
                        entry[key] += cnt

            results = list(vuln_map.values())
            # Deterministic sorting
            results.sort(
                key=lambda v: (
                    -v["finding_count"],
                    -v["critical_count"],
                    -v["high_count"],
                    -v["medium_count"],
                    v["category"].lower(),
                )
            )
            return results[:safe_limit]

    def get_repository_analytics(
        self,
        time_window: Optional[str] = DEFAULT_TIME_WINDOW,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Aggregate security risk and analysis metrics across repositories.

        Deterministic ordering: critical_count DESC, high_count DESC, finding_count DESC,
        analysis_count DESC, repository_id ASC.
        Bounded result set.
        """
        safe_limit = 20 if limit is None or int(limit) <= 0 else min(100, int(limit))
        window_name, cutoff_iso = parse_time_window(time_window)

        with self._get_connection() as conn:
            if cutoff_iso:
                analysis_rows = conn.execute(
                    "SELECT analysis_id, created_at, finding_count, summary_json FROM analyses WHERE created_at >= ? ORDER BY created_at DESC;",
                    (cutoff_iso,),
                ).fetchall()
            else:
                analysis_rows = conn.execute(
                    "SELECT analysis_id, created_at, finding_count, summary_json FROM analyses ORDER BY created_at DESC;"
                ).fetchall()

            repo_stats: Dict[str, Dict[str, Any]] = {}
            repo_analyses_map: Dict[str, List[str]] = {}

            for row in analysis_rows:
                try:
                    summary = json.loads(row["summary_json"])
                except Exception:
                    summary = {}

                repo_meta = summary.get("_repository")
                repo_id = "default"
                if isinstance(repo_meta, dict):
                    owner = str(repo_meta.get("owner", "") or "").strip()
                    r_name = str(repo_meta.get("repository", "") or repo_meta.get("name", "") or "").strip()
                    if owner and r_name:
                        repo_id = f"{owner}/{r_name}"
                    elif r_name or owner:
                        repo_id = r_name or owner
                elif isinstance(repo_meta, str) and repo_meta.strip():
                    repo_id = repo_meta.strip()

                if repo_id not in repo_stats:
                    repo_stats[repo_id] = {
                        "repository_id": repo_id,
                        "analysis_count": 0,
                        "finding_count": 0,
                        "critical_count": 0,
                        "high_count": 0,
                        "medium_count": 0,
                        "low_count": 0,
                        "info_count": 0,
                        "review_status_distribution": {"allow": 0, "block": 0, "review": 0, "unknown": 0},
                        "last_analysis_timestamp": str(row["created_at"]),
                    }
                    repo_analyses_map[repo_id] = []

                entry = repo_stats[repo_id]
                entry["analysis_count"] += 1
                repo_analyses_map[repo_id].append(row["analysis_id"])

                rev_stat = str(summary.get("_review_status", "")).lower()
                if rev_stat in entry["review_status_distribution"]:
                    entry["review_status_distribution"][rev_stat] += 1
                else:
                    entry["review_status_distribution"]["unknown"] += 1

                if str(row["created_at"]) > entry["last_analysis_timestamp"]:
                    entry["last_analysis_timestamp"] = str(row["created_at"])

            # Accumulate findings counts from SQLite findings table per repository
            for repo_id, a_ids in repo_analyses_map.items():
                entry = repo_stats[repo_id]
                chunk_size = 500
                for i in range(0, len(a_ids), chunk_size):
                    chunk = a_ids[i : i + chunk_size]
                    placeholders = ",".join("?" for _ in chunk)
                    f_rows = conn.execute(
                        f"""
                        SELECT LOWER(severity) AS sev, COUNT(*) AS cnt
                        FROM findings
                        WHERE analysis_id IN ({placeholders})
                        GROUP BY LOWER(severity);
                        """,
                        chunk,
                    ).fetchall()

                    for f_row in f_rows:
                        s_name = f_row["sev"]
                        cnt = int(f_row["cnt"])
                        entry["finding_count"] += cnt
                        key = f"{s_name}_count"
                        if key in entry:
                            entry[key] += cnt

            results = list(repo_stats.values())
            results.sort(
                key=lambda r: (
                    -r["critical_count"],
                    -r["high_count"],
                    -r["finding_count"],
                    -r["analysis_count"],
                    r["repository_id"].lower(),
                )
            )
            return results[:safe_limit]

    def get_suppression_analytics(
        self,
        time_window: Optional[str] = DEFAULT_TIME_WINDOW,
        repository_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Aggregate false-positive and suppression telemetry.

        Observational only: NEVER mutates status from ACTIVE to EXPIRED in SQLite.
        Expiration is derived at query-time.
        """
        window_name, cutoff_iso = parse_time_window(time_window)
        target_repo = str(repository_id).strip().lower() if repository_id else None

        with self._get_connection() as conn:
            query = "SELECT * FROM false_positives"
            params: List[Any] = []
            conditions = []
            if target_repo:
                conditions.append("LOWER(repository_id) = ?")
                params.append(target_repo)
            if cutoff_iso:
                conditions.append("created_at >= ?")
                params.append(cutoff_iso)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY created_at DESC;"

            rows = conn.execute(query, tuple(params)).fetchall()

            total_suppressions = len(rows)
            active_count = 0
            expired_count = 0
            revoked_count = 0
            reason_distribution: Dict[str, int] = {}
            version_distribution: Dict[str, int] = {"v1": 0, "v2": 0}

            for row in rows:
                status = str(row["status"]).upper()
                if status == "REVOKED":
                    revoked_count += 1
                elif status == "ACTIVE":
                    if is_suppression_active(status, row["expires_at"]):
                        active_count += 1
                    else:
                        expired_count += 1

                reason_code = str(row["reason_code"] or "FALSE_POSITIVE").strip()
                reason_distribution[reason_code] = reason_distribution.get(reason_code, 0) + 1

                v = int(row["fingerprint_version"] or 1)
                v_key = f"v{v}"
                version_distribution[v_key] = version_distribution.get(v_key, 0) + 1

        return {
            "time_window": window_name,
            "cutoff_timestamp": cutoff_iso,
            "repository_id": repository_id,
            "total_suppressions": total_suppressions,
            "active_count": active_count,
            "expired_count": expired_count,
            "revoked_count": revoked_count,
            "reason_distribution": reason_distribution,
            "fingerprint_version_distribution": version_distribution,
        }

    # ========================================================================
    # Phase 33B: Webhook Delivery Idempotency Methods
    # ========================================================================

    def claim_delivery(
        self,
        delivery_id: str,
        event_type: str,
        now_iso: Optional[str] = None,
        ttl_seconds: Optional[int] = None
    ) -> bool:
        """
        Atomically claims a webhook delivery ID if unseen or expired.

        Guarantees:
        1. Runs bounded cleanup of expired entries (LIMIT 100) to prevent unbounded growth.
        2. Deletes any expired record specifically matching this delivery_id.
        3. Attempts an atomic INSERT with primary key constraint.

        Returns:
            True if successfully claimed, False if already claimed (unexpired duplicate).
        """
        clean_id = str(delivery_id or "").strip()
        if not clean_id or clean_id.lower() in ("none", "unknown"):
            return True

        clean_event = str(event_type or "unknown").strip().lower()

        from datetime import datetime, timezone, timedelta

        if now_iso:
            clean_now = str(now_iso).strip().replace("Z", "+00:00")
            now_dt = datetime.fromisoformat(clean_now).astimezone(timezone.utc)
        else:
            now_dt = datetime.now(timezone.utc)

        ttl = int(ttl_seconds) if ttl_seconds is not None and int(ttl_seconds) > 0 else DEFAULT_DELIVERY_TTL_SECONDS
        exp_dt = now_dt + timedelta(seconds=ttl)

        now_str = now_dt.isoformat()
        exp_str = exp_dt.isoformat()

        with self._get_connection() as conn:
            # 1. Bounded cleanup of expired deliveries
            conn.execute(
                "DELETE FROM webhook_deliveries WHERE rowid IN ("
                "SELECT rowid FROM webhook_deliveries WHERE expires_at <= ? LIMIT 100);",
                (now_str,)
            )
            # 2. Reclaim this specific delivery_id if it exists but is expired
            conn.execute(
                "DELETE FROM webhook_deliveries WHERE delivery_id = ? AND expires_at <= ?;",
                (clean_id, now_str)
            )
            # 3. Attempt atomic insert
            try:
                conn.execute(
                    "INSERT INTO webhook_deliveries (delivery_id, event_type, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?);",
                    (clean_id, clean_event, now_str, exp_str)
                )
                return True
            except sqlite3.IntegrityError:
                # Primary key constraint violation: already claimed and unexpired
                return False

    def is_delivery_claimed(self, delivery_id: str, now_iso: Optional[str] = None) -> bool:
        """Check whether a delivery_id is currently claimed and unexpired."""
        clean_id = str(delivery_id or "").strip()
        if not clean_id or clean_id.lower() in ("none", "unknown"):
            return False

        from datetime import datetime, timezone

        if now_iso:
            clean_now = str(now_iso).strip().replace("Z", "+00:00")
            now_dt = datetime.fromisoformat(clean_now).astimezone(timezone.utc)
        else:
            now_dt = datetime.now(timezone.utc)

        now_str = now_dt.isoformat()

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM webhook_deliveries WHERE delivery_id = ? AND expires_at > ?;",
                (clean_id, now_str)
            ).fetchone()
            return row is not None

    def release_delivery(self, delivery_id: str) -> bool:
        """Release a claimed delivery ID if unhandled processing error occurred."""
        clean_id = str(delivery_id or "").strip()
        if not clean_id or clean_id.lower() in ("none", "unknown"):
            return False

        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM webhook_deliveries WHERE delivery_id = ?;",
                (clean_id,)
            )
            return cursor.rowcount > 0

    def cleanup_expired_deliveries(self, now_iso: Optional[str] = None, limit: int = 100) -> int:
        """Explicitly run bounded cleanup of expired webhook delivery records."""
        from datetime import datetime, timezone

        if now_iso:
            clean_now = str(now_iso).strip().replace("Z", "+00:00")
            now_dt = datetime.fromisoformat(clean_now).astimezone(timezone.utc)
        else:
            now_dt = datetime.now(timezone.utc)

        now_str = now_dt.isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM webhook_deliveries WHERE rowid IN ("
                "SELECT rowid FROM webhook_deliveries WHERE expires_at <= ? LIMIT ?);",
                (now_str, max(1, limit))
            )
            return cursor.rowcount

    # =========================================================================
    # Phase 33C: Commit-Level Analysis Idempotency & PR Persistence Methods
    # =========================================================================

    def get_pr_analysis_by_commit(
        self,
        owner: str,
        repository: str,
        pr_number: Any,
        head_sha: str,
    ) -> Optional[Dict[str, Any]]:
        """Safely and deterministically retrieve completed PR analysis for an exact commit.

        Uses indexed exact query against (owner, repository, pr_number, head_sha).
        Returns None if missing, incomplete, failed, or historical without explicit PR identity.
        """
        try:
            clean_owner, clean_repo, clean_pr, clean_head = _validate_pr_identity(
                owner, repository, pr_number, head_sha
            )
        except Exception:
            return None

        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT analysis_id FROM analyses
                WHERE owner = ? AND repository = ? AND pr_number = ? AND head_sha = ?
                  AND status IN ('success', 'completed')
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (clean_owner, clean_repo, clean_pr, clean_head),
            ).fetchone()

            if not row:
                return None

            analysis_id = row["analysis_id"]

        return self.get_analysis(analysis_id)

    def reserve_pr_commit_analysis(
        self,
        owner: str,
        repository: str,
        pr_number: Any,
        head_sha: str,
        ttl_seconds: int = DEFAULT_COMMIT_RESERVATION_TTL_SECONDS,
        now_iso: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """Atomically reserve execution rights for an exact PR commit analysis.

        Guarantees only one worker acquires reservation.
        Returns:
            (acquired: bool, reason: str, analysis_id: Optional[str])
            - (True, "reserved", None): Successfully reserved analysis ownership.
            - (False, "already_completed", analysis_id): A completed analysis already exists.
            - (False, "in_progress", None): Another worker currently has active in-progress reservation.
        """
        try:
            clean_owner, clean_repo, clean_pr, clean_head = _validate_pr_identity(
                owner, repository, pr_number, head_sha
            )
        except Exception as e:
            return False, f"invalid_identity_{type(e).__name__}", None

        commit_key = f"{clean_owner.lower()}/{clean_repo.lower()}:{clean_pr}:{clean_head.lower()}"

        from datetime import datetime, timezone, timedelta

        if now_iso:
            clean_now = str(now_iso).strip().replace("Z", "+00:00")
            now_dt = datetime.fromisoformat(clean_now).astimezone(timezone.utc)
        else:
            now_dt = datetime.now(timezone.utc)

        now_str = now_dt.isoformat()
        exp_dt = now_dt + timedelta(seconds=max(10, int(ttl_seconds)))
        exp_str = exp_dt.isoformat()

        with self._get_connection() as conn:
            # 1. Check if completed analysis already exists in analyses
            existing = conn.execute(
                """
                SELECT analysis_id FROM analyses
                WHERE owner = ? AND repository = ? AND pr_number = ? AND head_sha = ?
                  AND status IN ('success', 'completed')
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                (clean_owner, clean_repo, clean_pr, clean_head)
            ).fetchone()

            if existing:
                return False, "already_completed", existing["analysis_id"]

            # 2. Check existing reservation in pr_commit_reservations
            res_row = conn.execute(
                "SELECT status, analysis_id, expires_at FROM pr_commit_reservations WHERE commit_key = ?;",
                (commit_key,)
            ).fetchone()

            if res_row:
                status = res_row["status"]
                res_exp = res_row["expires_at"]
                res_aid = res_row["analysis_id"]

                # If marked completed, verify if analysis actually exists
                if status == "completed":
                    if res_aid:
                        a_row = conn.execute(
                            "SELECT analysis_id FROM analyses WHERE analysis_id = ? AND status IN ('success', 'completed');",
                            (res_aid,)
                        ).fetchone()
                        if a_row:
                            return False, "already_completed", res_aid
                    # Completed reservation but missing analysis record -> allow retry
                    conn.execute("DELETE FROM pr_commit_reservations WHERE commit_key = ?;", (commit_key,))

                elif status == "in_progress":
                    # Check expiration
                    try:
                        clean_exp = str(res_exp).strip().replace("Z", "+00:00")
                        exp_time = datetime.fromisoformat(clean_exp).astimezone(timezone.utc)
                        if now_dt < exp_time:
                            # Active unexpired in-progress reservation
                            return False, "in_progress", None
                        else:
                            # Stale reservation from crashed worker -> reclaim
                            conn.execute("DELETE FROM pr_commit_reservations WHERE commit_key = ?;", (commit_key,))
                    except Exception:
                        conn.execute("DELETE FROM pr_commit_reservations WHERE commit_key = ?;", (commit_key,))
                else:
                    # Failed or unknown status -> allow retry
                    conn.execute("DELETE FROM pr_commit_reservations WHERE commit_key = ?;", (commit_key,))

            # 3. Clean bounded expired reservations
            conn.execute(
                "DELETE FROM pr_commit_reservations WHERE expires_at <= ? AND status = 'in_progress';",
                (now_str,)
            )

            # 4. Atomic INSERT to claim reservation
            try:
                conn.execute(
                    """
                    INSERT INTO pr_commit_reservations (
                        commit_key, owner, repository, pr_number, head_sha, status, analysis_id, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, 'in_progress', NULL, ?, ?);
                    """,
                    (commit_key, clean_owner, clean_repo, clean_pr, clean_head, now_str, exp_str)
                )
                return True, "reserved", None
            except sqlite3.IntegrityError:
                # Concurrent worker won the race
                row = conn.execute(
                    "SELECT status, analysis_id FROM pr_commit_reservations WHERE commit_key = ?;",
                    (commit_key,)
                ).fetchone()
                if row and row["status"] == "completed":
                    return False, "already_completed", row["analysis_id"]
                return False, "in_progress", None

    def complete_pr_commit_reservation(
        self,
        owner: str,
        repository: str,
        pr_number: Any,
        head_sha: str,
        analysis_id: Optional[str] = None,
    ) -> bool:
        """Mark commit reservation as completed upon successful analysis report persistence."""
        try:
            clean_owner, clean_repo, clean_pr, clean_head = _validate_pr_identity(
                owner, repository, pr_number, head_sha
            )
        except Exception:
            return False

        commit_key = f"{clean_owner.lower()}/{clean_repo.lower()}:{clean_pr}:{clean_head.lower()}"
        now_str = get_utc_now_iso()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO pr_commit_reservations (
                    commit_key, owner, repository, pr_number, head_sha, status, analysis_id, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, '9999-12-31T23:59:59+00:00')
                ON CONFLICT(commit_key) DO UPDATE SET
                    status = 'completed',
                    analysis_id = COALESCE(excluded.analysis_id, pr_commit_reservations.analysis_id),
                    expires_at = '9999-12-31T23:59:59+00:00';
                """,
                (commit_key, clean_owner, clean_repo, clean_pr, clean_head, str(analysis_id or ""), now_str)
            )
            return True

    def release_pr_commit_reservation(
        self,
        owner: str,
        repository: str,
        pr_number: Any,
        head_sha: str,
    ) -> bool:
        """Release in-progress commit reservation on failure or exception to allow retry."""
        try:
            clean_owner, clean_repo, clean_pr, clean_head = _validate_pr_identity(
                owner, repository, pr_number, head_sha
            )
        except Exception:
            return False

        commit_key = f"{clean_owner.lower()}/{clean_repo.lower()}:{clean_pr}:{clean_head.lower()}"

        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM pr_commit_reservations WHERE commit_key = ? AND status = 'in_progress';",
                (commit_key,)
            )
            return cursor.rowcount > 0

    def cleanup_expired_commit_reservations(self, now_iso: Optional[str] = None, limit: int = 100) -> int:
        """Bounded cleanup of expired in-progress commit reservations."""
        from datetime import datetime, timezone

        if now_iso:
            clean_now = str(now_iso).strip().replace("Z", "+00:00")
            now_dt = datetime.fromisoformat(clean_now).astimezone(timezone.utc)
        else:
            now_dt = datetime.now(timezone.utc)

        now_str = now_dt.isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM pr_commit_reservations WHERE rowid IN ("
                "SELECT rowid FROM pr_commit_reservations WHERE expires_at <= ? AND status = 'in_progress' LIMIT ?);",
                (now_str, max(1, limit))
            )
            return cursor.rowcount

    # ========================================================================
    # Phase A3: User & Access-Control Storage Methods
    # ========================================================================

    @staticmethod
    def _row_to_user(row: Optional[sqlite3.Row]) -> Optional[UserRecord]:
        """Convert a database row to an immutable UserRecord dataclass instance."""
        if not row:
            return None
        return UserRecord(
            user_id=str(row["user_id"]),
            google_sub=str(row["google_sub"]) if row["google_sub"] is not None else None,
            email=str(row["email"]),
            full_name=str(row["full_name"]) if row["full_name"] is not None else None,
            profile_picture=str(row["profile_picture"]) if row["profile_picture"] is not None else None,
            role=str(row["role"]),
            status=str(row["status"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            last_login=str(row["last_login"]) if row["last_login"] is not None else None,
            created_by=str(row["created_by"]) if row["created_by"] is not None else None,
        )

    def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        """Retrieve user record by internal user_id. Returns UserRecord or None."""
        if not user_id or not isinstance(user_id, str):
            return None
        clean_uid = user_id.strip()
        if not clean_uid:
            return None

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE user_id = ?;",
                (clean_uid,)
            ).fetchone()
            return self._row_to_user(row)

    def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        """Retrieve user record by normalized lowercase email address."""
        if not email or not isinstance(email, str):
            return None
        try:
            clean_email = normalize_email(email)
        except ValueError:
            return None

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?;",
                (clean_email,)
            ).fetchone()
            return self._row_to_user(row)

    def get_user_by_google_sub(self, google_sub: str) -> Optional[UserRecord]:
        """Retrieve user record by Google OpenID Connect subject identifier (sub)."""
        if not google_sub or not isinstance(google_sub, str):
            return None
        clean_sub = google_sub.strip()
        if not clean_sub:
            return None

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE google_sub = ?;",
                (clean_sub,)
            ).fetchone()
            return self._row_to_user(row)

    def insert_user(self, user: UserRecord) -> UserRecord:
        """Insert a new user record into storage.
        
        Validates internal constraints and enforces unique constraints on email and google_sub.
        Raises:
            TypeError: If user is not an instance of UserRecord.
            ValueError: If user parameters are invalid or violate uniqueness.
        """
        if not isinstance(user, UserRecord):
            raise TypeError("user must be an instance of UserRecord")
        if not user.user_id or not user.user_id.strip():
            raise ValueError("user_id cannot be empty")

        clean_email = normalize_email(user.email)
        clean_role = str(user.role).strip().upper()
        if clean_role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role '{user.role}'. Must be ADMIN or USER.")

        clean_status = str(user.status).strip().upper()
        if clean_status not in (UserStatus.ACTIVE.value, UserStatus.DISABLED.value):
            raise ValueError(f"Invalid status '{user.status}'. Must be ACTIVE or DISABLED.")

        clean_sub = str(user.google_sub).strip() if user.google_sub else None
        now = get_utc_now_iso()
        created_at = str(user.created_at) if user.created_at else now
        updated_at = str(user.updated_at) if user.updated_at else now

        with self._get_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users (
                        user_id, google_sub, email, full_name, profile_picture,
                        role, status, created_at, updated_at, last_login, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        user.user_id.strip(),
                        clean_sub,
                        clean_email,
                        user.full_name.strip() if user.full_name else None,
                        user.profile_picture.strip() if user.profile_picture else None,
                        clean_role,
                        clean_status,
                        created_at,
                        updated_at,
                        user.last_login,
                        user.created_by.strip() if user.created_by else None,
                    )
                )
            except sqlite3.IntegrityError as err:
                err_msg = str(err).lower()
                if "users.email" in err_msg or ("unique" in err_msg and "email" in err_msg):
                    raise ValueError(f"User with email '{clean_email}' already exists.") from err
                if "users.google_sub" in err_msg or ("unique" in err_msg and "google_sub" in err_msg):
                    raise ValueError(f"User with Google identity '{clean_sub}' already exists.") from err
                if "primary" in err_msg or "user_id" in err_msg:
                    raise ValueError(f"User with user_id '{user.user_id.strip()}' already exists.") from err
                raise ValueError(f"Integrity violation creating user: {err}") from err

        return UserRecord(
            user_id=user.user_id.strip(),
            google_sub=clean_sub,
            email=clean_email,
            full_name=user.full_name.strip() if user.full_name else None,
            profile_picture=user.profile_picture.strip() if user.profile_picture else None,
            role=clean_role,
            status=clean_status,
            created_at=created_at,
            updated_at=updated_at,
            last_login=user.last_login,
            created_by=user.created_by.strip() if user.created_by else None,
        )

    def create_authorized_user(
        self,
        email: str,
        role: str = UserRole.USER.value,
        full_name: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> UserRecord:
        """Create and pre-authorize a new user account with google_sub=None.
        
        Account defaults to status='ACTIVE' and role='USER' (unless explicitly specified).
        Raises:
            ValueError: If email is invalid, duplicate, or role is invalid.
        """
        clean_email = normalize_email(email)
        clean_role = str(role).strip().upper()
        if clean_role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role '{role}'. Must be ADMIN or USER.")

        existing = self.get_user_by_email(clean_email)
        if existing:
            raise ValueError(f"User with email '{clean_email}' already exists.")

        user_id = f"usr_{uuid.uuid4().hex[:16]}"
        now = get_utc_now_iso()
        record = UserRecord(
            user_id=user_id,
            google_sub=None,
            email=clean_email,
            full_name=full_name.strip() if full_name else None,
            profile_picture=None,
            role=clean_role,
            status=UserStatus.ACTIVE.value,
            created_at=now,
            updated_at=now,
            last_login=None,
            created_by=created_by.strip() if created_by else None,
        )
        return self.insert_user(record)

    def bind_google_identity(
        self,
        user_id: str,
        google_sub: str,
        full_name: Optional[str] = None,
        profile_picture: Optional[str] = None,
    ) -> UserRecord:
        """Bind verified Google OpenID Connect identity claims to an authorized user account.
        
        Guarantees:
        1. google_sub cannot be empty.
        2. Prevent binding the same google_sub to two distinct users.
        3. Prevent silently mutating an existing user's bound google_sub to a different identity.
        4. Preserves account role, status, created_at, and created_by.
        5. Updates updated_at and profile metadata if provided.
        """
        if not user_id or not isinstance(user_id, str):
            raise ValueError("user_id cannot be empty.")
        if not google_sub or not isinstance(google_sub, str):
            raise ValueError("google_sub cannot be empty.")

        clean_uid = user_id.strip()
        clean_sub = google_sub.strip()
        if not clean_uid:
            raise ValueError("user_id cannot be empty.")
        if not clean_sub:
            raise ValueError("google_sub cannot be empty.")

        with self._get_connection() as conn:
            # Check if another user already holds this google_sub
            conflict_row = conn.execute(
                "SELECT user_id FROM users WHERE google_sub = ? AND user_id != ?;",
                (clean_sub, clean_uid)
            ).fetchone()
            if conflict_row:
                raise ValueError(f"Google identity '{clean_sub}' is already linked to another account.")

            target_row = conn.execute(
                "SELECT * FROM users WHERE user_id = ?;",
                (clean_uid,)
            ).fetchone()
            if not target_row:
                raise ValueError(f"User '{clean_uid}' not found.")

            target_user = self._row_to_user(target_row)
            if target_user.google_sub and target_user.google_sub != clean_sub:
                raise ValueError(f"User '{clean_uid}' is already bound to a different Google identity.")

            now = get_utc_now_iso()
            new_full_name = full_name.strip() if full_name and full_name.strip() else target_user.full_name
            new_picture = profile_picture.strip() if profile_picture and profile_picture.strip() else target_user.profile_picture

            conn.execute(
                """
                UPDATE users
                SET google_sub = ?,
                    full_name = ?,
                    profile_picture = ?,
                    updated_at = ?
                WHERE user_id = ?;
                """,
                (clean_sub, new_full_name, new_picture, now, clean_uid)
            )

            updated_row = conn.execute(
                "SELECT * FROM users WHERE user_id = ?;", (clean_uid,)
            ).fetchone()
            return self._row_to_user(updated_row)

    def record_successful_login(
        self,
        user_id: str,
        login_time_iso: Optional[str] = None,
    ) -> Optional[UserRecord]:
        """Record successful authentication timestamp.
        
        Updates last_login and updated_at.
        Preserves role, status, created_at, created_by.
        """
        if not user_id or not isinstance(user_id, str):
            return None
        clean_uid = user_id.strip()
        if not clean_uid:
            return None

        now = login_time_iso or get_utc_now_iso()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE users
                SET last_login = ?,
                    updated_at = ?
                WHERE user_id = ?;
                """,
                (now, now, clean_uid)
            )
            if cursor.rowcount == 0:
                return None

            row = conn.execute("SELECT * FROM users WHERE user_id = ?;", (clean_uid,)).fetchone()
            return self._row_to_user(row)

    def update_user_role(self, user_id: str, role: str) -> Optional[UserRecord]:
        """Atomically update a user's role (ADMIN or USER)."""
        clean_role = str(role).strip().upper()
        if clean_role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role '{role}'. Must be ADMIN or USER.")
        if not user_id or not isinstance(user_id, str):
            return None
        clean_uid = user_id.strip()
        if not clean_uid:
            return None

        now = get_utc_now_iso()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE users
                SET role = ?,
                    updated_at = ?
                WHERE user_id = ?;
                """,
                (clean_role, now, clean_uid)
            )
            if cursor.rowcount == 0:
                return None

            row = conn.execute("SELECT * FROM users WHERE user_id = ?;", (clean_uid,)).fetchone()
            return self._row_to_user(row)

    def update_user_status(self, user_id: str, status: str) -> Optional[UserRecord]:
        """Atomically update a user's operational status (ACTIVE or DISABLED)."""
        clean_status = str(status).strip().upper()
        if clean_status not in (UserStatus.ACTIVE.value, UserStatus.DISABLED.value):
            raise ValueError(f"Invalid status '{status}'. Must be ACTIVE or DISABLED.")
        if not user_id or not isinstance(user_id, str):
            return None
        clean_uid = user_id.strip()
        if not clean_uid:
            return None

        now = get_utc_now_iso()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE users
                SET status = ?,
                    updated_at = ?
                WHERE user_id = ?;
                """,
                (clean_status, now, clean_uid)
            )
            if cursor.rowcount == 0:
                return None

            row = conn.execute("SELECT * FROM users WHERE user_id = ?;", (clean_uid,)).fetchone()
            return self._row_to_user(row)

    def update_user_role_and_status(
        self,
        user_id: str,
        role: str,
        status: str,
    ) -> Optional[UserRecord]:
        """Atomically update both role and status in a single database transaction."""
        clean_role = str(role).strip().upper()
        if clean_role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role '{role}'. Must be ADMIN or USER.")
        clean_status = str(status).strip().upper()
        if clean_status not in (UserStatus.ACTIVE.value, UserStatus.DISABLED.value):
            raise ValueError(f"Invalid status '{status}'. Must be ACTIVE or DISABLED.")
        if not user_id or not isinstance(user_id, str):
            return None
        clean_uid = user_id.strip()
        if not clean_uid:
            return None

        now = get_utc_now_iso()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE users
                SET role = ?,
                    status = ?,
                    updated_at = ?
                WHERE user_id = ?;
                """,
                (clean_role, clean_status, now, clean_uid)
            )
            if cursor.rowcount == 0:
                return None

            row = conn.execute("SELECT * FROM users WHERE user_id = ?;", (clean_uid,)).fetchone()
            return self._row_to_user(row)

    def list_users(
        self,
        limit: int = 50,
        offset: int = 0,
        role: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[UserRecord]:
        """Retrieve paginated list of user records with deterministic ordering."""
        safe_limit = max(1, min(limit, 200))
        safe_offset = max(0, offset)

        query = "SELECT * FROM users"
        params: List[Any] = []
        conditions: List[str] = []

        if role:
            clean_role = str(role).strip().upper()
            if clean_role in (UserRole.ADMIN.value, UserRole.USER.value):
                conditions.append("role = ?")
                params.append(clean_role)

        if status:
            clean_status = str(status).strip().upper()
            if clean_status in (UserStatus.ACTIVE.value, UserStatus.DISABLED.value):
                conditions.append("status = ?")
                params.append(clean_status)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC, user_id ASC LIMIT ? OFFSET ?;"
        params.extend([safe_limit, safe_offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [self._row_to_user(r) for r in rows if r]

    def count_users(
        self,
        role: Optional[str] = None,
        status: Optional[str] = None,
    ) -> int:
        """Count total user records matching optional role and status filters."""
        query = "SELECT COUNT(*) as cnt FROM users"
        params: List[Any] = []
        conditions: List[str] = []

        if role:
            clean_role = str(role).strip().upper()
            if clean_role in (UserRole.ADMIN.value, UserRole.USER.value):
                conditions.append("role = ?")
                params.append(clean_role)

        if status:
            clean_status = str(status).strip().upper()
            if clean_status in (UserStatus.ACTIVE.value, UserStatus.DISABLED.value):
                conditions.append("status = ?")
                params.append(clean_status)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        with self._get_connection() as conn:
            row = conn.execute(query, tuple(params)).fetchone()
            return int(row["cnt"]) if row else 0

    def seed_initial_admin(
        self,
        admin_email: Optional[str],
        admin_name: Optional[str] = "Root Administrator",
    ) -> Optional[UserRecord]:
        """Idempotently seed or reaffirm the initial root administrator account.
        
        Guarantees:
        1. If admin_email is None or empty, safely returns None.
        2. If user exists: reaffirms role='ADMIN' and status='ACTIVE' without wiping
           bound google_sub, profile picture, or login timestamp.
        3. If user does not exist: creates pre-authorized ADMIN record with google_sub=None
           and created_by='SYSTEM_SEED'.
        """
        if not admin_email or not str(admin_email).strip():
            return None

        try:
            normalized_email = normalize_email(admin_email)
        except ValueError:
            return None

        existing_user = self.get_user_by_email(normalized_email)
        if existing_user:
            if existing_user.role != UserRole.ADMIN.value or existing_user.status != UserStatus.ACTIVE.value:
                return self.update_user_role_and_status(
                    user_id=existing_user.user_id,
                    role=UserRole.ADMIN.value,
                    status=UserStatus.ACTIVE.value,
                )
            return existing_user

        user_id = f"usr_root_{uuid.uuid4().hex[:12]}"
        now = get_utc_now_iso()
        root_admin = UserRecord(
            user_id=user_id,
            google_sub=None,
            email=normalized_email,
            full_name=admin_name.strip() if admin_name and admin_name.strip() else "Root Administrator",
            profile_picture=None,
            role=UserRole.ADMIN.value,
            status=UserStatus.ACTIVE.value,
            created_at=now,
            updated_at=now,
            last_login=None,
            created_by="SYSTEM_SEED",
        )
        return self.insert_user(root_admin)

    # ========================================================================
    # Phase A4: Session Storage Methods
    # ========================================================================

    def create_session(
        self,
        user_id: str,
        expires_seconds: int = 86400 * 7,
    ) -> str:
        """Create a new authenticated user session and store in SQLite.
        
        Returns generated session_id.
        """
        if not user_id or not str(user_id).strip():
            raise ValueError("user_id cannot be empty to create session.")
        clean_uid = str(user_id).strip()

        from datetime import datetime, timezone, timedelta
        now_dt = datetime.now(timezone.utc)
        expires_dt = now_dt + timedelta(seconds=max(60, expires_seconds))

        import secrets
        session_id = f"sess_{secrets.token_hex(32)}"
        created_at = now_dt.isoformat()
        expires_at = expires_dt.isoformat()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO user_sessions (session_id, user_id, created_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, NULL);
                """,
                (session_id, clean_uid, created_at, expires_at)
            )

        return session_id

    def get_session_user(self, session_id: str) -> Optional[UserRecord]:
        """Retrieve the UserRecord associated with an active, unexpired, unrevoked session.
        
        Returns UserRecord or None if session is missing, revoked, or expired.
        """
        if not session_id or not str(session_id).strip():
            return None
        clean_sid = str(session_id).strip()

        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT u.* FROM users u
                JOIN user_sessions s ON u.user_id = s.user_id
                WHERE s.session_id = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?;
                """,
                (clean_sid, now_iso)
            ).fetchone()
            return self._row_to_user(row)

    def revoke_session(self, session_id: str) -> bool:
        """Revoke an active session. Returns True if a session was revoked."""
        if not session_id or not str(session_id).strip():
            return False
        clean_sid = str(session_id).strip()

        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE user_sessions
                SET revoked_at = ?
                WHERE session_id = ? AND revoked_at IS NULL;
                """,
                (now_iso, clean_sid)
            )
            return cursor.rowcount > 0

    def cleanup_expired_sessions(self, limit: int = 500) -> int:
        """Bounded deletion of expired or revoked user sessions."""
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM user_sessions
                WHERE rowid IN (
                    SELECT rowid FROM user_sessions
                    WHERE expires_at <= ? OR revoked_at IS NOT NULL
                    LIMIT ?
                );
                """,
                (now_iso, max(1, limit))
            )
            return cursor.rowcount

    def revoke_user_sessions(self, user_id: str) -> int:
        """Revoke all active sessions for a specific user ID.
        
        Returns count of sessions revoked.
        """
        if not user_id or not str(user_id).strip():
            return 0
        clean_uid = str(user_id).strip()

        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE user_sessions
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL;
                """,
                (now_iso, clean_uid)
            )
            return cursor.rowcount

    def delete_user(self, user_id: str) -> bool:
        """Delete a user record by user_id. Cascades deletion to user_sessions via SQLite foreign keys.
        
        Returns True if a user record was deleted.
        """
        if not user_id or not str(user_id).strip():
            return False
        clean_uid = str(user_id).strip()

        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM users WHERE user_id = ?;",
                (clean_uid,)
            )
            return cursor.rowcount > 0




