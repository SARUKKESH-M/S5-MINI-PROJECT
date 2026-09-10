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
import uuid
from typing import Any, Dict, List, Optional
from backend.analysis.storage.models import (
    ANALYSIS_SCHEMA_VERSION,
    VALID_REASON_CODES,
    create_analysis_record,
    create_suppression_record,
    get_utc_now_iso,
    sanitize_finding_record,
    validate_reason_payload,
    validate_utc_iso_timestamp,
)


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
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    data_dir = os.path.join(backend_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "codesentinel.db")


class AnalysisStore:
    """Storage manager for saving and retrieving security analysis records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_default_db_path()
        self.initialize()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection with foreign keys enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        """Initialize database directory, tables, indexes, and additive Phase 31 columns."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        with self._get_connection() as conn:
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

                CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);
                CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_fp_repo_fingerprint ON false_positives(repository_id, finding_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_fp_analysis_finding ON false_positives(analysis_id, finding_id);
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

            # Insert analysis record
            conn.execute(
                """
                INSERT INTO analyses (
                    analysis_id, status, query, created_at, finding_count, summary_json, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    record["analysis_id"],
                    record["status"],
                    record["query"],
                    record["created_at"],
                    record["finding_count"],
                    json.dumps(record["summary"]),
                    record["schema_version"],
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
    ) -> List[Dict[str, Any]]:
        """Aggregate developer security activity from persistent analysis records."""
        safe_limit = 20 if limit is None or int(limit) <= 0 else min(100, int(limit))
        target_repo = str(repository).strip().lower() if repository else None

        with self._get_connection() as conn:
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
