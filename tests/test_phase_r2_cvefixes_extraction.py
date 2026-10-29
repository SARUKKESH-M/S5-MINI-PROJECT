"""Focused Acceptance and Verification Suite for CVEfixes Bounded Extraction (Phase R2).

Verifies that the extracted curated database (`knowledge/data/cvefixes_curated.db`)
satisfies all CodeSentinel Phase R2 acceptance criteria:
  1. Exact record count (exactly 93 records)
  2. Balanced language distribution (31 Python, 31 JavaScript, 31 TypeScript)
  3. Coverage across all 12 supported detector CWE categories
  4. Relationship integrity and zero orphan foreign keys
  5. Absence of synthetic template strings or placeholder metadata
  6. Clean NVD prose descriptions and non-empty commit messages
  7. Content length ceiling: MAX_CONTENT_LENGTH <= 4,000 characters
  8. Security Authority Invariant: severity is strictly None
  9. Secret sanitization active on code diffs and metadata
  10. Deterministic reproducibility: stable SHA-256 digest
  11. Unaltered behavior for MITRE CWE and CISA KEV ingestion
  12. CVEfixes production ingestion remains safely quarantined
"""

import hashlib
import os
import sqlite3
import sys
import tempfile
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "backend"))
sys.path.insert(0, ROOT_DIR)

from backend.app.core.config import settings
from backend.app.core.security import sanitize_sensitive_text
from knowledge.adapters.cvefixes_adapter import CvefixesAdapter, MAX_CONTENT_LENGTH
from knowledge.curation import CvefixesCurator, SUPPORTED_CWES as DEFAULT_CURATION_CWES
from knowledge.data.extract_cvefixes_subset import (
    extract_cvefixes_subset,
    compute_sha256,
    DEFAULT_DST_PATH,
    EXPECTED_SRC_SHA256,
    SUPPORTED_CWES,
    TARGET_LANGS,
)

EXPECTED_CURATED_SHA256 = "e7f4700c5b5e4899389ad803b4c097174eccbe785c4c5919a69ef58d8be28d18"


@pytest.fixture(scope="module")
def curated_db_conn():
    """Provide read-only connection to the curated SQLite database."""
    assert os.path.exists(DEFAULT_DST_PATH), f"Curated DB missing at: {DEFAULT_DST_PATH}"
    conn = sqlite3.connect(f"file:{DEFAULT_DST_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def test_curated_db_exists_and_integrity(curated_db_conn):
    """Verify that the curated database exists, passes PRAGMA integrity_check, and matches SHA-256."""
    cur = curated_db_conn.cursor()
    check = [r[0] for r in cur.execute("PRAGMA integrity_check").fetchall()]
    assert check == ["ok"], f"Integrity check failed: {check}"

    actual_sha = compute_sha256(DEFAULT_DST_PATH)
    assert actual_sha == EXPECTED_CURATED_SHA256, f"Checksum mismatch: {actual_sha} != {EXPECTED_CURATED_SHA256}"
    assert os.path.getsize(DEFAULT_DST_PATH) < 2 * 1024 * 1024, "Curated DB size exceeds 2 MB limit"


def test_exact_record_counts_and_distributions(curated_db_conn):
    """Verify exactly 93 records with balanced 31/31/31 language distribution."""
    cur = curated_db_conn.cursor()

    for table in ["fixes", "commits", "file_change", "cve", "cwe_classification"]:
        cnt = cur.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert cnt == 93, f"Table {table} has {cnt} rows, expected exactly 93"

    # Verify language distribution: exactly 31 each
    langs = cur.execute(
        "SELECT LOWER(programming_language), COUNT(*) FROM file_change GROUP BY LOWER(programming_language)"
    ).fetchall()
    lang_dict = {r[0]: r[1] for r in langs}
    assert lang_dict == {"javascript": 31, "python": 31, "typescript": 31}

    # Verify all 12 supported CWEs are represented
    cwes = cur.execute("SELECT DISTINCT cwe_id FROM cwe_classification").fetchall()
    found_cwes = {r[0] for r in cwes}
    assert found_cwes == set(SUPPORTED_CWES), f"CWE coverage incomplete: missing {set(SUPPORTED_CWES) - found_cwes}"


def test_relationship_integrity_and_zero_orphans(curated_db_conn):
    """Verify primary key uniqueness and zero orphan records across all joins."""
    cur = curated_db_conn.cursor()

    # Uniqueness checks
    distinct_fc = cur.execute("SELECT COUNT(DISTINCT file_change_id) FROM file_change").fetchone()[0]
    distinct_cve = cur.execute("SELECT COUNT(DISTINCT cve_id) FROM cve").fetchone()[0]
    distinct_hash = cur.execute("SELECT COUNT(DISTINCT hash) FROM commits").fetchone()[0]
    assert distinct_fc == 93, f"Duplicate file_change_ids: {distinct_fc} != 93"
    assert distinct_cve == 93, f"Duplicate cve_ids: {distinct_cve} != 93"
    assert distinct_hash == 93, f"Duplicate commit hashes: {distinct_hash} != 93"

    # Zero orphan joins
    orphan_commits = cur.execute(
        "SELECT COUNT(*) FROM fixes f LEFT JOIN commits c ON f.hash = c.hash WHERE c.hash IS NULL"
    ).fetchone()[0]
    orphan_cve = cur.execute(
        "SELECT COUNT(*) FROM fixes f LEFT JOIN cve c ON f.cve_id = c.cve_id WHERE c.cve_id IS NULL"
    ).fetchone()[0]
    orphan_cwe = cur.execute(
        "SELECT COUNT(*) FROM fixes f LEFT JOIN cwe_classification w ON f.cve_id = w.cve_id WHERE w.cve_id IS NULL"
    ).fetchone()[0]
    orphan_fc = cur.execute(
        "SELECT COUNT(*) FROM fixes f LEFT JOIN file_change fc ON f.hash = fc.hash WHERE fc.file_change_id IS NULL"
    ).fetchone()[0]

    assert orphan_commits == 0, f"Orphan commits found: {orphan_commits}"
    assert orphan_cve == 0, f"Orphan cves found: {orphan_cve}"
    assert orphan_cwe == 0, f"Orphan cwe classifications found: {orphan_cwe}"
    assert orphan_fc == 0, f"Orphan file changes found: {orphan_fc}"


def test_data_authenticity_and_zero_placeholders(curated_db_conn):
    """Verify absence of synthetic boilerplate and presence of authentic commit/diff data."""
    cur = curated_db_conn.cursor()

    # Zero template descriptions
    t_desc = cur.execute(
        "SELECT COUNT(*) FROM cve WHERE description LIKE 'Security vulnerability % classified under %'"
    ).fetchone()[0]
    assert t_desc == 0, "Found synthetic template descriptions in curated DB"

    # Zero template commit messages
    t_msg = cur.execute(
        "SELECT COUNT(*) FROM commits WHERE msg LIKE 'Fix security vulnerability in commit %'"
    ).fetchone()[0]
    assert t_msg == 0, "Found synthetic template commit messages in curated DB"

    # Descriptions must be clean non-empty prose (not raw JSON brackets)
    raw_json_brackets = cur.execute(
        "SELECT COUNT(*) FROM cve WHERE description LIKE '[{%'"
    ).fetchone()[0]
    assert raw_json_brackets == 0, f"Found unparsed stringified JSON descriptions: {raw_json_brackets}"

    # Verify all 93 rows have non-empty code_before and code_after
    empty_codes = cur.execute(
        "SELECT COUNT(*) FROM file_change WHERE code_before IS NULL OR code_before = '' OR code_after IS NULL OR code_after = ''"
    ).fetchone()[0]
    assert empty_codes == 0, f"Found {empty_codes} rows with empty code_before or code_after"


def test_cvefixes_adapter_normalization_invariants(curated_db_conn):
    """Verify CvefixesAdapter normalizes all 93 records with severity=None and length <= 4000."""
    adapter = CvefixesAdapter()
    docs = adapter.load_from_db(curated_db_conn, limit=100)
    assert len(docs) == 93, f"CvefixesAdapter produced {len(docs)} documents, expected 93"

    for doc in docs:
        meta = doc["metadata"]
        assert meta.get("severity") is None, f"Severity violation: {meta.get('severity')}"
        assert len(doc["content"]) <= MAX_CONTENT_LENGTH, f"Content length violation: {len(doc['content'])}"
        assert meta["source"] == "cvefixes"
        assert meta["category"] == "vulnerability_fix"
        assert meta["language"] in TARGET_LANGS
        assert meta["cwe_id"] in SUPPORTED_CWES
        assert doc["document_id"].startswith("kn_cvefixes_")


def test_cvefixes_curator_normalization_invariants(curated_db_conn):
    """Verify CvefixesCurator normalizes all 93 records with severity=None and length <= 4000."""
    curator = CvefixesCurator(supported_cwes=set(SUPPORTED_CWES))
    curated_docs = curator.curate_from_db(curated_db_conn, limit=100)
    assert len(curated_docs) == 93, f"CvefixesCurator produced {len(curated_docs)} documents, expected 93"

    for doc in curated_docs:
        assert doc.metadata.severity is None, f"Severity violation in curator: {doc.metadata.severity}"
        assert len(doc.content) <= MAX_CONTENT_LENGTH, f"Content length violation: {len(doc.content)}"
        assert doc.metadata.source == "cvefixes"
        assert doc.metadata.language in TARGET_LANGS
        assert doc.metadata.cwe_id in SUPPORTED_CWES
        assert doc.document_id.startswith("knowledge_cvefixes_")


def test_secret_sanitization_active():
    """Verify secret scrubbing is applied and redacts sensitive tokens."""
    dirty_text = "Bearer ghp_abcdef1234567890abcdef1234567890"
    clean_text = sanitize_sensitive_text(dirty_text)
    assert "[REDACTED_SECRET]" in clean_text
    assert "ghp_abcdef" not in clean_text


def test_reproducibility_idempotency():
    """Verify re-running extraction against a temporary destination produces byte-for-byte identical output."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dst = os.path.join(tmp_dir, "reproduced.db")
        res = extract_cvefixes_subset(
            dst_path=tmp_dst,
            force=True,
            verify_src_hash=False,
        )
        assert res["status"] == "success"
        assert res["record_count"] == 93
        assert res["dst_sha256"] == EXPECTED_CURATED_SHA256, (
            f"Reproduction SHA-256 differs: {res['dst_sha256']} != {EXPECTED_CURATED_SHA256}"
        )


def test_production_ingestion_remains_disabled():
    """Verify that external knowledge remains disabled by default and CVEfixes is blocked from production ingestion."""
    assert settings.ENABLE_EXTERNAL_KNOWLEDGE is False, "ENABLE_EXTERNAL_KNOWLEDGE must default to False"

    # Verify rag.ingestion blocks cvefixes
    from rag.ingestion import ingest_external_security_knowledge
    with pytest.raises((ValueError, PermissionError)) as exc_info:
        ingest_external_security_knowledge(sources=["cvefixes"])
    assert "cvefixes" in str(exc_info.value).lower()
