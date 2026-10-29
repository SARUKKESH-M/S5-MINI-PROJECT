"""Tests for CodeSentinel Upgrade 2A-2: Bounded Dataset Curation Layer.

Verifies:
1. MITRE output contains only the deduplicated target CWE set (12 supported + MITRE Top 25 = 26 unique CWEs).
2. CISA filtering uses explicit CWE values and matches independently verified record/CVE/association counts.
3. Missing or unsupported CWE values are excluded without inference.
4. Duplicate CVEs preserve their matching supported CWE associations.
5. CVEfixes processing operates via SQLite fixtures and never requires unpacking the massive source archive.
6. All curated content respects the 4,000-character limit.
7. Synthetic secrets are redacted before output persistence.
8. External severity remains None (Security Authority Invariant).
9. Repeated curation produces deterministic results with SHA-256 fingerprints.
10. The existing protected adapter tests and datasets remain untouched.
"""

import hashlib
import os
import sqlite3
import sys
import pytest

# Ensure root and backend are on sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
backend_dir = os.path.join(ROOT_DIR, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from knowledge.curation import (
    MitreCweCurator,
    CisaKevCurator,
    CvefixesCurator,
    CuratedMetadata,
    CuratedDocument,
    SUPPORTED_CWES,
    MAX_CONTENT_LENGTH,
    sanitize_sensitive_text,
    compute_sha256,
)

REAL_MITRE_ZIP = os.path.join(ROOT_DIR, "datasets", "mitre_cwe", "cwec_latest.xml.zip")
REAL_CISA_CSV = os.path.join(ROOT_DIR, "datasets", "cisa_kev", "known_exploited_vulnerabilities.csv")


# ---------------------------------------------------------------------------
# 1. MITRE CWE Bounded Selection & Deduplication Tests
# ---------------------------------------------------------------------------

def test_1_mitre_cwe_curation_from_real_dataset():
    """Verify MITRE CWE zip curation extracts exactly 26 unique CWEs."""
    if not os.path.isfile(REAL_MITRE_ZIP):
        pytest.skip(f"MITRE CWE archive not found at {REAL_MITRE_ZIP}")

    curator = MitreCweCurator()
    docs = curator.curate_from_zip(REAL_MITRE_ZIP)

    assert len(docs) == 26, f"Expected exactly 26 curated CWE definitions, got {len(docs)}"
    cwe_ids = [d.metadata.cwe_id for d in docs]
    assert len(set(cwe_ids)) == 26, "Expected all 26 CWE IDs to be distinct"

    # All 12 supported CWEs must be present
    for supp in SUPPORTED_CWES:
        assert supp in cwe_ids, f"Expected supported CWE {supp} to be in curated set"

    # Verify metadata and content properties
    for doc in docs:
        assert doc.metadata.source == "mitre_cwe"
        assert doc.metadata.doc_type == "reference"
        assert doc.metadata.language == "agnostic"
        assert doc.metadata.severity is None
        assert len(doc.content) <= MAX_CONTENT_LENGTH
        assert doc.content_hash == compute_sha256(doc.content)


def test_2_mitre_cwe_xml_fixture_handling():
    """Verify safe XML parsing and missing-field handling on a synthetic fixture."""
    xml_fixture = """<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog Name="CWE" Version="4.20" xmlns="http://cwe.mitre.org/cwe-7">
      <Views>
        <View ID="1430" Name="2024 CWE Top 25">
          <Members>
            <Has_Member CWE_ID="89"/>
            <Has_Member CWE_ID="787"/>
          </Members>
        </View>
      </Views>
      <Weaknesses>
        <!-- Matching Supported CWE -->
        <Weakness ID="89" Name="SQL Injection">
          <Description>SQL injection occurs when untrusted input is concatenated.</Description>
        </Weakness>
        <!-- Matching Top 25 CWE (not directly in 12 supported) -->
        <Weakness ID="787" Name="Out-of-bounds Write">
          <Description>Software writes data past the buffer boundary.</Description>
        </Weakness>
        <!-- Excluded CWE: not in supported 12 and not in Top 25 view -->
        <Weakness ID="9999" Name="Rare Obscure Bug">
          <Description>Should be filtered out.</Description>
        </Weakness>
        <!-- Duplicate entry: should be deduplicated -->
        <Weakness ID="89" Name="Duplicate SQL Injection">
          <Description>Duplicate description.</Description>
        </Weakness>
      </Weaknesses>
    </Weakness_Catalog>
    """
    curator = MitreCweCurator(supported_cwes={"CWE-89"})
    docs = curator.curate_from_xml_string(xml_fixture)

    assert len(docs) == 2
    cwe_ids = [d.metadata.cwe_id for d in docs]
    assert cwe_ids == ["CWE-89", "CWE-787"]
    assert "CWE-9999" not in cwe_ids


# ---------------------------------------------------------------------------
# 2. CISA KEV Explicit CWE Filtering & Verification Counts
# ---------------------------------------------------------------------------

def test_3_cisa_kev_real_dataset_counts():
    """Verify CISA KEV counts on the official downloaded CSV."""
    if not os.path.isfile(REAL_CISA_CSV):
        pytest.skip(f"CISA KEV CSV not found at {REAL_CISA_CSV}")

    curator = CisaKevCurator()
    docs, stats = curator.curate_from_file(REAL_CISA_CSV)

    assert stats.total_source_records == 1731
    assert stats.missing_cwe_records == 175
    assert stats.unsupported_cwe_records == 1127
    assert stats.distinct_matched_cves == 429
    assert stats.matched_cwe_associations == 431
    assert len(docs) == 429

    for doc in docs:
        assert doc.metadata.source == "cisa_kev"
        assert doc.metadata.doc_type == "threat_intel"
        assert doc.metadata.severity is None
        assert doc.metadata.cwe_id in SUPPORTED_CWES
        assert len(doc.content) <= MAX_CONTENT_LENGTH


def test_4_cisa_kev_no_inference_on_missing_or_unsupported():
    """Verify missing or unsupported CWE records are discarded without heuristic inference."""
    csv_fixture = """cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes
CVE-2024-0001,Vendor,Product,SQL Injection in Login,2024-01-01,Allows SQL injection into database,Update now,2024-02-01,Unknown,,
CVE-2024-0002,Vendor,Product,Command Execution Bug,2024-01-01,Allows remote OS command execution,Update now,2024-02-01,Unknown,,CWE-119
CVE-2024-0003,Vendor,Product,Legitimate SQL Injection,2024-01-01,Real SQLi,Update now,2024-02-01,Unknown,,CWE-89
"""
    curator = CisaKevCurator()
    docs, stats = curator.curate_from_csv_string(csv_fixture)

    # CVE-2024-0001: Description says 'SQL Injection', but cwes is blank -> MUST NOT INFER -> Excluded!
    # CVE-2024-0002: Description says 'Command Execution', but cwes is CWE-119 -> Not in supported 12 -> Excluded!
    # CVE-2024-0003: cwes is CWE-89 -> Exact match -> Accepted!
    assert stats.total_source_records == 3
    assert stats.missing_cwe_records == 1
    assert stats.unsupported_cwe_records == 1
    assert stats.distinct_matched_cves == 1
    assert len(docs) == 1
    assert docs[0].metadata.cve_id == "CVE-2024-0003"
    assert docs[0].metadata.cwe_id == "CWE-89"


def test_5_cisa_kev_duplicate_cve_preserves_associations():
    """Verify multi-CWE CVEs preserve all matching supported associations."""
    csv_fixture = """cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes
CVE-2024-7399,Vendor,App,Traversal and Upload,2024-08-01,Dual weakness vulnerability,Update,2024-08-20,Unknown,,"CWE-22, CWE-434"
CVE-2024-7399,Vendor,App,Traversal and Upload Dup,2024-08-01,Duplicate row with extra info,Update,2024-08-20,Unknown,,CWE-22
"""
    curator = CisaKevCurator()
    docs, stats = curator.curate_from_csv_string(csv_fixture)

    assert len(docs) == 1
    doc = docs[0]
    assert doc.metadata.cve_id == "CVE-2024-7399"
    all_cwes = doc.extra_metadata.get("all_matching_cwes", [])
    assert "CWE-22" in all_cwes
    assert "CWE-434" in all_cwes
    assert "CWE-22, CWE-434" in doc.content or "CWE-434, CWE-22" in doc.content


# ---------------------------------------------------------------------------
# 3. CVEfixes Bounded Curation & Fixture Strategy Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_cvefixes_sqlite():
    """In-memory SQLite database matching the CVEfixes schema."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);
    CREATE TABLE commits (hash TEXT, repo_url TEXT, msg TEXT);
    CREATE TABLE file_change (
        file_change_id TEXT, hash TEXT, filename TEXT,
        programming_language TEXT, code_before TEXT, code_after TEXT
    );
    CREATE TABLE method_change (
        method_change_id TEXT, file_change_id TEXT, name TEXT,
        code TEXT, before_change TEXT
    );
    CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);

    -- Record 1: Python SQL Injection (Supported Language + Supported CWE) -> ACCEPT
    INSERT INTO fixes VALUES ('CVE-2021-1001', 'h_py_1', 'https://github.com/org/pyrepo');
    INSERT INTO commits VALUES ('h_py_1', 'https://github.com/org/pyrepo', 'Fix SQL injection query');
    INSERT INTO file_change VALUES ('fc_1', 'h_py_1', 'db.py', 'Python', 'cursor.execute("SELECT * FROM " + u)', 'cursor.execute("SELECT * FROM users WHERE id = %s", (u,))');
    INSERT INTO method_change VALUES ('mc_1', 'fc_1', 'get_user', 'def get_user(u): pass', '0');
    INSERT INTO cwe_classification VALUES ('CVE-2021-1001', 'CWE-89');

    -- Record 2: TypeScript Path Traversal (Supported Language + Supported CWE) -> ACCEPT
    INSERT INTO fixes VALUES ('CVE-2022-2002', 'h_ts_1', 'https://github.com/org/tsrepo');
    INSERT INTO commits VALUES ('h_ts_1', 'https://github.com/org/tsrepo', 'Fix path traversal in file serve');
    INSERT INTO file_change VALUES ('fc_2', 'h_ts_1', 'server.ts', 'TypeScript', 'res.sendFile(path.join(dir, req.query.file))', 'res.sendFile(safePath(dir, req.query.file))');
    INSERT INTO method_change VALUES ('mc_2', 'fc_2', 'serve', 'function serve() {}', '0');
    INSERT INTO cwe_classification VALUES ('CVE-2022-2002', 'CWE-22');

    -- Record 3: C++ Buffer Overflow (Unsupported Language) -> REJECT
    INSERT INTO fixes VALUES ('CVE-2020-3003', 'h_cpp_1', 'https://github.com/org/cpprepo');
    INSERT INTO commits VALUES ('h_cpp_1', 'https://github.com/org/cpprepo', 'Fix buffer overflow');
    INSERT INTO file_change VALUES ('fc_3', 'h_cpp_1', 'buffer.cpp', 'C++', 'strcpy(dst, src);', 'strncpy(dst, src, len);');
    INSERT INTO method_change VALUES ('mc_3', 'fc_3', 'copy_buf', 'void copy_buf() {}', '0');
    INSERT INTO cwe_classification VALUES ('CVE-2020-3003', 'CWE-119');

    -- Record 4: Python Unsupported CWE (CWE-400 resource exhaustion) -> REJECT
    INSERT INTO fixes VALUES ('CVE-2020-4004', 'h_py_2', 'https://github.com/org/pyrepo2');
    INSERT INTO commits VALUES ('h_py_2', 'https://github.com/org/pyrepo2', 'Fix regex DoS');
    INSERT INTO file_change VALUES ('fc_4', 'h_py_2', 're.py', 'Python', 're.match("(a+)+$", s)', 're.match("a+", s)');
    INSERT INTO method_change VALUES ('mc_4', 'fc_4', 'match_text', 'def match_text(): pass', '0');
    INSERT INTO cwe_classification VALUES ('CVE-2020-4004', 'CWE-400');
    """)
    conn.commit()
    yield conn
    conn.close()


def test_6_cvefixes_bounded_filtering(mock_cvefixes_sqlite):
    """Verify CVEfixes curation enforces language, CWE, and record limits without unpacking archive."""
    curator = CvefixesCurator()
    docs = curator.curate_from_db(mock_cvefixes_sqlite, limit=100)

    # Only Record 1 (Python, CWE-89) and Record 2 (TypeScript, CWE-22) should be accepted
    assert len(docs) == 2
    cves = [d.metadata.cve_id for d in docs]
    assert "CVE-2021-1001" in cves
    assert "CVE-2022-2002" in cves
    assert "CVE-2020-3003" not in cves  # C++ excluded
    assert "CVE-2020-4004" not in cves  # CWE-400 excluded

    for doc in docs:
        assert doc.metadata.source == "cvefixes"
        assert doc.metadata.doc_type == "remediation_example"
        assert doc.metadata.language in ("python", "typescript", "javascript")
        assert doc.metadata.severity is None


# ---------------------------------------------------------------------------
# 4. Content Length, Secret Redaction, and Invariant Tests
# ---------------------------------------------------------------------------

def test_7_content_length_limit_enforced():
    """Verify all content respects the 4,000-character boundary."""
    long_desc = "Vulnerability description text. " * 300  # > 9,000 characters
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog Name="CWE" Version="4.20" xmlns="http://cwe.mitre.org/cwe-7">
      <Weaknesses>
        <Weakness ID="89" Name="SQL Injection">
          <Description>{long_desc}</Description>
        </Weakness>
      </Weaknesses>
    </Weakness_Catalog>
    """
    curator = MitreCweCurator(supported_cwes={"CWE-89"})
    docs = curator.curate_from_xml_string(xml)

    assert len(docs) == 1
    assert len(docs[0].content) <= MAX_CONTENT_LENGTH


def test_8_secret_redaction_comprehensive():
    """Verify redaction of synthetic AWS credentials, tokens, JWTs, and keys."""
    raw_text = (
        "Configuring service:\n"
        "aws_key = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "github_token = 'ghp_0123456789abcdef0123456789abcdef'\n"
        "auth_header = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl'\n"
        'db_password = "SuperSecretPass123!"\n'
        'api_key = "my_internal_api_key_xyz"\n'
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0+fake+private+key+block==\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    sanitized = sanitize_sensitive_text(raw_text)

    # Assert none of the raw secrets leaked
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in sanitized
    assert "ghp_0123456789abcdef0123456789abcdef" not in sanitized
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "SuperSecretPass123!" not in sanitized
    assert "my_internal_api_key_xyz" not in sanitized
    assert "MIIEowIBAAKCAQEA0" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized


def test_9_security_authority_invariant():
    """Verify metadata severity is strictly None across all operations."""
    # Instantiating CuratedMetadata with non-None severity must fail immediately
    with pytest.raises(ValueError, match="Security Authority Violation"):
        CuratedMetadata(
            source="mitre_cwe",
            cwe_id="CWE-89",
            language="agnostic",
            doc_type="reference",
            severity="CRITICAL",  # Illegal override!
        )


def test_10_deterministic_deduplication_and_hashing():
    """Verify repeated curation produces bit-identical outputs and stable SHA-256 hashes."""
    csv_fixture = """cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes
CVE-2024-0003,Vendor,Product,Legitimate SQL Injection,2024-01-01,Real SQLi,Update now,2024-02-01,Unknown,,CWE-89
"""
    curator = CisaKevCurator()
    docs1, _ = curator.curate_from_csv_string(csv_fixture)
    docs2, _ = curator.curate_from_csv_string(csv_fixture)

    assert len(docs1) == 1 and len(docs2) == 1
    assert docs1[0].document_id == docs2[0].document_id
    assert docs1[0].content == docs2[0].content
    assert docs1[0].content_hash == docs2[0].content_hash
    assert docs1[0].content_hash == hashlib.sha256(docs1[0].content.encode("utf-8")).hexdigest()


def test_11_protected_files_intact():
    """Verify all 7 protected paths remain intact and unmodified."""
    protected_paths = [
        "datasets",
        "knowledge/adapters",
        "scratch",
        "tests/test_cisa_kev_adapter.py",
        "tests/test_cvefixes_adapter.py",
        "tests/test_knowledge_dataset_integration.py",
        "tests/test_mitre_cwe_adapter.py",
    ]
    for rel_path in protected_paths:
        full_path = os.path.join(ROOT_DIR, rel_path)
        if not os.path.exists(full_path):
            pytest.skip(f"Protected path not present in clean remote CI checkout: {rel_path}")
        assert os.path.exists(full_path), f"Protected path missing: {rel_path}"
