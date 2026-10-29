"""CodeSentinel Upgrade 2A-2: Bounded Dataset Curation Layer.

Implements bounded, type-safe filtering, deduplication, secret scrubbing, and schema
validation for external security knowledge sources (MITRE CWE, CISA KEV, and CVEfixes).

Architectural Invariants:
1. Security Authority Invariant: External knowledge sources are advisory only.
   Metadata 'severity' MUST remain None. External sources never override or inflate
   deterministic AST finding severity.
2. Controlled Granularity:
   - MITRE CWE: Exact 12 supported CodeSentinel CWEs plus MITRE Top 25 entries (26 unique CWEs).
   - CISA KEV: Only explicit, exact matches to the 12 supported CWEs (no heuristic inference).
   - CVEfixes: Python, JavaScript, TypeScript only; 12 supported CWEs; max 100 records.
3. Content & Sanitization Limits:
   - Maximum content length strictly capped at 4,000 characters.
   - Sensitive tokens, credentials, and keys scrubbed prior to persistence or indexing.
   - Deterministic SHA-256 content fingerprints (no Python randomized hash).
4. Zero Coupling & Isolation:
   - Read-only data access; no modifications to raw archives or source datasets.
   - Zero side-effects on AST engine, security gates, or frozen Step 6O API response schemas.
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
import zipfile

# ---------------------------------------------------------------------------
# Constants and Ontological Scope
# ---------------------------------------------------------------------------

MAX_CONTENT_LENGTH = 4000

# Canonical set of 12 supported CWE IDs across CodeSentinel's deterministic detectors
SUPPORTED_CWES: Set[str] = {
    "CWE-89",   # SQL Injection
    "CWE-78",   # OS Command Injection
    "CWE-798",  # Hardcoded Credentials
    "CWE-22",   # Path Traversal
    "CWE-502",  # Insecure Deserialization
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-327",  # Broken / Risky Cryptography
    "CWE-306",  # Missing Authentication
    "CWE-352",  # Cross-Site Request Forgery (CSRF)
    "CWE-434",  # Unrestricted File Upload
    "CWE-200",  # Information Exposure
    "CWE-476",  # NULL Pointer Dereference
}

# Supported programming languages for remediation fixes
SUPPORTED_LANGUAGES: Set[str] = {"python", "javascript", "typescript", "agnostic"}

# Canonical Document Types
VALID_DOC_TYPES: Set[str] = {"reference", "threat_intel", "remediation_example"}

# Canonical Sources
VALID_SOURCES: Set[str] = {"mitre_cwe", "cisa_kev", "cvefixes"}


# ---------------------------------------------------------------------------
# Secret Scrubbing & Redaction
# ---------------------------------------------------------------------------

# Multi-pattern regex for scrubbing credentials, tokens, private keys, and passwords
_AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_AWS_SECRET_REGEX = re.compile(
    r"(?i)((?:aws_secret_access_key|aws_access_key|aws_secret)\s*[:=]\s*['\"]?)[A-Za-z0-9/+=]{40}(['\"]?)"
)
_JWT_REGEX = re.compile(
    r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"
)
_PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_PASSWORD_OR_KEY_REGEX = re.compile(
    r"(?i)(\b[a-zA-Z0-9_]*(?:password|passwd|pwd|api_key|apikey|secret|token)\s*[:=]\s*['\"])[^'\"]{4,}(['\"])"
)
_STANDARD_TOKEN_REGEX = re.compile(
    r"(ghp_[a-zA-Z0-9_]{16,255}|gho_[a-zA-Z0-9_]{16,255}|github_pat_[a-zA-Z0-9_]{16,255}|gsk_[a-zA-Z0-9_]{16,255}|bearer\s+[a-zA-Z0-9._\-]+|secret_[a-zA-Z0-9_]{4,}|sess_[a-fA-F0-9]{16,}|session_[a-zA-Z0-9_]{16,})",
    re.IGNORECASE,
)

REDACTED_PLACEHOLDER = "[REDACTED_SECRET]"


def sanitize_sensitive_text(text: Optional[str]) -> str:
    """Mask known sensitive token literals, private keys, and credentials from text.

    Uses comprehensive multi-pattern matching for private keys, AWS credentials,
    JWTs, hardcoded passwords/secrets, and standard GitHub/vendor token literals.
    """
    if not text or not isinstance(text, str):
        return ""

    sanitized = text

    # 1. Private keys (full PEM blocks)
    sanitized = _PRIVATE_KEY_REGEX.sub(REDACTED_PLACEHOLDER, sanitized)

    # 2. Key-value credentials and secrets (run before token regex to avoid corrupting key names)
    sanitized = _AWS_SECRET_REGEX.sub(r"\g<1>[REDACTED_SECRET]\g<2>", sanitized)
    sanitized = _PASSWORD_OR_KEY_REGEX.sub(r"\g<1>[REDACTED_SECRET]\g<2>", sanitized)

    # 3. AWS Access Key IDs
    sanitized = _AWS_KEY_REGEX.sub(REDACTED_PLACEHOLDER, sanitized)

    # 4. JWT tokens
    sanitized = _JWT_REGEX.sub(REDACTED_PLACEHOLDER, sanitized)

    # 5. Core security tokens and GitHub/vendor tokens
    sanitized = _STANDARD_TOKEN_REGEX.sub(REDACTED_PLACEHOLDER, sanitized)

    try:
        from backend.app.core.security import sanitize_sensitive_text as _core_sanitize
        sanitized = _core_sanitize(sanitized)
    except Exception:
        try:
            from app.core.security import sanitize_sensitive_text as _core_sanitize
            sanitized = _core_sanitize(sanitized)
        except Exception:
            pass

    return sanitized


def compute_sha256(text: str) -> str:
    """Compute deterministic SHA-256 fingerprint for arbitrary content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Metadata and Curated Document Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CuratedMetadata:
    """Strictly validated metadata schema for curated knowledge documents."""

    source: str
    cwe_id: str
    language: str
    doc_type: str
    cve_id: Optional[str] = None
    severity: None = None  # Security Authority Invariant: always None

    def __post_init__(self) -> None:
        if self.source not in VALID_SOURCES:
            raise ValueError(f"Invalid source '{self.source}'. Must be one of {VALID_SOURCES}")
        if not self.cwe_id or not self.cwe_id.startswith("CWE-"):
            raise ValueError(f"Invalid cwe_id '{self.cwe_id}'. Must start with 'CWE-'")
        if self.language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Invalid language '{self.language}'. Must be one of {SUPPORTED_LANGUAGES}")
        if self.doc_type not in VALID_DOC_TYPES:
            raise ValueError(f"Invalid doc_type '{self.doc_type}'. Must be one of {VALID_DOC_TYPES}")
        if self.severity is not None:
            raise ValueError("Security Authority Violation: severity must strictly remain None")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to ChromaDB-safe primitive dictionary."""
        d: Dict[str, Any] = {
            "source": self.source,
            "cwe_id": self.cwe_id,
            "language": self.language,
            "doc_type": self.doc_type,
            "document_type": "security_knowledge",
            "schema_version": "1.0",
        }
        if self.cve_id:
            d["cve_id"] = self.cve_id
        return d


@dataclass
class CuratedDocument:
    """Canonical representation of a curated external security document."""

    document_id: str
    content: str
    metadata: CuratedMetadata
    content_hash: str
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to standard CodeSentinel knowledge document representation."""
        meta = self.metadata.to_dict()
        meta.update(self.extra_metadata)
        return {
            "document_id": self.document_id,
            "content": self.content,
            "content_hash": self.content_hash,
            "metadata": meta,
        }


# ---------------------------------------------------------------------------
# 1. MITRE CWE Bounded Curator
# ---------------------------------------------------------------------------

class MitreCweCurator:
    """Curates a bounded subset of MITRE CWE definitions.

    Extracts exactly the 12 supported CodeSentinel CWEs plus the MITRE Top 25
    weaknesses, resulting in a deduplicated target set of 26 unique CWEs.
    """

    def __init__(self, supported_cwes: Optional[Set[str]] = None):
        self.supported_cwes = set(supported_cwes) if supported_cwes else set(SUPPORTED_CWES)

    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    @staticmethod
    def _clean_text(elem: Any) -> str:
        if elem is None:
            return ""
        if isinstance(elem, str):
            raw = elem
        elif hasattr(elem, "itertext"):
            raw = "".join(elem.itertext())
        else:
            raw = str(elem)
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        return " ".join(lines).strip()

    def discover_top_25_cwes(self, root: ET.Element) -> Set[str]:
        """Discover Top 25 CWE IDs from catalog Views in the XML tree.

        Prefers View 1430 (2024 Top 25) or View 1425 (2023 Top 25) or the latest Top 25 View.
        """
        ns = "{http://cwe.mitre.org/cwe-7}"
        views = root.findall(f"{ns}Views/{ns}View")
        top_25_views = {}
        for v in views:
            v_id = v.get("ID", "")
            name = v.get("Name", "")
            if "Top 25" in name and "CWE" in name:
                members = set()
                for m in v.findall(f"{ns}Members/{ns}Has_Member"):
                    cwe_num = m.get("CWE_ID")
                    if cwe_num:
                        members.add(f"CWE-{cwe_num}")
                if len(members) >= 20:
                    top_25_views[v_id] = members

        # Prefer View 1430 (2024), then 1425 (2023), else largest view found
        if "1430" in top_25_views:
            return top_25_views["1430"]
        if "1425" in top_25_views:
            return top_25_views["1425"]
        if top_25_views:
            # Pick the one with the highest integer view ID
            best_id = max(top_25_views.keys(), key=lambda x: int(x) if x.isdigit() else 0)
            return top_25_views[best_id]

        # Fallback to static 2024 Top 25 if views not declared
        return {
            "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78",
            "CWE-416", "CWE-862", "CWE-434", "CWE-94", "CWE-20", "CWE-77", "CWE-287",
            "CWE-269", "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119", "CWE-476",
            "CWE-798", "CWE-190", "CWE-400", "CWE-306"
        }

    def curate_from_xml_root(self, root: ET.Element) -> List[CuratedDocument]:
        """Curate definitions from an ElementTree root."""
        ns = "{http://cwe.mitre.org/cwe-7}"
        top_25_cwes = self.discover_top_25_cwes(root)
        target_cwes = self.supported_cwes.union(top_25_cwes)

        weaknesses = root.findall(f"{ns}Weaknesses/{ns}Weakness")
        curated_docs: List[CuratedDocument] = []
        seen_cwes: Set[str] = set()

        for w in weaknesses:
            w_id = w.get("ID")
            if not w_id:
                continue
            canonical_cwe = f"CWE-{w_id.strip()}"
            if canonical_cwe not in target_cwes or canonical_cwe in seen_cwes:
                continue

            seen_cwes.add(canonical_cwe)
            name = w.get("Name", "").strip()

            desc_elem = w.find(f"{ns}Description")
            ext_desc_elem = w.find(f"{ns}Extended_Description")
            description = self._clean_text(desc_elem)
            ext_description = self._clean_text(ext_desc_elem)

            # Mitigations
            mitigations: List[str] = []
            for mit in w.findall(f"{ns}Potential_Mitigations/{ns}Mitigation"):
                m_desc = self._clean_text(mit.find(f"{ns}Description"))
                if m_desc:
                    mitigations.append(m_desc)

            # Demonstrative Examples
            examples: List[str] = []
            for ex in w.findall(f"{ns}Demonstrative_Examples/{ns}Demonstrative_Example"):
                intro = self._clean_text(ex.find(f"{ns}Intro_Text"))
                body = self._clean_text(ex.find(f"{ns}Example_Code"))
                if intro or body:
                    examples.append(f"{intro}\n{body}".strip())

            # Build curated content body
            content_parts = [
                f"# {canonical_cwe}: {name}",
                f"**Description**: {description}",
            ]
            if ext_description:
                content_parts.append(f"**Details**: {ext_description}")
            if mitigations:
                content_parts.append("**Mitigations**:\n" + "\n".join(f"- {m}" for m in mitigations[:3]))
            if examples:
                content_parts.append("**Example**:\n" + examples[0])

            raw_content = "\n\n".join(content_parts)
            sanitized_content = sanitize_sensitive_text(raw_content)

            # Truncate to MAX_CONTENT_LENGTH
            if len(sanitized_content) > MAX_CONTENT_LENGTH:
                sanitized_content = sanitized_content[: MAX_CONTENT_LENGTH - 3].rstrip() + "..."

            metadata = CuratedMetadata(
                source="mitre_cwe",
                cwe_id=canonical_cwe,
                language="agnostic",
                doc_type="reference",
                severity=None,
            )

            content_hash = compute_sha256(sanitized_content)
            curated_docs.append(
                CuratedDocument(
                    document_id=f"knowledge_mitre_cwe_{canonical_cwe}",
                    content=sanitized_content,
                    metadata=metadata,
                    content_hash=content_hash,
                    extra_metadata={
                        "title": f"{canonical_cwe}: {name}",
                        "is_top_25": canonical_cwe in top_25_cwes,
                        "is_supported": canonical_cwe in self.supported_cwes,
                    },
                )
            )

        # Sort deterministically by numeric CWE ID
        curated_docs.sort(key=lambda d: int(d.metadata.cwe_id.split("-")[1]))
        return curated_docs

    def curate_from_zip(self, zip_path: str) -> List[CuratedDocument]:
        """Curate directly from the MITRE CWE ZIP archive."""
        if not os.path.isfile(zip_path):
            raise FileNotFoundError(f"MITRE CWE zip archive not found at: {zip_path}")
        with zipfile.ZipFile(zip_path, "r") as z:
            names = [n for n in z.namelist() if n.endswith(".xml")]
            if not names:
                raise ValueError("No XML files found inside MITRE CWE zip archive")
            with z.open(names[0]) as f:
                tree = ET.parse(f)
                return self.curate_from_xml_root(tree.getroot())

    def curate_from_xml_string(self, xml_content: str) -> List[CuratedDocument]:
        """Curate from an XML text string (for testing and isolated fixtures)."""
        root = ET.fromstring(xml_content)
        return self.curate_from_xml_root(root)


# ---------------------------------------------------------------------------
# 2. CISA KEV Bounded Curator
# ---------------------------------------------------------------------------

@dataclass
class CisaKevCuratorStats:
    """Detailed accounting for CISA KEV curation."""

    total_source_records: int = 0
    missing_cwe_records: int = 0
    unsupported_cwe_records: int = 0
    distinct_matched_cves: int = 0
    matched_cwe_associations: int = 0


class CisaKevCurator:
    """Curates a bounded subset of the CISA KEV catalog.

    Accepts ONLY records having an explicit, exact match to one of the 12 supported
    CWE IDs. Missing and unsupported CWE associations are excluded without inference.
    Deduplicates records by CVE ID while preserving all matched supported CWEs.
    """

    def __init__(self, supported_cwes: Optional[Set[str]] = None):
        self.supported_cwes = set(supported_cwes) if supported_cwes else set(SUPPORTED_CWES)

    def curate(self, csv_reader: Iterable[Dict[str, str]]) -> Tuple[List[CuratedDocument], CisaKevCuratorStats]:
        """Curate KEV records from a DictReader iterable."""
        stats = CisaKevCuratorStats()
        cve_map: Dict[str, Dict[str, Any]] = {}
        cve_cwes: Dict[str, List[str]] = {}

        for row in csv_reader:
            stats.total_source_records += 1
            raw_cve = row.get("cveID", "").strip()
            if not raw_cve:
                continue

            cve_id = raw_cve.upper()
            raw_cwes = row.get("cwes", "").strip()

            if not raw_cwes:
                stats.missing_cwe_records += 1
                continue

            # Split possible multiple CWEs (e.g. "CWE-119, CWE-787")
            tokens = [t.strip().upper() for t in raw_cwes.replace(";", ",").split(",") if t.strip()]
            matched_cwes = [t for t in tokens if t in self.supported_cwes]

            if not matched_cwes:
                stats.unsupported_cwe_records += 1
                continue

            if cve_id not in cve_map:
                cve_map[cve_id] = row
                cve_cwes[cve_id] = []

            for cwe in matched_cwes:
                if cwe not in cve_cwes[cve_id]:
                    cve_cwes[cve_id].append(cwe)
                    stats.matched_cwe_associations += 1

        stats.distinct_matched_cves = len(cve_map)

        curated_docs: List[CuratedDocument] = []
        for cve_id in sorted(cve_map.keys()):
            row = cve_map[cve_id]
            cwes = cve_cwes[cve_id]
            primary_cwe = cwes[0]

            vendor = row.get("vendorProject", "").strip()
            product = row.get("product", "").strip()
            vuln_name = row.get("vulnerabilityName", "").strip()
            desc = row.get("shortDescription", "").strip()
            action = row.get("requiredAction", "").strip()
            date_added = row.get("dateAdded", "").strip()
            notes = row.get("notes", "").strip()

            content_lines = [
                f"# {cve_id}: {vuln_name or product}",
                f"**Vendor/Product**: {vendor} {product}".strip(),
                f"**CWE Associations**: {', '.join(cwes)}",
                f"**Date Added to KEV**: {date_added}",
                f"**Description**: {desc}",
                f"**Required Remediation**: {action}",
            ]
            if notes:
                content_lines.append(f"**Notes**: {notes}")

            raw_content = "\n\n".join(content_lines)
            sanitized = sanitize_sensitive_text(raw_content)

            if len(sanitized) > MAX_CONTENT_LENGTH:
                sanitized = sanitized[: MAX_CONTENT_LENGTH - 3].rstrip() + "..."

            metadata = CuratedMetadata(
                source="cisa_kev",
                cwe_id=primary_cwe,
                cve_id=cve_id,
                language="agnostic",
                doc_type="threat_intel",
                severity=None,
            )

            content_hash = compute_sha256(sanitized)
            curated_docs.append(
                CuratedDocument(
                    document_id=f"knowledge_cisa_kev_{cve_id}",
                    content=sanitized,
                    metadata=metadata,
                    content_hash=content_hash,
                    extra_metadata={
                        "all_matching_cwes": cwes,
                        "vendor_project": vendor,
                        "product": product,
                        "is_cisa_kev": True,
                    },
                )
            )

        return curated_docs, stats

    def curate_from_file(self, file_path: str) -> Tuple[List[CuratedDocument], CisaKevCuratorStats]:
        """Curate from a CSV file path."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"CISA KEV CSV not found at: {file_path}")
        with open(file_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            return self.curate(reader)

    def curate_from_csv_string(self, csv_content: str) -> Tuple[List[CuratedDocument], CisaKevCuratorStats]:
        """Curate from a CSV string."""
        f = io.StringIO(csv_content.strip())
        reader = csv.DictReader(f)
        return self.curate(reader)


# ---------------------------------------------------------------------------
# 3. CVEfixes Bounded Curator & Safe Fixture Strategy
# ---------------------------------------------------------------------------

class CvefixesCurator:
    """Curates a safe, bounded subset from an SQLite CVEfixes database connection or file.

    Enforces:
    1. Languages: Python, JavaScript, TypeScript only.
    2. CWEs: Supported 12 CWEs only.
    3. Max Records: At most 100 entries.
    4. Secret Sanitization: Scrubbing before saving.
    5. Length Limit: Max 4,000 characters per document.
    6. Severity: Strictly None.
    """

    def __init__(self, supported_cwes: Optional[Set[str]] = None):
        self.supported_cwes = set(supported_cwes) if supported_cwes else set(SUPPORTED_CWES)
        self.supported_languages = {"python", "javascript", "typescript"}

    def curate_from_db(self, conn: sqlite3.Connection, limit: int = 100) -> List[CuratedDocument]:
        """Curate vulnerability fixing records from an SQLite database connection."""
        limit = min(limit, 100)
        cur = conn.cursor()

        # Query joins fixes, commits, file_change, method_change, cve, and cwe_classification
        query = """
        SELECT
            fc.file_change_id,
            fc.programming_language,
            fc.filename,
            f.cve_id,
            cwe.cwe_id,
            c.msg,
            fc.code_before,
            fc.code_after,
            mc.name as method_name,
            mc.code as method_code,
            mc.before_change
        FROM file_change fc
        JOIN fixes f ON fc.hash = f.hash
        LEFT JOIN commits c ON fc.hash = c.hash
        LEFT JOIN cwe_classification cwe ON f.cve_id = cwe.cve_id
        LEFT JOIN method_change mc ON fc.file_change_id = mc.file_change_id
        WHERE fc.programming_language IS NOT NULL
        ORDER BY f.cve_id, fc.file_change_id
        """

        try:
            cur.execute(query)
            rows = cur.fetchall()
        except sqlite3.OperationalError:
            # Table might not exist in an uninitialized DB
            return []

        curated_docs: List[CuratedDocument] = []
        seen_keys: Set[str] = set()

        for row in rows:
            if len(curated_docs) >= limit:
                break

            (
                file_change_id,
                raw_lang,
                filename,
                raw_cve,
                raw_cwe,
                commit_msg,
                code_before,
                code_after,
                method_name,
                method_code,
                before_change,
            ) = row

            lang = str(raw_lang).strip().lower()
            if lang not in self.supported_languages:
                continue

            cwe_id = str(raw_cwe).strip().upper() if raw_cwe else ""
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}" if cwe_id.isdigit() else ""
            if cwe_id not in self.supported_cwes:
                continue

            cve_id = str(raw_cve).strip().upper() if raw_cve else "CVE-UNKNOWN"

            # Deduplication key
            dedup_key = f"{cve_id}_{cwe_id}_{file_change_id}_{method_name or ''}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Construct remediation example content
            parts = [
                f"# Vulnerability Remediation: {cve_id} ({cwe_id})",
                f"**Language**: {lang.title()}",
                f"**File**: {filename or 'unknown'}",
            ]
            if commit_msg:
                parts.append(f"**Commit Message**: {commit_msg.strip()}")

            if method_name:
                parts.append(f"**Method**: {method_name}")

            if code_before and str(code_before).strip():
                parts.append(f"```\n// Vulnerable Context\n{str(code_before).strip()}\n```")
            if code_after and str(code_after).strip():
                parts.append(f"```\n// Fixed Context\n{str(code_after).strip()}\n```")
            elif method_code and str(method_code).strip():
                state = "Before Fix" if str(before_change).lower() in ("true", "1") else "After Fix"
                parts.append(f"```\n// Code ({state})\n{str(method_code).strip()}\n```")

            raw_content = "\n\n".join(parts)
            sanitized = sanitize_sensitive_text(raw_content)

            if len(sanitized) > MAX_CONTENT_LENGTH:
                sanitized = sanitized[: MAX_CONTENT_LENGTH - 3].rstrip() + "..."

            metadata = CuratedMetadata(
                source="cvefixes",
                cwe_id=cwe_id,
                cve_id=cve_id,
                language=lang,
                doc_type="remediation_example",
                severity=None,
            )

            content_hash = compute_sha256(sanitized)
            doc_id = f"knowledge_cvefixes_{cve_id}_{cwe_id}_{len(curated_docs) + 1}"
            curated_docs.append(
                CuratedDocument(
                    document_id=doc_id,
                    content=sanitized,
                    metadata=metadata,
                    content_hash=content_hash,
                    extra_metadata={
                        "filename": filename or "",
                        "method_name": method_name or "",
                    },
                )
            )

        return curated_docs
