# CodeSentinel — CVEfixes Curated Dataset Provenance & Attribution Manifest

**Dataset Identifier:** `codesentinel-cvefixes-curated-v1`  
**Artifact File:** `knowledge/data/cvefixes_curated.db`  
**Artifact Version:** 1.0.8-bounded-r2  
**Date Generated:** 2026-10-29  
**Status:** Cryptographically Verified, Sanitized & Bounded  

---

## 1. Upstream Dataset Attribution & Citation

This curated artifact is derived from the **CVEfixes** open-source vulnerability dataset.

- **Primary Authors:** Guru Bhandari, Amineh Naseer, and Dr. Leon Moonen  
- **Institutional Affiliation:** Simula Research Laboratory, Fornebu, Norway  
- **Peer-Reviewed Reference:**  
  > Guru Bhandari, Amineh Naseer, and Leon Moonen. 2021. *CVEfixes: automated collection of vulnerabilities and their fixes from open-source software*. In *Proceedings of the 17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE 2021)*. Association for Computing Machinery, New York, NY, USA, 30–39.  
- **Digital Object Identifier (DOI):** [https://doi.org/10.1145/3475960.3475985](https://doi.org/10.1145/3475960.3475985)  
- **Zenodo Archive Record:** [https://doi.org/10.5281/zenodo.4475478](https://doi.org/10.5281/zenodo.4475478)  
- **Upstream Release Version:** `v1.0.8` (released under Zenodo deposit 4475478)  
- **Official Project Repository:** [https://github.com/secureIT-project/CVEfixes](https://github.com/secureIT-project/CVEfixes)  
- **Upstream License:** **Creative Commons Attribution 4.0 International (CC BY 4.0)**  
  [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/)

---

## 2. Licensing, Embedded Code & Legal Notices

### Creative Commons Attribution 4.0 International (CC BY 4.0) Compliance
Under the terms of CC BY 4.0, CodeSentinel provides this dataset with appropriate attribution, link to license, and clear notice of modifications.

### Third-Party Embedded Code Notice
The code snippets, functions, and diffs embedded within this database originate from public open-source software repositories on GitHub (e.g., phpMyAdmin, Zope, jQuery UI, Node.js packages). 
- Embedded code samples retain their respective original upstream licenses (such as MIT, Apache 2.0, BSD-2/3-Clause, or GNU GPL/LGPL).
- All original copyright headers and author notices present in the source files are preserved verbatim within the `code_before` and `code_after` text fields.
- Redistribution and retrieval use of these code snippets are subject to their respective upstream licenses.

---

## 3. Cryptographic Hashes & Integrity

> [!IMPORTANT]
> The upstream publication provided the raw dataset as a 12.7 GB ZIP archive (`CVEfixes_v1.0.8.zip`) without an accompanying official upstream SHA-256 checksum file. All checksums below are locally calculated cryptographic hashes established to guarantee exact bit-for-bit reproducibility.

| Artifact Role | File Path | File Size (Bytes) | SHA-256 Checksum (Locally Calculated) |
| :--- | :--- | :--- | :--- |
| **Source Stream DB** | `scratch/cvefixes_stream_temp.db` | 3,491,495,936 | `89e7bc47b679c32ee0cebe6da3e03ba0a9557c446e917cf25dedb502418b49f3` |
| **Curated Output DB** | `knowledge/data/cvefixes_curated.db` | 634,880 | `e7f4700c5b5e4899389ad803b4c097174eccbe785c4c5919a69ef58d8be28d18` |

- **SQLite Integrity Check:** `ok` (`PRAGMA integrity_check`)

---

## 4. Selection Criteria & Scope

The curated subset was selected deterministically from the 4,804 authentic candidates matching all of the following rules:

1. **Target Language Scope:** Strictly limited to **Python**, **JavaScript**, and **TypeScript** (exactly 31 records each, total 93).
2. **Target Weakness Scope:** Strictly limited to the **12 CodeSentinel supported detector CWEs**:
   - `CWE-20` (Input Validation): 9 records
   - `CWE-22` (Path Traversal): 9 records
   - `CWE-78` (OS Command Injection): 9 records
   - `CWE-79` (Cross-Site Scripting): 9 records
   - `CWE-89` (SQL Injection): 9 records
   - `CWE-94` (Code Injection): 9 records
   - `CWE-287` (Improper Authentication): 8 records
   - `CWE-352` (Cross-Site Request Forgery): 9 records
   - `CWE-400` (Uncontrolled Resource Consumption): 6 records
   - `CWE-502` (Insecure Deserialization): 5 records
   - `CWE-798` (Hardcoded Credentials): 2 records
   - `CWE-918` (Server-Side Request Forgery): 9 records
3. **Data Completeness Requirements:**
   - Source code (`code_before`) and target code (`code_after`) must both be non-null and non-empty.
   - Unified line diff (`diff`) must be non-null and non-empty.
   - Genuine NVD vulnerability description (`cve.description`) must be non-null and non-empty.
   - Original developer commit message (`commits.msg`) and commit hash (`commits.hash`) must be non-null and non-empty.
4. **Stratified Deterministic Tie-Breaking:**
   - Candidate records prioritized by moderate snippet length ($100 \le \text{length} \le 3,000$ characters) for high pedagogical and retrieval quality.
   - Deterministic secondary sorting on `(cwe_id, programming_language, cve_id, hash, file_change_id)`.
   - Guaranteed unique CVE ID and unique `file_change_id` across all 93 records.

---

## 5. Modifications and Sanitization Notice

The records in this database have been transformed and sanitized as follows:
1. **NVD Description Normalization:** Raw stringified NVD JSON arrays (e.g. `[{'lang': 'en', 'value': '...'}]`) were unwrapped to extract clean, human-readable English advisory prose without altering semantic meaning.
2. **Sensitive Text Scrubbing:** All code snippets, commit messages, and text fields were processed through CodeSentinel's multi-pattern regex sanitizer (`sanitize_sensitive_text`) to redact private keys (PEM), API tokens (AWS, GitHub, Google), Bearer tokens, and passwords into `[REDACTED_SECRET]`.
3. **Content Boundary Enforcement:** Every normalized document is capped at `MAX_CONTENT_LENGTH = 4,000` characters to prevent context window starvation.
4. **Security Authority Invariant:** Baseline `severity` is strictly omitted (`severity = None`). This dataset provides advisory remediation examples only and never overrides deterministic AST finding severities.

---

## 6. Table Counts & Schema Summary

| Table Name | Record Count | Primary Key | Description |
| :--- | :--- | :--- | :--- |
| `fixes` | 93 | `(cve_id, hash)` | Maps authentic CVE ID to fixing commit hash and repository URL |
| `commits` | 93 | `hash` | Authentic commit author, timestamp, and developer commit message |
| `file_change` | 93 | `file_change_id` | Changed file path, `code_before`, `code_after`, and unified `diff` |
| `method_change` | 0 | `method_change_id` | Method-level changes table (schema-compatible, zero rows) |
| `cve` | 93 | `cve_id` | Authentic NVD description and publication date |
| `cwe_classification`| 93 | `(cve_id, cwe_id)` | Explicit weakness classification (12 supported CWEs only) |
| `repository` | 88 | `repo_url` | Originating open-source repository slug and URL |

---

## 7. Version Control, Packaging & Reproduction Instructions

### Version Control & Gitignore Architecture
- **Tracked Artifacts:** The deterministic extraction script (`knowledge/data/extract_cvefixes_subset.py`) and this provenance manifest (`knowledge/data/CVEFIXES_PROVENANCE.md`) are explicitly whitelisted in `.gitignore` (`!knowledge/data/*.py`, `!knowledge/data/*.md`) and tracked in Git.
- **Git-Ignored Binary Database:** The compiled binary database (`knowledge/data/cvefixes_curated.db`) is intentionally ignored by `.gitignore` (`*.db`) to avoid committing binary databases to repository history.
- **Fresh Checkout Behavior:** A fresh checkout of CodeSentinel contains the extraction script and provenance documentation, but does not bundle the generated `.db` file.
- **Production Safety Invariant:** Production external security knowledge ingestion remains strictly disabled by default (`ENABLE_EXTERNAL_KNOWLEDGE=False` in `backend/app/core/config.py`). Furthermore, `cvefixes` is explicitly excluded from production knowledge ingestion routines. Therefore, the absence of `knowledge/data/cvefixes_curated.db` in a fresh checkout has zero impact on core static security analysis, AST findings, security gates, or production operation.

### Regeneration from Authenticated Source Stream
To regenerate the exact 93-record SQLite database on a local machine:

#### Prerequisites
- Access to the authenticated parent stream database (`scratch/cvefixes_stream_temp.db`, SHA-256: `89e7bc47b679c32ee0cebe6da3e03ba0a9557c446e917cf25dedb502418b49f3`).
- Python 3.10+ (tested with Python 3.14.6)
- SQLite 3.35+ (with JSON and URI filename support)
- Workspace virtual environment with CodeSentinel dependencies installed

#### Execution Command
```powershell
python knowledge/data/extract_cvefixes_subset.py --force
```

#### Cryptographic Verification
```powershell
python -c "import hashlib; print(hashlib.sha256(open('knowledge/data/cvefixes_curated.db','rb').read()).hexdigest())"
```
**Expected Output:** `e7f4700c5b5e4899389ad803b4c097174eccbe785c4c5919a69ef58d8be28d18`

