# CodeSentinel — Upgrade 2A Acceptance Record

**Document Status:** FORMALLY VERIFIED & ACCEPTED (PASS WITH BLOCKERS)  
**Phase:** Upgrade 2A (External Security Knowledge Dataset Curation, Opt-In Ingestion & RAG Integration)  
**Date:** 2026-10-29  
**Repository:** `SARUKKESH-M/S5-MINI-PROJECT` (`c:\Users\admin\Downloads\SHE..! - Copy`)  
**Git Branch:** `main` | **HEAD Commit:** `132237540b3bf8081717b167c96e5eba4434028c`  
**Execution Environment:** Windows 11 (AMD64) | Python 3.14.6 | Pytest 9.1.1 | ChromaDB 0.4.x | SQLite 3.50.4  
**Phase Verdict:** **PASS WITH BLOCKERS** (MITRE CWE and CISA KEV verified and ready behind explicit opt-in; CVEfixes quarantined with a formal blocker)

---

## 1. Executive Summary & Purpose

This document provides the formal, evidence-based acceptance record for **Upgrade 2A (External Security Knowledge Curation and Opt-In Ingestion)** of the CodeSentinel platform.

Upgrade 2A establishes bounded, type-safe ingestion of external security threat intelligence and vulnerability weakness definitions into CodeSentinel's hybrid RAG pipeline without degrading deterministic AST authority, increasing false-positive rates, or regressing Upgrade 1 performance SLOs.

### Subsystem Highlights:
1. **Bounded Dataset Curation (`knowledge/curation.py`):**
   - **MITRE CWE:** Targets the 12 detector-supported CWEs unified with the MITRE Top 25 weaknesses (View 1430), extracting **exactly 26 unique weakness definitions** while skipping 943 out-of-scope weaknesses.
   - **CISA KEV:** Strictly filters the official KEV catalog by requiring an explicit match in the `cwes` field against the 12 supported detector CWEs. Evaluates **429 distinct CVEs** across **431 associations**, completely rejecting 175 missing-CWE records and 1,127 unsupported-CWE records without heuristic inference.
   - **Secret Scrubbing & Boundaries:** Multi-pattern regex sanitizer (`sanitize_sensitive_text`) masks PEM private keys, AWS tokens, JWTs, and passwords as `[REDACTED_SECRET]` prior to persistence. Enforces a hard `MAX_CONTENT_LENGTH = 4000` limit and deterministic SHA-256 fingerprinting.
2. **Opt-In Ingestion Pipeline (`rag/ingestion.py`):**
   - Controlled by `settings.ENABLE_EXTERNAL_KNOWLEDGE` (default `False`). Normal startup and analysis runs load only the core 12 OWASP curated documents.
   - `ingest_external_security_knowledge(sources=["mitre_cwe", "cisa_kev"])` performs bounded upserts in batches of 50 chunks (`EXTERNAL_INGESTION_BATCH_SIZE = 50`) reusing `_DOC_EMB_CACHE` embeddings.
   - Repeat ingestion is fully idempotent using stable chunk IDs and canonical chunk existence checks.
3. **CLI Integration (`cli/main.py`):**
   - Exposes `codesentinel ingest-knowledge [--sources] [--force] [--json]`.
   - Explicitly rejects unapproved sources and blocks `cvefixes` with exit code 1 and sanitized error formatting.
4. **CVEfixes Blocker & Quarantine:**
   - The 12.7 GB raw archive (`datasets/cvefixes/CVEfixes_v1.0.8.zip`) was kept compressed and unextracted to prevent disk space exhaustion and long test timeouts. CVEfixes is retained as a formal blocker for production ingestion until an authentic, uncompressed standalone SQLite slice is promoted.

---

## 2. Git Baseline, Environment & Protected Paths State

- **Branch:** `main` tracking `origin/main` at commit `132237540b3bf8081717b167c96e5eba4434028c`.
- **Staging State:** 0 files staged (`git add` avoided per audit/safety rules).
- **Protected Paths Status (Preserved Untouched & Untracked):**
  - `datasets/` (intact)
  - `knowledge/adapters/` (intact)
  - `scratch/` (intact)
  - `tests/test_cisa_kev_adapter.py` (intact)
  - `tests/test_cvefixes_adapter.py` (intact)
  - `tests/test_knowledge_dataset_integration.py` (intact)
  - `tests/test_mitre_cwe_adapter.py` (intact)

---

## 3. Exact Verification Test Results

### A. Complete Upgrade 2A Test Suite (70/70 Passed in 172.92s)
Command:
```powershell
$env:PYTHONPATH=".;backend"; backend\venv\Scripts\python.exe -m pytest tests/test_phase_upgrade_2a2_curation.py tests/test_phase_upgrade_2a4_ingestion.py tests/test_mitre_cwe_adapter.py tests/test_cisa_kev_adapter.py tests/test_cvefixes_adapter.py tests/test_knowledge_dataset_integration.py
```
Results:
- `tests/test_phase_upgrade_2a2_curation.py`: **11 passed**
- `tests/test_phase_upgrade_2a4_ingestion.py`: **8 passed**
- `tests/test_mitre_cwe_adapter.py`: **12 passed**
- `tests/test_cisa_kev_adapter.py`: **19 passed**
- `tests/test_cvefixes_adapter.py`: **15 passed**
- `tests/test_knowledge_dataset_integration.py`: **5 passed**
- **Total: 70 passed, 0 failed, 1 warning (deprecation) in 172.92s.**

### B. Upgrade 2 Regression Test Suite (196/196 Passed in 151.62s)
Command:
```powershell
$env:PYTHONPATH=".;backend"; backend\venv\Scripts\python.exe -m pytest tests/test_phase_upgrade_2b_rule_quality.py tests/test_phase_upgrade_2c_knowledge_relevance.py tests/test_github_resilience_idempotency.py tests/test_github_commit_idempotency.py tests/test_stage_7a_security_evidence.py tests/test_false_positives.py tests/test_phase_upgrade_2e_acceptance.py
```
Results:
- `tests/test_phase_upgrade_2b_rule_quality.py`: **13 passed**
- `tests/test_phase_upgrade_2c_knowledge_relevance.py`: **9 passed**
- `tests/test_github_resilience_idempotency.py`: **30 passed**
- `tests/test_github_commit_idempotency.py`: **25 passed**
- `tests/test_stage_7a_security_evidence.py`: **65 passed**
- `tests/test_false_positives.py`: **49 passed**
- `tests/test_phase_upgrade_2e_acceptance.py`: **5 passed**
- **Total: 196 passed, 0 failed, 4 warnings in 151.62s.**

### C. Upgrade 1 Performance Benchmark Verification
Command:
```powershell
$env:PYTHONPATH=".;backend"; backend\venv\Scripts\python.exe -m pytest -v tests/test_phase_upgrade_1_representative_benchmarks.py
```
All 6 benchmark workloads passed (`6 passed in 36.97s`). Direct empirical metric measurement:

| Benchmark Workload | Target SLO | Previous Baseline | Measured Value (Upgrade 2A-5) | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Large Repo Loading Latency** | Median $\le 150.00$ ms | $52.20$ ms | **$53.01$ ms** | **PASSED** |
| **Large Repo Loading Throughput** | $\ge 5,000.0$ files/s | $9,578.1$ files/s | **$9,432.8$ files/s** | **PASSED** |
| **Vulnerable-Analysis Median Latency** | Median $\le 4,000.00$ ms | $1,552.50$ ms | **$1,192.89$ ms** | **PASSED** |
| **Vulnerable-Analysis P95 Latency** | P95 $\le 5,000.00$ ms | $1,610.20$ ms | **$1,293.22$ ms** | **PASSED** |
| **Clean-Analysis Median Latency** | Informational | $145.10$ ms | **$143.30$ ms** | **PASSED** |

**Empirical Conclusion:** Zero performance degradation. Vulnerable-analysis latency improved to 1,192.89 ms, and large repository throughput remains well above the 5,000 files/s threshold at 9,432.8 files/s.

---

## 4. Dataset Counts & Ingestion Verification Evidence

1. **MITRE CWE Curation Counts:**
   - Catalog Weaknesses: 969.
   - CodeSentinel Supported Detector CWEs: 12.
   - MITRE Top 25 (View 1430): 25.
   - Target Deduplicated Set: **26 distinct CWEs** (verified: `CWE-20`, `CWE-22`, `CWE-77`, `CWE-78`, `CWE-79`, `CWE-89`, `CWE-94`, `CWE-119`, `CWE-125`, `CWE-190`, `CWE-200`, `CWE-269`, `CWE-287`, `CWE-306`, `CWE-327`, `CWE-352`, `CWE-400`, `CWE-416`, `CWE-434`, `CWE-476`, `CWE-502`, `CWE-787`, `CWE-798`, `CWE-862`, `CWE-863`, `CWE-918`).
2. **CISA KEV Curation Counts:**
   - Total Source Records: 1,731.
   - Records with Missing CWE: 175 (100% excluded without inference).
   - Records with Unsupported CWE: 1,127 (100% excluded without inference).
   - Distinct Matched CVEs: **429**.
   - Matched CWE Associations: **431** (`CVE-2024-7399` and `CVE-2025-2749` exhibit both `CWE-22` and `CWE-434`).
3. **Idempotency & Caching:**
   - Re-running `ingest_external_security_knowledge()` without `--force` returns `already_present=True` and skips vector generation.
   - Collection size remains strictly unchanged across duplicate runs.

---

## 5. Security Authority & Ingestion Invariants

1. **Advisory Role (`severity = None`):**
   - `CuratedMetadata` explicitly validates `self.severity is None`. Any attempt to assign severity raises `ValueError`.
   - In ChromaDB storage, `None` is safely preserved as an empty string `""` by `_clean_metadata_for_chroma()`.
   - External knowledge never overrides or inflates AST finding severity.
2. **Finding Invariance:**
   - Ingesting MITRE CWE and CISA KEV documents into `codesentinel_security_knowledge` does not alter AST detector verdicts, line mappings, review status (`passed`/`failed`), or security-gate exit codes.
3. **Fast-Path Curated Short-Circuit:**
   - `backend/analysis/finding_enrichment.py:135-150` executes `_find_exact_curated_knowledge()` first. Supported finding signals immediately short-circuit vector retrieval, protecting analysis latency.
4. **Context Quota Anti-Starvation:**
   - `rag/context_builder.py` enforces balanced candidate selection and `MAX_CONTEXT_DOCUMENTS = 20`. External knowledge documents occupy `context["security_knowledge"]` and cannot starve AST evidence.
5. **Frozen Step 6O Response Contract:**
   - The response schema remains strictly frozen: `analysis_id`, `status`, `repository`, `review_status`, `summary`, `findings`, `analysis_version`.

---

## 6. CVEfixes Blocker Analysis & Quarantine Policy

- **Artifact Inspection:** `datasets/cvefixes/CVEfixes_v1.0.8.zip` (12.7 GB compressed, ~30–50 GB decompressed SQL dump).
- **Prohibition Enforced:** The archive was not extracted, decompressed, or converted.
- **CLI & API Rejection:** Requesting `sources=["cvefixes"]` raises a descriptive error explaining that the 12.7 GB archive cannot be processed safely.
- **Fixture Strategy:** `CvefixesCurator` was validated against in-memory SQLite schemas (`tests/test_cvefixes_adapter.py` and `tests/test_phase_upgrade_2a2_curation.py`).
- **Prerequisite for Production Ingestion:** An authorized, standalone, uncompressed SQLite slice (~50–100 records for Python, JS, TS) must be placed in an unprotected tracked directory before CVEfixes can be added to production ingestion.

---

## 7. Remaining Limitations & Risk Mitigations

| Limitation | Impact | Safe Mitigation |
| :--- | :--- | :--- |
| **CVEfixes Production Ingestion Blocked** | Remediation examples from CVEfixes are not ingested in production. | Retained as a formal blocker. MITRE CWE and CISA KEV provide comprehensive advisory reference and threat intel. |
| **Cold-Start Embedding Time** | Embedding ~500 chunks takes ~2.5–3 minutes on CPU without GPU acceleration. | Disabled by default; explicit opt-in required; ChromaDB persistence and `_DOC_EMB_CACHE` prevent repeated embeddings. |
| **Quarantined Untracked Files** | Adapters and datasets remain untracked per sandbox rules. | All files validated in-place with zero modification or staging. |

---

## 8. Final Verdict

# `PASS WITH BLOCKERS`

**Summary of Acceptance:**
- **Upgrade 2A Test Suite:** 70 passed / 0 failed (100% pass rate).
- **Upgrade 2 Regression Suite:** 196 passed / 0 failed (100% pass rate).
- **Upgrade 1 Performance SLOs:** All approved targets verified (Large Repo Throughput: 9,432.8 files/s; Vulnerable Analysis Median: 1,192.89 ms).
- **Security Invariants:** Advisory-only severity, frozen Step 6O schema, and curated fast-path short-circuit fully intact.
- **Blocker:** CVEfixes 12.7 GB raw archive safely quarantined.

