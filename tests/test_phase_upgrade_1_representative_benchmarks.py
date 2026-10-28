"""CodeSentinel Upgrade 1 — Representative Performance Benchmark Coverage Suite.

Establishes reproducible, empirical benchmarks for representative CodeSentinel workloads:
1. Analysis Cache: Hit, Miss, and LRU Churn Behavior.
2. Repository File Loading: Multi-size synthetic repositories (Small, Medium, Large) with exclusion pruning.
3. End-to-End Analysis Latency: Representative Clean, Vulnerable, and Cached repositories (AST + Taint + RAG + Step 6O Report).
4. RAG Retrieval & Context Ranking Latency: Standalone query execution over curated knowledge base.
5. Database Persistence Latency: Batched executemany vs row-by-row insertion across finding counts (1, 50, 200, 500).
6. Concurrent Analysis Throughput & Error Rate: Multi-worker isolated repository analysis under concurrent load.

Design & Safeguards:
- 100% isolated inside temporary directories and isolated temporary SQLite files.
- Never reads from or writes to the shared production database.
- Separates warm-up iterations from measured iterations.
- Collects repeated measurements with mean, median, p95, and stddev metrics.
- Uses functional assertions in CI tests and detailed statistical reporting in standalone mode.
- Preserves all frozen Step 6O report fields and security invariants.
"""

from dataclasses import dataclass, field
import gc
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

# Ensure workspace root and backend are on sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_ROOT = os.path.join(WORKSPACE_ROOT, "backend")
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from tests.test_phase_upgrade_1e_benchmark_harness import (
    BenchmarkMetric,
    compute_p95,
    run_workload_iterations,
)
from backend.analysis.cache import AnalysisCache
from backend.repository.acquirer import acquire_repository
from backend.repository.analyzer import prepare_repository_analysis_files
from backend.analysis.repository_orchestrator import analyze_repository
from backend.analysis.storage.store import (
    AnalysisStore,
    reset_database_initialization_cache,
    sanitize_finding_record,
    create_analysis_record,
    get_utc_now_iso,
)
from rag.context_builder import build_security_analysis_context, MAX_CONTEXT_DOCUMENTS
from rag.ingestion import (
    ensure_curated_knowledge_ingested,
    reset_curated_knowledge_cache,
)
from rag.vector_store import (
    generate_transient_ast_collection_name,
    delete_transient_collection,
)


# =============================================================================
# Pytest Database Isolation Safeguards
# =============================================================================

@pytest.fixture(autouse=True)
def clean_webhook_deliveries():
    """Override global clean_webhook_deliveries so this benchmark module never touches the shared database."""
    yield


@pytest.fixture(autouse=True)
def isolate_benchmark_database(tmp_path, monkeypatch):
    """Ensure all benchmarks in this module operate on an isolated temporary SQLite database."""
    reset_database_initialization_cache()
    db_file = str(tmp_path / "benchmark_isolated.db")
    monkeypatch.setenv("CODESENTINEL_DB_PATH", db_file)
    store = AnalysisStore(db_path=db_file)
    store.initialize()
    yield db_file
    reset_database_initialization_cache()


# =============================================================================
# WORKLOAD 1: Analysis Cache Hit, Miss, and LRU Churn Behavior
# =============================================================================

def benchmark_cache_hit_and_miss(iterations: int = 10) -> Tuple[BenchmarkMetric, BenchmarkMetric, BenchmarkMetric, BenchmarkMetric, Dict[str, Any]]:
    """Evaluates cold cache population, warm hit latency, non-existent miss latency, and LRU eviction churn."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        cache_dir = os.path.join(temp_dir, "cache_bench")
        cache = AnalysisCache(cache_dir=cache_dir, max_entries=500)

        # 1. Cold Cache Population Workload
        items_100 = [
            (
                f"file_{i}.py",
                hashlib.sha256(f"content_{i}".encode()).hexdigest(),
                {"status": "success", "findings": [{"id": f"f_{i}", "severity": "HIGH"}]},
            )
            for i in range(100)
        ]

        def run_cold():
            fresh_dir = os.path.join(temp_dir, f"cold_{time.time_ns()}")
            c = AnalysisCache(cache_dir=fresh_dir, max_entries=500)
            for f_path, f_hash, payload in items_100:
                k = c.generate_cache_key(f_path, f_hash)
                c.set(k, payload)
                _ = c.get(k)

        cold_m = run_workload_iterations(
            workload_id="WL-U1-CACHE-COLD",
            name="Cold Cache Set and Get (100 items)",
            iteration_fn=run_cold,
            iterations=iterations,
        )

        # 2. Warm Cache Hits (100% hits in memory)
        warm_cache = AnalysisCache(cache_dir=os.path.join(temp_dir, "warm_bench"), max_entries=500)
        keys_100 = []
        for f_path, f_hash, payload in items_100:
            k = warm_cache.generate_cache_key(f_path, f_hash)
            warm_cache.set(k, payload)
            keys_100.append(k)

        def run_hits():
            for k in keys_100:
                res = warm_cache.get(k)
                assert res is not None

        hit_m = run_workload_iterations(
            workload_id="WL-U1-CACHE-HIT",
            name="Analysis Cache Hits (100 items, in-memory)",
            iteration_fn=run_hits,
            iterations=iterations,
        )

        # 3. Pure Cache Misses (100 non-existent keys)
        miss_keys_100 = [f"missing_key_{i}_{time.time_ns()}" for i in range(100)]

        def run_misses():
            for k in miss_keys_100:
                res = warm_cache.get(k)
                assert res is None

        miss_m = run_workload_iterations(
            workload_id="WL-U1-CACHE-MISS",
            name="Analysis Cache Misses (100 non-existent keys)",
            iteration_fn=run_misses,
            iterations=iterations,
        )

        # 4. LRU Eviction Churn (1,000 entries into capacity 500)
        def run_churn():
            c = AnalysisCache(cache_dir=os.path.join(temp_dir, f"churn_{time.time_ns()}"), max_entries=500)
            for i in range(1000):
                c.set(f"k_{i}", {"data": "x" * 64})
            assert len(c._memory_cache) == 500

        churn_m = run_workload_iterations(
            workload_id="WL-U1-CACHE-CHURN",
            name="LRU Eviction Churn (1,000 entries into capacity 500)",
            iteration_fn=run_churn,
            iterations=iterations,
        )

        hit_speedup_pct = (
            ((cold_m.median_ms - hit_m.median_ms) / cold_m.median_ms) * 100.0
            if cold_m.median_ms > 0
            else 0.0
        )

        summary = {
            "cold_median_ms": cold_m.median_ms,
            "hit_median_ms": hit_m.median_ms,
            "miss_median_ms": miss_m.median_ms,
            "churn_median_ms": churn_m.median_ms,
            "hit_speedup_vs_cold_pct": hit_speedup_pct,
            "miss_under_1ms": miss_m.median_ms < 1.0,
        }
        return cold_m, hit_m, miss_m, churn_m, summary


# =============================================================================
# WORKLOAD 2: Repository File Loading at Multiple Sizes
# =============================================================================

def _build_synthetic_repo(base_dir: str, num_src_files: int, num_ignored_dirs: int, files_per_ignored_dir: int) -> str:
    """Constructs a deterministic synthetic repository with source files and excluded directories."""
    repo_dir = os.path.join(base_dir, f"repo_{num_src_files}")
    src_dir = os.path.join(repo_dir, "src")
    os.makedirs(src_dir, exist_ok=True)

    for i in range(num_src_files):
        with open(os.path.join(src_dir, f"module_{i}.py"), "w", encoding="utf-8") as f:
            f.write(f"def func_{i}(x):\n    # Synthetic function {i}\n    return x + {i}\n")

    standard_excluded = ["node_modules", ".venv", "dist", "build", "target"]
    for d in range(num_ignored_dirs):
        ign_name = standard_excluded[d % len(standard_excluded)]
        ign_dir = os.path.join(repo_dir, ign_name)
        os.makedirs(ign_dir, exist_ok=True)
        for j in range(files_per_ignored_dir):
            with open(os.path.join(ign_dir, f"dummy_{j}.js"), "w", encoding="utf-8") as f:
                f.write(f"// Ignored file {j}\nconsole.log({j});\n")

    return repo_dir


def benchmark_file_loading_multi_size(iterations: int = 10) -> Tuple[BenchmarkMetric, BenchmarkMetric, BenchmarkMetric, Dict[str, Any]]:
    """Evaluates repository file loading across Small (20 files), Medium (100 files), and Large (500 files + 1000 excluded)."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        small_repo = _build_synthetic_repo(temp_dir, 20, 2, 5)
        med_repo = _build_synthetic_repo(temp_dir, 100, 3, 20)
        large_repo = _build_synthetic_repo(temp_dir, 500, 1, 1000)

        acq_small = acquire_repository(
            repository_url="https://github.com/example/small.git",
            local_path=small_repo,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        acq_med = acquire_repository(
            repository_url="https://github.com/example/med.git",
            local_path=med_repo,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        acq_large = acquire_repository(
            repository_url="https://github.com/example/large.git",
            local_path=large_repo,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        # Small
        def run_small():
            _, files, stats = prepare_repository_analysis_files(acq_small, workspace_root=temp_dir, max_files=100)
            assert len(files) == 20

        small_m = run_workload_iterations(
            workload_id="WL-U1-LOAD-SMALL",
            name="Small Repo File Loading (20 files)",
            iteration_fn=run_small,
            iterations=iterations,
        )

        # Medium
        def run_med():
            _, files, stats = prepare_repository_analysis_files(acq_med, workspace_root=temp_dir, max_files=200)
            assert len(files) == 100

        med_m = run_workload_iterations(
            workload_id="WL-U1-LOAD-MED",
            name="Medium Repo File Loading (100 files)",
            iteration_fn=run_med,
            iterations=iterations,
        )

        # Large
        def run_large():
            _, files, stats = prepare_repository_analysis_files(acq_large, workspace_root=temp_dir, max_files=1000)
            assert len(files) == 500
            assert not any("node_modules" in f["path"] for f in files)

        large_m = run_workload_iterations(
            workload_id="WL-U1-LOAD-LARGE",
            name="Large Repo File Loading (500 files + 1000 excluded)",
            iteration_fn=run_large,
            iterations=iterations,
        )

        # Throughput calculations (files / second)
        small_fps = (20 / (small_m.median_ms / 1000.0)) if small_m.median_ms > 0 else 0.0
        med_fps = (100 / (med_m.median_ms / 1000.0)) if med_m.median_ms > 0 else 0.0
        large_fps = (500 / (large_m.median_ms / 1000.0)) if large_m.median_ms > 0 else 0.0

        summary = {
            "small_median_ms": small_m.median_ms,
            "small_throughput_files_per_sec": small_fps,
            "med_median_ms": med_m.median_ms,
            "med_throughput_files_per_sec": med_fps,
            "large_median_ms": large_m.median_ms,
            "large_throughput_files_per_sec": large_fps,
        }
        return small_m, med_m, large_m, summary


# =============================================================================
# WORKLOAD 3: Representative End-to-End Analysis Latency (Clean, Vuln, Cached)
# =============================================================================

def benchmark_representative_analysis_latency(iterations: int = 5) -> Tuple[BenchmarkMetric, BenchmarkMetric, BenchmarkMetric, Dict[str, Any]]:
    """Evaluates complete end-to-end repository analysis on representative clean, vulnerable, and cached codebases."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        # 1. Clean Codebase (10 Python files without security vulnerabilities)
        clean_dir = os.path.join(temp_dir, "clean_codebase")
        os.makedirs(clean_dir, exist_ok=True)
        for i in range(10):
            with open(os.path.join(clean_dir, f"service_{i}.py"), "w", encoding="utf-8") as f:
                f.write(
                    f"import math\n\n"
                    f"class CalculatorService{i}:\n"
                    f"    def compute_sum(self, a: int, b: int) -> int:\n"
                    f"        return a + b + {i}\n\n"
                    f"    def safe_sqrt(self, val: float) -> float:\n"
                    f"        return math.sqrt(max(0.0, val))\n"
                )

        acq_clean = acquire_repository(
            repository_url="https://github.com/example/clean-codebase.git",
            local_path=clean_dir,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        def run_clean_analysis():
            res = analyze_repository(
                acquisition_id=acq_clean,
                workspace_root=temp_dir,
                enable_cache=False,
            )
            assert res["status"] == "success"
            assert res["review_status"] == "allow"
            assert len(res.get("findings", [])) == 0

        clean_metric = run_workload_iterations(
            workload_id="WL-U1-ANALYSIS-CLEAN",
            name="End-to-End Analysis: Clean Codebase (10 files, 0 findings)",
            iteration_fn=run_clean_analysis,
            iterations=iterations,
        )

        # 2. Vulnerable Codebase (10 Python files containing AST-detectable vulnerabilities)
        vuln_dir = os.path.join(temp_dir, "vuln_codebase")
        os.makedirs(vuln_dir, exist_ok=True)

        vuln_snippets = [
            ("cmd_1.py", "import os\ndef r(c):\n    os.system(c)\n"),
            ("cmd_2.py", "import subprocess\ndef r(c):\n    subprocess.Popen(c, shell=True)\n"),
            ("sql_1.py", "import sqlite3\ndef q(u):\n    sqlite3.connect(':memory:').execute('SELECT * FROM t WHERE id=' + u)\n"),
            ("sql_2.py", "import sqlite3\ndef q(u):\n    sqlite3.connect(':memory:').cursor().execute(f'DELETE FROM t WHERE id={u}')\n"),
            ("path_1.py", "def read_file(p):\n    return open(p).read()\n"),
            ("crypto_1.py", "import hashlib\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"),
            ("crypto_2.py", "import hashlib\ndef h(p):\n    return hashlib.sha1(p.encode()).hexdigest()\n"),
            ("secret_1.py", "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE1234567890123456'\n"),
            ("exec_1.py", "def run_code(code_str):\n    eval(code_str)\n"),
            ("exec_2.py", "def run_code(code_str):\n    exec(code_str)\n"),
        ]

        for fname, content in vuln_snippets:
            with open(os.path.join(vuln_dir, fname), "w", encoding="utf-8") as f:
                f.write(content)

        acq_vuln = acquire_repository(
            repository_url="https://github.com/example/vuln-codebase.git",
            local_path=vuln_dir,
            workspace_root=temp_dir,
        )["acquisition"]["acquisition_id"]

        def run_vuln_analysis():
            res = analyze_repository(
                acquisition_id=acq_vuln,
                workspace_root=temp_dir,
                enable_cache=False,
            )
            assert res["status"] == "success"
            assert res["review_status"] in ("block", "review")
            assert len(res.get("findings", [])) >= 8

        vuln_metric = run_workload_iterations(
            workload_id="WL-U1-ANALYSIS-VULN",
            name="End-to-End Analysis: Vulnerable Codebase (10 files, >=8 findings)",
            iteration_fn=run_vuln_analysis,
            iterations=iterations,
        )

        # 3. Warm Cached Repository Analysis (Seed cache first, then measure 100% cache hits)
        _ = analyze_repository(acquisition_id=acq_clean, workspace_root=temp_dir, enable_cache=True)

        def run_cached_analysis():
            res = analyze_repository(
                acquisition_id=acq_clean,
                workspace_root=temp_dir,
                enable_cache=True,
            )
            assert res["status"] == "success"

        cached_metric = run_workload_iterations(
            workload_id="WL-U1-ANALYSIS-CACHED",
            name="End-to-End Analysis: Cached Codebase (10 files, 100% cache hit)",
            iteration_fn=run_cached_analysis,
            iterations=iterations,
        )

        cache_savings_pct = (
            ((clean_metric.median_ms - cached_metric.median_ms) / clean_metric.median_ms) * 100.0
            if clean_metric.median_ms > 0
            else 0.0
        )

        summary = {
            "clean_median_ms": clean_metric.median_ms,
            "clean_p95_ms": clean_metric.p95_ms,
            "vuln_median_ms": vuln_metric.median_ms,
            "vuln_p95_ms": vuln_metric.p95_ms,
            "cached_median_ms": cached_metric.median_ms,
            "cached_p95_ms": cached_metric.p95_ms,
            "cache_savings_pct": cache_savings_pct,
            "vuln_overhead_ms": vuln_metric.median_ms - clean_metric.median_ms,
        }
        return clean_metric, vuln_metric, cached_metric, summary


# =============================================================================
# WORKLOAD 4: RAG Retrieval & Context Ranking Latency
# =============================================================================

def benchmark_rag_retrieval_and_ranking(iterations: int = 10) -> Tuple[BenchmarkMetric, Dict[str, Any]]:
    """Evaluates standalone RAG retrieval and ranking latency querying curated security knowledge."""
    # Ensure curated knowledge is loaded in memory
    ensure_curated_knowledge_ingested(force=False)

    queries = [
        "sql injection parameterized query vulnerability",
        "remote command execution os system call",
        "directory traversal arbitrary file read",
        "hardcoded credentials secret api token",
        "insecure deserialization pickle load",
    ]

    def run_rag_retrieval():
        for q in queries:
            ctx = build_security_analysis_context(query=q, top_k=5)
            assert ctx["status"] == "success"
            assert "context" in ctx
            total_docs = (
                len(ctx["context"].get("security_knowledge", []))
                + len(ctx["context"].get("security_evidence", []))
                + len(ctx["context"].get("code_structure", []))
            )
            assert total_docs <= MAX_CONTEXT_DOCUMENTS

    rag_metric = run_workload_iterations(
        workload_id="WL-U1-RAG-RETRIEVAL",
        name="RAG Context Retrieval & Ranking (5 representative queries)",
        iteration_fn=run_rag_retrieval,
        iterations=iterations,
    )

    per_query_ms = rag_metric.median_ms / len(queries)
    summary = {
        "rag_batch_median_ms": rag_metric.median_ms,
        "rag_batch_p95_ms": rag_metric.p95_ms,
        "rag_per_query_median_ms": per_query_ms,
        "queries_evaluated": len(queries),
    }
    return rag_metric, summary


# =============================================================================
# WORKLOAD 5: Database Persistence Latency Across Finding Counts
# =============================================================================

def benchmark_database_persistence_latency(iterations: int = 10) -> Tuple[List[BenchmarkMetric], List[BenchmarkMetric], Dict[str, Any]]:
    """Evaluates batched executemany persistence latency vs unbatched row-by-row across finding counts (1, 50, 200, 500)."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        db_path = os.path.join(temp_dir, "db_bench.db")
        reset_database_initialization_cache()
        store = AnalysisStore(db_path=db_path)

        def make_report(num_findings: int, a_id: str) -> Dict[str, Any]:
            return {
                "analysis_id": a_id,
                "status": "success",
                "query": "security audit",
                "repository": {"name": "bench-repo", "owner": "test-org"},
                "review_status": "block" if num_findings > 0 else "allow",
                "summary": {"total_findings": num_findings},
                "findings": [
                    {
                        "finding_id": f"f_{a_id}_{i}",
                        "title": f"Vulnerability {i}",
                        "description": f"Details for vulnerability {i}",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "category": "injection",
                        "evidence": {"snippet": f"vulnerable_call_{i}()"},
                    }
                    for i in range(num_findings)
                ],
            }

        counts = [1, 50, 200, 500]
        batch_metrics: List[BenchmarkMetric] = []
        loop_metrics: List[BenchmarkMetric] = []

        for count in counts:
            # 1. Batched executemany persistence
            def run_batched():
                rep = make_report(count, f"batch_{count}_{time.time_ns()}")
                store.save_analysis(rep)

            b_m = run_workload_iterations(
                workload_id=f"WL-U1-DB-BATCH-{count}",
                name=f"Database Save (executemany): {count} findings",
                iteration_fn=run_batched,
                iterations=iterations,
            )
            batch_metrics.append(b_m)

            # 2. Row-by-row loop persistence baseline
            def run_loop():
                a_id = f"loop_{count}_{time.time_ns()}"
                rep = make_report(count, a_id)
                sanitized = [sanitize_finding_record(f) for f in rep.get("findings", []) if isinstance(f, dict)]
                record = create_analysis_record(
                    analysis_id=a_id,
                    status="success",
                    query="security audit",
                    summary=rep.get("summary", {}),
                    created_at=get_utc_now_iso(),
                )
                params = [
                    (
                        f["finding_id"] or f"finding_{idx}",
                        a_id,
                        f["title"],
                        f["description"],
                        f["severity"],
                        f["confidence"],
                        f["category"],
                        json.dumps(f["evidence"]),
                    )
                    for idx, f in enumerate(sanitized, start=1)
                ]
                with store._get_connection() as conn:
                    conn.execute("DELETE FROM findings WHERE analysis_id = ?;", (a_id,))
                    conn.execute("DELETE FROM analyses WHERE analysis_id = ?;", (a_id,))
                    conn.execute(
                        "INSERT INTO analyses (analysis_id, status, query, created_at, finding_count, summary_json, schema_version) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
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
                    for p in params:
                        conn.execute(
                            "INSERT INTO findings (finding_id, analysis_id, title, description, severity, confidence, category, evidence_json) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                            p,
                        )

            l_m = run_workload_iterations(
                workload_id=f"WL-U1-DB-LOOP-{count}",
                name=f"Database Save (unbatched loop): {count} findings",
                iteration_fn=run_loop,
                iterations=iterations,
            )
            loop_metrics.append(l_m)

        b_500 = next(m for m in batch_metrics if m.workload_id == "WL-U1-DB-BATCH-500")
        l_500 = next(m for m in loop_metrics if m.workload_id == "WL-U1-DB-LOOP-500")
        speedup_500_pct = ((l_500.median_ms - b_500.median_ms) / l_500.median_ms) * 100.0 if l_500.median_ms > 0 else 0.0

        summary = {
            "batch_1_median_ms": next(m for m in batch_metrics if m.workload_id == "WL-U1-DB-BATCH-1").median_ms,
            "batch_500_median_ms": b_500.median_ms,
            "loop_500_median_ms": l_500.median_ms,
            "speedup_500_pct": speedup_500_pct,
        }
        return batch_metrics, loop_metrics, summary


# =============================================================================
# WORKLOAD 6: Concurrent Analysis Throughput & Error Rate
# =============================================================================

def benchmark_concurrent_throughput_and_errors(workers: int = 4, iterations: int = 5) -> Tuple[BenchmarkMetric, Dict[str, Any]]:
    """Evaluates multi-worker concurrent repository analysis throughput, p95 latency, and 0% error rate."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        # Build 4 distinct repositories
        repos = []
        vulns = ["cmd_exec", "sql_inject", "path_trav", "weak_crypto"]
        for w_id in range(workers):
            r_dir = os.path.join(temp_dir, f"worker_repo_{w_id}")
            os.makedirs(r_dir, exist_ok=True)
            v_name = vulns[w_id % len(vulns)]
            with open(os.path.join(r_dir, f"{v_name}.py"), "w", encoding="utf-8") as f:
                if v_name == "cmd_exec":
                    f.write("import os\ndef r(c):\n    os.system(c)\n")
                elif v_name == "sql_inject":
                    f.write("import sqlite3\ndef q(u):\n    sqlite3.connect(':memory:').execute('SELECT * FROM t WHERE id=' + u)\n")
                elif v_name == "path_trav":
                    f.write("def read(p):\n    return open(p).read()\n")
                else:
                    f.write("import hashlib\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n")

            acq = acquire_repository(
                repository_url=f"https://github.com/example/concurrent-{w_id}.git",
                local_path=r_dir,
                workspace_root=temp_dir,
            )
            repos.append((w_id, acq["acquisition"]["acquisition_id"]))

        results: Dict[int, Any] = {}
        worker_errors: List[Tuple[int, Exception]] = []

        def run_concurrent_batch():
            results.clear()
            worker_errors.clear()

            def worker_fn(w_id: int, acq_id: str):
                try:
                    res = analyze_repository(
                        acquisition_id=acq_id,
                        workspace_root=temp_dir,
                        enable_cache=False,
                    )
                    results[w_id] = res
                except Exception as exc:
                    worker_errors.append((w_id, exc))

            threads = [
                threading.Thread(target=worker_fn, args=(w_id, acq_id))
                for w_id, acq_id in repos
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(worker_errors) == 0, f"Worker errors encountered: {worker_errors}"
            assert len(results) == workers
            for w_id in range(workers):
                assert results[w_id]["status"] == "success"

        concurrency_metric = run_workload_iterations(
            workload_id="WL-U1-CONCUR-4W",
            name=f"{workers} Concurrent Repository Analyses (Throughput & Error Rate)",
            iteration_fn=run_concurrent_batch,
            iterations=iterations,
        )

        # Cross-contamination verification
        cross_contamination_detected = False
        vuln_markers = {0: "cmd_exec.py", 1: "sql_inject.py", 2: "path_trav.py", 3: "weak_crypto.py"}
        for w_id, res in results.items():
            findings = res.get("findings", [])
            other_markers = [m for idx, m in vuln_markers.items() if idx != w_id]
            for f in findings:
                evidence = str(f.get("evidence", ""))
                for om in other_markers:
                    if om in evidence:
                        cross_contamination_detected = True

        total_analyses_per_iter = workers
        analyses_per_sec = (total_analyses_per_iter / (concurrency_metric.median_ms / 1000.0)) if concurrency_metric.median_ms > 0 else 0.0

        summary = {
            "workers": workers,
            "median_duration_ms": concurrency_metric.median_ms,
            "p95_duration_ms": concurrency_metric.p95_ms,
            "throughput_analyses_per_sec": analyses_per_sec,
            "error_rate_pct": 0.0 if len(worker_errors) == 0 else (len(worker_errors) / workers) * 100.0,
            "cross_contamination_detected": cross_contamination_detected,
        }
        return concurrency_metric, summary


# =============================================================================
# Pytest Test Functions (Functional & CI-Safe)
# =============================================================================

def test_workload_u1_cache():
    """Verify cache miss, hit, and churn behavior functionally."""
    cold_m, hit_m, miss_m, churn_m, summary = benchmark_cache_hit_and_miss(iterations=3)
    assert cold_m.median_ms > 0.0
    assert hit_m.median_ms > 0.0
    assert miss_m.median_ms > 0.0
    assert churn_m.median_ms > 0.0
    assert summary["hit_median_ms"] <= summary["cold_median_ms"]


def test_workload_u1_file_loading():
    """Verify multi-size repository loading functionally."""
    small_m, med_m, large_m, summary = benchmark_file_loading_multi_size(iterations=3)
    assert small_m.median_ms > 0.0
    assert med_m.median_ms > 0.0
    assert large_m.median_ms > 0.0
    assert summary["large_throughput_files_per_sec"] > 0.0


def test_workload_u1_representative_analysis():
    """Verify clean, vulnerable, and cached end-to-end repository analysis functionally."""
    clean_m, vuln_m, cached_m, summary = benchmark_representative_analysis_latency(iterations=3)
    assert clean_m.median_ms > 0.0
    assert vuln_m.median_ms > 0.0
    assert cached_m.median_ms > 0.0
    assert summary["cached_median_ms"] < summary["clean_median_ms"]


def test_workload_u1_rag_retrieval():
    """Verify standalone RAG context retrieval and ranking functionally."""
    rag_m, summary = benchmark_rag_retrieval_and_ranking(iterations=3)
    assert rag_m.median_ms > 0.0
    assert summary["queries_evaluated"] == 5


def test_workload_u1_database_persistence():
    """Verify batched and loop database persistence functionally."""
    b_metrics, l_metrics, summary = benchmark_database_persistence_latency(iterations=3)
    assert len(b_metrics) == 4
    assert len(l_metrics) == 4
    assert summary["batch_500_median_ms"] > 0.0


def test_workload_u1_concurrency_throughput():
    """Verify concurrent multi-worker analysis throughput and 0% error rate functionally."""
    concur_m, summary = benchmark_concurrent_throughput_and_errors(workers=4, iterations=3)
    assert summary["error_rate_pct"] == 0.0
    assert summary["cross_contamination_detected"] is False
    assert summary["throughput_analyses_per_sec"] > 0.0


# =============================================================================
# Standalone Benchmark CLI Runner
# =============================================================================

def print_markdown_table(metrics: List[BenchmarkMetric]):
    print("| Workload ID | Name | Iterations | Warmup (ms) | Mean (ms) | Median (ms) | P95 (ms) | StdDev (ms) | Peak RAM (KB) |")
    print("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for m in metrics:
        print(f"| `{m.workload_id}` | {m.name} | {m.iterations} | {m.warmup_ms:.2f} | {m.mean_ms:.2f} | {m.median_ms:.2f} | {m.p95_ms:.2f} | {m.stddev_ms:.2f} | {m.peak_memory_kb:.1f} |")


if __name__ == "__main__":
    print("=" * 80)
    print("CodeSentinel U1 — Representative Performance Benchmark Execution")
    print(f"Platform: {platform.system()} {platform.release()} | Architecture: {platform.machine()}")
    print(f"Python: {platform.python_version()} | Implementation: {platform.python_implementation()}")
    print(f"SQLite: {sqlite3.sqlite_version}")
    print("=" * 80)

    all_metrics: List[BenchmarkMetric] = []

    print("\n[1/6] Running Workload 1: Cache Miss vs Hit & LRU Churn...")
    cold_m, hit_m, miss_m, churn_m, s_1 = benchmark_cache_hit_and_miss(iterations=10)
    all_metrics.extend([cold_m, hit_m, miss_m, churn_m])
    print(f"  -> Cold Median: {s_1['cold_median_ms']:.2f}ms | Hit Median: {s_1['hit_median_ms']:.2f}ms | Miss Median: {s_1['miss_median_ms']:.2f}ms")
    print(f"  -> LRU Churn Median: {s_1['churn_median_ms']:.2f}ms")
    print(f"  -> Hit Speedup vs Cold: {s_1['hit_speedup_vs_cold_pct']:.2f}%")

    print("\n[2/6] Running Workload 2: Multi-Size Repository File Loading...")
    small_m, med_m, large_m, s_2 = benchmark_file_loading_multi_size(iterations=10)
    all_metrics.extend([small_m, med_m, large_m])
    print(f"  -> Small (20 files): {s_2['small_median_ms']:.2f}ms ({s_2['small_throughput_files_per_sec']:.1f} files/sec)")
    print(f"  -> Medium (100 files): {s_2['med_median_ms']:.2f}ms ({s_2['med_throughput_files_per_sec']:.1f} files/sec)")
    print(f"  -> Large (500 files): {s_2['large_median_ms']:.2f}ms ({s_2['large_throughput_files_per_sec']:.1f} files/sec)")

    print("\n[3/6] Running Workload 3: Representative End-to-End Analysis Latency...")
    clean_m, vuln_m, cached_m, s_3 = benchmark_representative_analysis_latency(iterations=5)
    all_metrics.extend([clean_m, vuln_m, cached_m])
    print(f"  -> Clean Codebase (10 files): Median {s_3['clean_median_ms']:.2f}ms | P95 {s_3['clean_p95_ms']:.2f}ms")
    print(f"  -> Vulnerable Codebase (10 files): Median {s_3['vuln_median_ms']:.2f}ms | P95 {s_3['vuln_p95_ms']:.2f}ms")
    print(f"  -> Warm Cached Codebase (10 files): Median {s_3['cached_median_ms']:.2f}ms | P95 {s_3['cached_p95_ms']:.2f}ms")
    print(f"  -> Cache Savings: {s_3['cache_savings_pct']:.2f}% | Vuln Detection Overhead: {s_3['vuln_overhead_ms']:.2f}ms")

    print("\n[4/6] Running Workload 4: Standalone RAG Retrieval & Context Ranking...")
    rag_m, s_4 = benchmark_rag_retrieval_and_ranking(iterations=10)
    all_metrics.append(rag_m)
    print(f"  -> 5-Query Batch Median: {s_4['rag_batch_median_ms']:.2f}ms | P95: {s_4['rag_batch_p95_ms']:.2f}ms")
    print(f"  -> Per-Query Median: {s_4['rag_per_query_median_ms']:.2f}ms")

    print("\n[5/6] Running Workload 5: Database Persistence Latency (Batch vs Loop)...")
    b_metrics, l_metrics, s_5 = benchmark_database_persistence_latency(iterations=10)
    all_metrics.extend(b_metrics)
    all_metrics.extend(l_metrics)
    print(f"  -> Save 1 Finding: {s_5['batch_1_median_ms']:.2f}ms")
    print(f"  -> Save 500 Findings (Batch): {s_5['batch_500_median_ms']:.2f}ms | (Loop): {s_5['loop_500_median_ms']:.2f}ms")
    print(f"  -> 500 Findings Batching Speedup: {s_5['speedup_500_pct']:.2f}%")

    print("\n[6/6] Running Workload 6: Concurrent Multi-Worker Analysis Throughput...")
    concur_m, s_6 = benchmark_concurrent_throughput_and_errors(workers=4, iterations=5)
    all_metrics.append(concur_m)
    print(f"  -> 4 Workers Median Duration: {s_6['median_duration_ms']:.2f}ms | P95: {s_6['p95_duration_ms']:.2f}ms")
    print(f"  -> Throughput: {s_6['throughput_analyses_per_sec']:.2f} analyses/sec")
    print(f"  -> Error Rate: {s_6['error_rate_pct']:.1f}%")
    print(f"  -> Cross-Contamination Detected: {s_6['cross_contamination_detected']}")

    print("\n" + "=" * 80)
    print("DETAILED U1 REPRESENTATIVE BENCHMARK RESULTS")
    print("=" * 80)
    print_markdown_table(all_metrics)
