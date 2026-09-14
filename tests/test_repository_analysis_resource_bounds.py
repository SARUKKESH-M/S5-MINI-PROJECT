"""
Regression tests for CodeSentinel bounded repository RAG ingestion and memory lifecycle.

Verifies:
1. All in-scope files are deterministically analyzed.
2. Deterministic findings remain exact and authoritative.
3. Security gate decisions remain strictly governed by findings.
4. RAG transient ingestion receives only evidence-associated AST documents.
5. Clean files with no security evidence do not embed unnecessary AST chunks.
6. RAG enrichment remains functioning with structured explanations.
7. API response schema and contracts remain preserved.
8. Acquisition workspace and metadata invariants remain unchanged.
"""

import os
import tempfile
import pytest

from backend.repository.acquirer import acquire_repository
from backend.analysis.repository_orchestrator import analyze_repository
from rag.vector_store import get_collection, DEFAULT_COLLECTION_NAME


@pytest.fixture
def dummy_mixed_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        # File 1: Vulnerable file (Command injection)
        with open(os.path.join(tmpdir, "vuln.py"), "w", encoding="utf-8") as f:
            f.write("import os\n\ndef run_cmd(user_input):\n    os.system('echo ' + user_input)\n")

        # File 2: Clean helper file
        with open(os.path.join(tmpdir, "helper.py"), "w", encoding="utf-8") as f:
            f.write("def add(a, b):\n    return a + b\n\ndef multiply(x, y):\n    return x * y\n")

        # File 3: Another clean file
        with open(os.path.join(tmpdir, "utils.py"), "w", encoding="utf-8") as f:
            f.write("import math\n\ndef calc_hypotenuse(a, b):\n    return math.sqrt(a**2 + b**2)\n")

        yield tmpdir


@pytest.fixture
def dummy_clean_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "clean1.py"), "w", encoding="utf-8") as f:
            f.write("def clean_func():\n    return 42\n")

        with open(os.path.join(tmpdir, "clean2.py"), "w", encoding="utf-8") as f:
            f.write("class CleanClass:\n    pass\n")

        yield tmpdir


def test_bounded_rag_ingestion_and_scope_coverage(dummy_mixed_repo):
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/mixed-repo",
            local_path=dummy_mixed_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        # Execute repository analysis
        res = analyze_repository(acquisition_id=acq_id, workspace_root=ws_root)

        # 1. In-scope file coverage
        summary = res["summary"]
        assert summary["total_files"] == 3
        assert summary["analyzed_files"] == 3
        assert summary["skipped_files"] == 0

        # 2. Deterministic findings preserved
        findings = res["findings"]
        assert len(findings) == 1
        f = findings[0]
        assert "Command Injection" in f["title"]
        assert f["severity"] == "critical"
        # 3. Security gate authoritative decision
        assert res["review_status"].lower() == "block"

        # 4. RAG collection received ONLY evidence-associated AST documents
        # The 2 clean files (helper.py and utils.py) must NOT have had their function/module docs embedded
        coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)
        all_in_coll = coll.get()
        doc_ids = all_in_coll.get("ids", [])
        metadatas = all_in_coll.get("metadatas", [])

        # The only ingested AST doc should be the security_evidence document from vuln.py
        assert len(doc_ids) == 1
        assert metadatas[0].get("file_path") == "vuln.py"
        assert metadatas[0].get("document_type") == "security_evidence"
        assert f["evidence"][0]["document_id"] == doc_ids[0]

        # 5. Clean files helper.py and utils.py are NOT in the collection
        for m in metadatas:
            assert m.get("file_path") != "helper.py"
            assert m.get("file_path") != "utils.py"

        # 6. RAG / advisory explanation attached in description
        assert len(f["description"]) > 0

        # 7. Complete API response schema preserved
        assert "analysis_id" in res
        assert "repository" in res
        assert "traceability" in res
        assert res["status"] == "success"


def test_clean_repository_has_zero_transient_ast_embeddings(dummy_clean_repo):
    with tempfile.TemporaryDirectory() as ws_root:
        acq = acquire_repository(
            repository_url="https://github.com/example/clean-repo",
            local_path=dummy_clean_repo,
            workspace_root=ws_root
        )
        acq_id = acq["acquisition"]["acquisition_id"]

        res = analyze_repository(acquisition_id=acq_id, workspace_root=ws_root)

        assert res["status"] == "success"
        assert len(res["findings"]) == 0
        assert res["review_status"].lower() == "allow"
        assert res["summary"]["analyzed_files"] == 2

        # Transient collection must have 0 documents embedded
        coll = get_collection(collection_name=DEFAULT_COLLECTION_NAME)
        assert coll.count() == 0
