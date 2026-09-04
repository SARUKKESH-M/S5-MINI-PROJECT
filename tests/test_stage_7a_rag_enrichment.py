"""Stage 7A RAG enrichment must never gate deterministic findings."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.finding_enrichment import enrich_findings


def test_empty_rag_result_does_not_remove_finding(monkeypatch):
    monkeypatch.setattr(
        "backend.analysis.finding_enrichment.build_security_analysis_context",
        lambda *args, **kwargs: {"status": "success", "security_knowledge_context_count": 0},
    )
    finding = {
        "title": "Arbitrary Dynamic Code Execution Risk",
        "evidence": [{"signal_type": "dynamic_code_execution"}],
        "enriched_by": [],
    }
    result = enrich_findings([finding])
    assert len(result) == 1
    assert result[0]["title"] == finding["title"]
    assert result[0]["enriched_by"] == ["mock_llm"]
