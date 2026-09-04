"""Stage 7A finding-generation and retrieval-independence tests."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ast_engine.evidence_normalizer import normalize_security_evidence
from backend.analysis.deterministic_findings import generate_deterministic_findings
from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings
from backend.analysis.orchestrator import analyze_source_code


def test_dangerous_signal_survives_generic_query():
    result = analyze_source_code('def run(payload):\n    eval(payload)', query="security analysis")
    assert any(finding["title"] == "Arbitrary Dynamic Code Execution Risk" for finding in result["findings"])


def test_unrelated_file_evidence_does_not_suppress_dangerous_finding():
    safe = normalize_security_evidence('def safe():\n    return 1', file_path="safe.py")["security_evidence"]
    dangerous = normalize_security_evidence('def run(payload):\n    eval(payload)', file_path="dangerous.py")["security_evidence"]
    findings = generate_deterministic_findings(safe + dangerous)
    aggregate = aggregate_and_deduplicate_findings(findings)
    assert len(aggregate["findings"]) == 1
    assert aggregate["findings"][0]["file_path"] == "dangerous.py"


def test_parameterized_sql_has_no_finding():
    result = analyze_source_code('def get(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))')
    assert result["findings"] == []
