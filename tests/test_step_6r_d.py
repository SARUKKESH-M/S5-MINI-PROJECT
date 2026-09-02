"""
CodeSentinel — Step 6R-D Unit & Integration Test Suite

Tests CI Security Summary Markdown formatting, decision mapping (ALLOW, REVIEW, BLOCK),
severity telemetry, repository metadata formatting, secret/source exclusion, Step 6O
contract compatibility, 6R-C gate output compatibility, and 6Q comment marker stability.
"""

import json
import os
import sys
import tempfile
import pytest
from pathlib import Path

# Ensure backend and workspace root directory are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.ci_report import (
    generate_ci_security_summary,
    write_github_step_summary,
    COMMENT_MARKER
)
from backend.analysis.report_service import build_repository_report
from backend.analysis.security_gate import evaluate_security_gate, run_security_gate
from backend.analysis.security_scan import run_security_scan


def test_allow_markdown_generation():
    """1. ALLOW Markdown generation contains ALLOW decision label."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_allow_01",
        "repository": {"owner": "codesentinel", "repository": "core", "branch": "main"},
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 3,
            "info_count": 1,
            "total_findings": 4
        }
    }

    md = generate_ci_security_summary(report)
    assert "ALLOW / Safe to Merge" in md
    assert "Safe to merge" in md


def test_review_markdown_generation():
    """2. REVIEW Markdown generation contains REVIEW decision label."""
    report = {
        "status": "success",
        "review_status": "review",
        "analysis_id": "test_review_01",
        "repository": {"owner": "codesentinel", "repository": "core", "branch": "dev"},
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 2,
            "low_count": 0,
            "info_count": 0,
            "total_findings": 2
        }
    }

    md = generate_ci_security_summary(report)
    assert "REVIEW / Manual Review Required" in md
    assert "Manual security review required" in md


def test_block_markdown_generation():
    """3. BLOCK Markdown generation contains BLOCK decision label."""
    report = {
        "status": "success",
        "review_status": "block",
        "analysis_id": "test_block_01",
        "repository": {"owner": "codesentinel", "repository": "core", "branch": "main"},
        "summary": {
            "critical_count": 1,
            "high_count": 3,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "total_findings": 4
        }
    }

    md = generate_ci_security_summary(report)
    assert "BLOCK / Do Not Merge" in md
    assert "Do not merge" in md


def test_severity_counts_appear_correctly():
    """4. Severity counts appear accurately in formatted Markdown."""
    report = {
        "status": "success",
        "review_status": "block",
        "analysis_id": "test_sev_counts",
        "summary": {
            "critical_count": 5,
            "high_count": 4,
            "medium_count": 3,
            "low_count": 2,
            "info_count": 1,
            "total_findings": 15
        }
    }

    md = generate_ci_security_summary(report)
    assert "- **Total Findings**: `15`" in md
    assert "- **Critical**: `5`" in md
    assert "- **High**: `4`" in md
    assert "- **Medium**: `3`" in md
    assert "- **Low**: `2`" in md
    assert "- **Info**: `1`" in md


def test_repository_metadata_appears_correctly():
    """5. Repository owner, name, and branch appear correctly."""
    report = {
        "status": "completed",
        "review_status": "allow",
        "analysis_id": "test_repo_meta",
        "repository": {"owner": "acme-corp", "repository": "secure-app", "branch": "feature/sec"},
        "summary": {"total_findings": 0}
    }

    md = generate_ci_security_summary(report)
    assert "`acme-corp/secure-app`" in md
    assert "`feature/sec`" in md


def test_analysis_id_appears_correctly():
    """6. Analysis ID appears correctly in formatted Markdown."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "repo_ana_9876543210ab",
        "summary": {"total_findings": 0}
    }

    md = generate_ci_security_summary(report)
    assert "`repo_ana_9876543210ab`" in md


def test_raw_source_code_is_excluded():
    """7. Raw source code fields are strictly excluded from generated Markdown summary."""
    raw_code_sample = "def secret_function(): pass # CONFIDENTIAL SOURCE CODE"
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_src_excl",
        "summary": {"total_findings": 1},
        "findings": [
            {
                "finding_id": "f_src_1",
                "title": "SQL Injection in User Lookup",
                "severity": "high",
                "raw_code": raw_code_sample,
                "source_code": raw_code_sample
            }
        ]
    }

    clean_report = build_repository_report(report)
    md = generate_ci_security_summary(clean_report)
    assert raw_code_sample not in md


def test_raw_patches_are_excluded():
    """8. Raw patches or code replacement fields are strictly excluded."""
    patch_sample = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n-old()\n+new()"
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_patch_excl",
        "summary": {"total_findings": 1},
        "findings": [
            {
                "finding_id": "f_patch_1",
                "title": "Weak Hashing Function",
                "severity": "medium",
                "patch": patch_sample,
                "replacement_code": patch_sample
            }
        ]
    }

    clean_report = build_repository_report(report)
    md = generate_ci_security_summary(clean_report)
    assert patch_sample not in md


def test_secrets_are_excluded():
    """9. Secret tokens and credentials are masked/excluded."""
    secret_val = "THIS_SECRET_MUST_NOT_APPEAR"
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_secret_excl",
        "summary": {"total_findings": 1},
        "findings": [
            {
                "finding_id": "f_sec_1",
                "title": f"Exposed Secret {secret_val}",
                "severity": "low"
            }
        ]
    }

    clean_report = build_repository_report(report)
    md = generate_ci_security_summary(clean_report)
    assert secret_val not in md
    assert "[REDACTED_SECRET]" in md


def test_authorization_headers_are_excluded():
    """10. Authorization headers are strictly excluded."""
    auth_header = "Authorization: Bearer secret_token_abc123"
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_auth_excl",
        "summary": {"total_findings": 0},
        "auth_header": auth_header
    }

    md = generate_ci_security_summary(report)
    assert auth_header not in md
    assert "Bearer" not in md


def test_recommendation_text_matches_decision():
    """11. Recommended action text accurately reflects review_status."""
    report_allow = {"status": "success", "review_status": "allow", "analysis_id": "a1", "summary": {}}
    assert "Safe to merge" in generate_ci_security_summary(report_allow)

    report_review = {"status": "success", "review_status": "review", "analysis_id": "r1", "summary": {}}
    assert "Manual security review required" in generate_ci_security_summary(report_review)

    report_block = {"status": "success", "review_status": "block", "analysis_id": "b1", "summary": {}}
    assert "Do not merge" in generate_ci_security_summary(report_block)


def test_existing_step_6o_report_accepted_without_schema_changes():
    """12. Accepts standard Step 6O Production Report without modifying schema."""
    raw_record = {
        "status": "success",
        "analysis_id": "test_step_6o_compat",
        "repository": {"owner": "org", "repository": "app"},
        "summary": {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 1,
            "info_count": 0,
            "total_findings": 1
        },
        "findings": [
            {
                "finding_id": "f_6o_1",
                "title": "Use of Weak PRNG",
                "severity": "low",
                "confidence": "high",
                "category": "Cryptography",
                "evidence": []
            }
        ]
    }

    report = build_repository_report(raw_record)
    md = generate_ci_security_summary(report)
    assert "Use of Weak PRNG" in md
    assert report["review_status"] == "allow"


def test_malformed_report_fails_safely():
    """13. Malformed report structures raise ValueError gracefully."""
    with pytest.raises(ValueError, match="must be a non-empty dictionary"):
        generate_ci_security_summary(None)

    with pytest.raises(ValueError, match="Cannot generate security summary for failed or invalid"):
        generate_ci_security_summary({"status": "failed", "analysis_id": "fail_1"})


def test_existing_6r_c_gate_output_remains_compatible():
    """14. 6R-C security gate evaluation remains 100% compatible with 6R-D report summaries."""
    report = {
        "status": "success",
        "review_status": "block",
        "analysis_id": "test_gate_compat",
        "summary": {
            "critical_count": 2,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }

    decision, exit_code, _ = evaluate_security_gate(report)
    assert decision == "BLOCK"
    assert exit_code == 1

    md = generate_ci_security_summary(report)
    assert "BLOCK / Do Not Merge" in md


def test_github_comment_marker_compatibility_remains_intact():
    """15. Generated Markdown summary strictly includes Step 6Q comment marker."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_marker",
        "summary": {"total_findings": 0}
    }

    md = generate_ci_security_summary(report)
    assert COMMENT_MARKER in md
    assert md.startswith(COMMENT_MARKER)


def test_no_duplicate_comment_marker_is_generated():
    """16. Comment marker appears exactly once in generated Markdown output."""
    report = {
        "status": "success",
        "review_status": "allow",
        "analysis_id": "test_no_dup_marker",
        "summary": {"total_findings": 0}
    }

    md = generate_ci_security_summary(report)
    assert md.count(COMMENT_MARKER) == 1
