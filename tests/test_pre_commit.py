"""
CodeSentinel — Pre-Commit Hook Test Suite

Validates:
1. Git repository detection & rejection outside Git repos.
2. Staged file detection (added, modified, renamed, deleted handling).
3. Extension filtering (only supported .py files scanned, unsupported skipped).
4. Reading staged content directly from Git index (ignoring unstaged working-tree edits).
5. Hook installation into .git/hooks/pre-commit with markers and idempotency.
6. Preservation of existing unrelated hook scripts.
7. Invocation of NEW deterministic AST security engine (never OLD regex scanner).
8. Authoritative Security Gate enforcement (ALLOW=0, BLOCK=1, fail-closed).
9. Developer terminal formatting, secret sanitization, and raw code non-exposure.
10. Zero external network, GitHub API, or Slack dependencies.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Generator
import pytest

# Ensure backend and root are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cli.main import main as cli_main
from cli.pre_commit import (
    HOOK_MARKER_START,
    HOOK_MARKER_END,
    get_git_root,
    get_staged_content,
    get_staged_files,
    install_pre_commit_hook,
    run_pre_commit_scan,
    format_pre_commit_terminal,
)


# ---------------------------------------------------------------------------
# Temporary Git Repository Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_git_repo() -> Generator[Path, None, None]:
    """Creates a clean temporary Git repository for isolated testing."""
    temp_dir = tempfile.mkdtemp(prefix="cs_test_git_")
    repo_path = Path(temp_dir).resolve()

    # Configure minimal Git environment for deterministic commits/staging
    subprocess.run(["git", "init", str(repo_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_path), "config", "user.name", "Test User"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_path), "config", "user.email", "test@codesentinel.local"], check=True, capture_output=True)

    yield repo_path

    # Cleanup temporary repository
    shutil.rmtree(temp_dir, ignore_errors=True)


# ===========================================================================
# 1. GIT REPOSITORY DETECTION & REJECTION
# ===========================================================================

def test_1_detect_current_git_repository(temp_git_repo: Path):
    """1. Verifies get_git_root detects the valid Git repository root."""
    detected = get_git_root(str(temp_git_repo))
    assert detected is not None
    assert detected.resolve() == temp_git_repo.resolve()


def test_2_reject_execution_outside_git_repo():
    """2. Verifies rejection when executed outside a Git repository."""
    with tempfile.TemporaryDirectory(prefix="cs_not_git_") as non_git:
        detected = get_git_root(non_git)
        assert detected is None

        # run_pre_commit_scan must fail-closed with exit code 1
        report, exit_code = run_pre_commit_scan(repo_dir=non_git)
        assert exit_code == 1
        assert report["review_status"] == "block"
        assert report["summary"]["total_findings"] >= 1


# ===========================================================================
# 2. STAGED FILE DETECTION & FILTERING
# ===========================================================================

def test_3_detect_staged_python_file(temp_git_repo: Path):
    """3. Verifies detection of a newly added and staged Python file."""
    py_file = temp_git_repo / "app.py"
    py_file.write_text("print('hello world')", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "app.py"], check=True, capture_output=True)

    scannable, skipped = get_staged_files(str(temp_git_repo))
    assert "app.py" in scannable
    assert len(skipped) == 0


def test_4_detect_multiple_staged_files(temp_git_repo: Path):
    """4. Verifies detection across multiple staged Python files."""
    (temp_git_repo / "db.py").write_text("x = 1\n", encoding="utf-8")
    (temp_git_repo / "auth.py").write_text("y = 2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "db.py", "auth.py"], check=True, capture_output=True)

    scannable, _ = get_staged_files(str(temp_git_repo))
    assert "db.py" in scannable
    assert "auth.py" in scannable
    assert len(scannable) == 2


def test_5_skip_unsupported_file_types(temp_git_repo: Path):
    """5. Verifies non-Python files (.md, .json, .txt) are safely skipped."""
    (temp_git_repo / "README.md").write_text("# Project Docs\n", encoding="utf-8")
    (temp_git_repo / "config.json").write_text('{"env": "test"}\n', encoding="utf-8")
    (temp_git_repo / "valid.py").write_text("z = 3\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "."], check=True, capture_output=True)

    scannable, skipped = get_staged_files(str(temp_git_repo))
    assert scannable == ["valid.py"]
    assert any("README.md" in s for s in skipped)
    assert any("config.json" in s for s in skipped)


def test_6_handle_no_staged_files(temp_git_repo: Path):
    """6. Verifies clean pass when no files are staged."""
    scannable, skipped = get_staged_files(str(temp_git_repo))
    assert scannable == []
    assert skipped == []

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0
    assert report["review_status"] == "allow"
    assert report["summary"]["total_findings"] == 0


def test_7_handle_deleted_staged_file(temp_git_repo: Path):
    """7. Verifies deleted files (status D) are skipped without attempting to read them."""
    f = temp_git_repo / "old.py"
    f.write_text("old = 1", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "old.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(temp_git_repo), "commit", "-m", "initial"], check=True, capture_output=True)

    # Now delete the file and stage deletion
    os.remove(f)
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "old.py"], check=True, capture_output=True)

    scannable, skipped = get_staged_files(str(temp_git_repo))
    assert "old.py" not in scannable
    assert any("deleted" in s for s in skipped)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0
    assert report["review_status"] == "allow"


def test_8_handle_renamed_staged_file(temp_git_repo: Path):
    """8. Verifies renamed staged files are detected under their new name."""
    orig = temp_git_repo / "original.py"
    orig.write_text("x = 'clean code'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "original.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(temp_git_repo), "commit", "-m", "commit original"], check=True, capture_output=True)

    # Rename file and stage rename
    renamed = temp_git_repo / "renamed.py"
    subprocess.run(["git", "-C", str(temp_git_repo), "mv", "original.py", "renamed.py"], check=True, capture_output=True)

    scannable, _ = get_staged_files(str(temp_git_repo))
    assert "renamed.py" in scannable
    assert "original.py" not in scannable


# ===========================================================================
# 3. HOOK INSTALLATION & IDEMPOTENCY
# ===========================================================================

def test_9_install_hook_into_git_hooks(temp_git_repo: Path):
    """9. Verifies hook installer creates .git/hooks/pre-commit with executable permissions."""
    success, msg = install_pre_commit_hook(repo_dir=str(temp_git_repo))
    assert success
    hook_file = temp_git_repo / ".git" / "hooks" / "pre-commit"
    assert hook_file.exists()

    content = hook_file.read_text(encoding="utf-8")
    assert HOOK_MARKER_START in content
    assert HOOK_MARKER_END in content
    assert "codesentinel pre-commit --run" in content


def test_10_create_hooks_dir_when_missing(temp_git_repo: Path):
    """10. Verifies installer creates .git/hooks directory if it does not exist."""
    hooks_dir = temp_git_repo / ".git" / "hooks"
    if hooks_dir.exists():
        shutil.rmtree(hooks_dir)
    assert not hooks_dir.exists()

    success, _ = install_pre_commit_hook(repo_dir=str(temp_git_repo))
    assert success
    assert hooks_dir.exists()
    assert (hooks_dir / "pre-commit").exists()


def test_11_repeated_installation_does_not_duplicate_hook(temp_git_repo: Path):
    """11. Verifies running install multiple times is strictly idempotent."""
    for _ in range(5):
        success, _ = install_pre_commit_hook(repo_dir=str(temp_git_repo))
        assert success

    content = (temp_git_repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert content.count(HOOK_MARKER_START) == 1
    assert content.count(HOOK_MARKER_END) == 1


def test_12_existing_unrelated_hook_content_is_preserved(temp_git_repo: Path):
    """12. Verifies pre-existing custom developer hooks are safely preserved."""
    hooks_dir = temp_git_repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    existing_hook = hooks_dir / "pre-commit"

    original_script = "#!/bin/sh\necho 'Running custom linter'\n./custom-lint.sh\n"
    existing_hook.write_text(original_script, encoding="utf-8")

    success, _ = install_pre_commit_hook(repo_dir=str(temp_git_repo))
    assert success

    updated_content = existing_hook.read_text(encoding="utf-8")
    assert "Running custom linter" in updated_content
    assert "./custom-lint.sh" in updated_content
    assert HOOK_MARKER_START in updated_content
    assert HOOK_MARKER_END in updated_content


def test_13_codesentinel_block_is_marked_clearly(temp_git_repo: Path):
    """13. Verifies clear boundary markers around CodeSentinel hook integration."""
    install_pre_commit_hook(repo_dir=str(temp_git_repo))
    content = (temp_git_repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert HOOK_MARKER_START in content
    assert HOOK_MARKER_END in content


def test_14_install_does_not_modify_unrelated_git_files(temp_git_repo: Path):
    """14. Verifies installer touches only .git/hooks/pre-commit and no other git files."""
    config_before = (temp_git_repo / ".git" / "config").read_text(encoding="utf-8")
    install_pre_commit_hook(repo_dir=str(temp_git_repo))
    config_after = (temp_git_repo / ".git" / "config").read_text(encoding="utf-8")
    assert config_before == config_after


# ===========================================================================
# 4. DETERMINISTIC ANALYSIS & SECURITY GATE ENFORCEMENT
# ===========================================================================

def test_15_run_invokes_new_analysis_path(temp_git_repo: Path):
    """15. Verifies --run invokes the AST security analyzer pipeline."""
    vuln_code = "import sqlite3\ndef run_q(u):\n    conn = sqlite3.connect(':memory:')\n    conn.execute('SELECT * FROM users WHERE id=' + u)\n"
    (temp_git_repo / "query.py").write_text(vuln_code, encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "query.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert report["review_status"] == "block"
    assert exit_code == 1
    assert any(f.get("title") == "SQL Injection" or "execute" in str(f) for f in report["findings"])


def test_16_old_scanner_is_never_invoked(monkeypatch, temp_git_repo: Path):
    """16. Confirms legacy scanner.py and regex rules are completely bypassed."""
    # Ensure sys.modules does not load or reference old scanner
    if "backend.scanner" in sys.modules:
        del sys.modules["backend.scanner"]
    if "scanner" in sys.modules:
        del sys.modules["scanner"]

    (temp_git_repo / "clean.py").write_text("print('clean')", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "clean.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0
    assert "backend.scanner" not in sys.modules
    assert "scanner" not in sys.modules


def test_17_clean_analysis_returns_success(temp_git_repo: Path):
    """17. Verifies clean staged code produces ALLOW decision with exit code 0."""
    clean_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    (temp_git_repo / "math_utils.py").write_text(clean_code, encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "math_utils.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0
    assert report["review_status"] == "allow"
    assert report["summary"]["total_findings"] == 0


def test_18_blocking_analysis_returns_non_zero(temp_git_repo: Path):
    """18. Verifies critical/high vulnerability results in non-zero exit code 1."""
    vuln_code = "import os\ndef run_bad_command(user_arg):\n    os.system('cat ' + user_arg)\n"
    (temp_git_repo / "command.py").write_text(vuln_code, encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "command.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 1
    assert report["review_status"] == "block"


def test_19_existing_security_gate_decision_respected(temp_git_repo: Path):
    """19. Verifies the security gate evaluate_security_gate mapping is preserved."""
    (temp_git_repo / "clean.py").write_text("x = 42\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "clean.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert report["review_status"] == "allow"
    assert exit_code == 0


def test_20_analyzer_failure_does_not_become_false_allow():
    """20. Verifies fail-closed behavior: errors never turn into false ALLOW."""
    with tempfile.TemporaryDirectory() as bad_dir:
        report, exit_code = run_pre_commit_scan(repo_dir=bad_dir)
        assert exit_code != 0
        assert report["review_status"] == "block"


# ===========================================================================
# 5. STAGED CONTENT VS WORKING TREE EVALUATION
# ===========================================================================

def test_21_staged_content_used_rather_than_dirty_working_tree(temp_git_repo: Path):
    """
    21. Critical requirement: If working tree has vulnerable code but staged index
        has clean code, the scan must evaluate what is staged and pass!
    """
    test_file = temp_git_repo / "target.py"

    # 1. Write clean code and STAGE it
    clean_code = "def compute(x: int) -> int:\n    return x * 2\n"
    test_file.write_text(clean_code, encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "target.py"], check=True, capture_output=True)

    # 2. Modify working tree file on disk to be VULNERABLE (without staging)
    vulnerable_code = "import sqlite3\ndef bad(u):\n    conn = sqlite3.connect(':memory:')\n    conn.execute('SELECT * FROM u WHERE id=' + u)\n"
    test_file.write_text(vulnerable_code, encoding="utf-8")

    # 3. Pre-commit scan MUST inspect git index content (clean) and ALLOW
    staged_text = get_staged_content("target.py", repo_dir=str(temp_git_repo))
    assert staged_text == clean_code

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0
    assert report["review_status"] == "allow"
    assert report["summary"]["total_findings"] == 0


def test_21b_staged_vulnerability_detected_even_if_working_tree_cleaned(temp_git_repo: Path):
    """
    21b. Inverse check: If staged index has vulnerable code, but working tree was
         cleaned afterwards, the staged vulnerability must still be BLOCKED!
    """
    test_file = temp_git_repo / "target2.py"

    # 1. Write vulnerable code and STAGE it
    vulnerable_code = "import sqlite3\ndef bad(u):\n    conn = sqlite3.connect(':memory:')\n    conn.execute('SELECT * FROM u WHERE id=' + u)\n"
    test_file.write_text(vulnerable_code, encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "target2.py"], check=True, capture_output=True)

    # 2. Clean up working tree on disk
    test_file.write_text("x = 100\n", encoding="utf-8")

    # 3. Pre-commit scan MUST inspect git index (vulnerable) and BLOCK
    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 1
    assert report["review_status"] == "block"


# ===========================================================================
# 6. ISOLATION, OUTPUT & SANITIZATION TESTS
# ===========================================================================

def test_22_no_network_required(temp_git_repo: Path):
    """22. Verifies local deterministic analysis works 100% offline."""
    (temp_git_repo / "offline.py").write_text("def ping(): return True", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "offline.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0
    assert report["status"] == "success"


def test_23_no_slack_calls_made(monkeypatch, temp_git_repo: Path):
    """23. Verifies pre-commit scanning never dispatches Slack alerts."""
    def forbid_slack(*args, **kwargs):
        raise AssertionError("Slack must NEVER be called from local git pre-commit hook!")

    monkeypatch.setattr("backend.notifications.slack.send_slack_pr_alert_sync", forbid_slack)
    (temp_git_repo / "offline.py").write_text("x = 10", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "offline.py"], check=True, capture_output=True)

    # Should not trigger forbid_slack
    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0


def test_24_no_github_api_calls_made(monkeypatch, temp_git_repo: Path):
    """24. Verifies pre-commit scanning never invokes GitHub REST API."""
    def forbid_github(*args, **kwargs):
        raise AssertionError("GitHub API must NEVER be called from local git pre-commit hook!")

    monkeypatch.setattr("backend.github.client.GitHubClient.request", forbid_github)
    (temp_git_repo / "offline.py").write_text("y = 20", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "offline.py"], check=True, capture_output=True)

    report, exit_code = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    assert exit_code == 0


def test_25_cli_output_does_not_expose_secrets():
    """25. Verifies terminal output redacts sensitive credentials via sanitize_sensitive_text."""
    fake_report = {
        "status": "completed",
        "review_status": "block",
        "summary": {
            "total_files": 1,
            "analyzed_files": 1,
            "skipped_files": 0,
            "total_findings": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        },
        "findings": [
            {
                "finding_id": "f_1",
                "title": "Hardcoded token ghp_secretkeyliteral1234567890abcdef",
                "severity": "critical",
                "evidence": [
                    {
                        "document_id": "app/config_ghp_leakedsecret12345.py",
                        "line_start": 12,
                    }
                ],
            }
        ],
    }
    output = format_pre_commit_terminal(fake_report)
    assert "ghp_secretkeyliteral1234567890abcdef" not in output
    assert "ghp_leakedsecret12345" not in output
    assert "[REDACTED_SECRET]" in output


def test_26_cli_output_does_not_expose_raw_source_code(temp_git_repo: Path):
    """26. Verifies that full source code and diff syntax never leak into pre-commit output."""
    code = "import os\ndef test():\n    raw_secret_pattern = 'VERY_SECRET_INTERNAL_KEY'\n"
    (temp_git_repo / "test_leak.py").write_text(code, encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "test_leak.py"], check=True, capture_output=True)

    report, _ = run_pre_commit_scan(repo_dir=str(temp_git_repo))
    output = format_pre_commit_terminal(report)
    assert "VERY_SECRET_INTERNAL_KEY" not in output
    assert "def test():" not in output
    assert "diff --git" not in output


def test_27_cli_main_pre_commit_dispatch(temp_git_repo: Path, capsys):
    """27. Verifies end-to-end execution of CLI pre-commit commands (--install and --run)."""
    # 1. Test CLI --install
    exit_install = cli_main(["pre-commit", "--install", "--repo-dir", str(temp_git_repo)])
    assert exit_install == 0
    captured = capsys.readouterr()
    assert "successfully installed" in captured.out

    # 2. Stage clean file and test CLI --run
    (temp_git_repo / "valid_code.py").write_text("VALUE = 42\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(temp_git_repo), "add", "valid_code.py"], check=True, capture_output=True)

    exit_run = cli_main(["pre-commit", "--run", "--repo-dir", str(temp_git_repo)])
    assert exit_run == 0
    captured_run = capsys.readouterr()
    assert "CodeSentinel scan PASSED" in captured_run.out

    # 3. Test CLI --json output format
    exit_json = cli_main(["pre-commit", "--run", "--repo-dir", str(temp_git_repo), "--json"])
    assert exit_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out.strip())
    assert data["review_status"] == "allow"
    assert "summary" in data
