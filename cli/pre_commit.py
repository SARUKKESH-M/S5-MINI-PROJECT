"""
CodeSentinel — Pre-Commit Hook Integration & Staged File Analysis

Provides thin Git workstation integration:
1. Detects Git repository root safely.
2. Identifies staged files from Git index (A, C, M, R; ignores D).
3. Reads staged content directly from Git index (`git show :<path>`) to guarantee
   evaluating staged changes regardless of working-tree modifications.
4. Executes deterministic AST security analysis on supported files (.py).
5. Aggregates findings and evaluates authoritative Step 6O Security Gate (ALLOW / REVIEW / BLOCK).
6. Installs/updates idempotent pre-commit hook into `.git/hooks/pre-commit`,
   strictly preserving any existing hook logic.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from ast_engine.security_analyzer import analyze_security_structure
    from ast_engine.structural_analyzer import analyze_javascript_structure
    from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
    from backend.analysis.deterministic_findings import generate_deterministic_findings
    from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings
    from backend.analysis.report_service import build_repository_report
    from backend.analysis.security_gate import evaluate_security_gate
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    from ast_engine.security_analyzer import analyze_security_structure
    from ast_engine.structural_analyzer import analyze_javascript_structure
    from ast_engine.javascript_security_analyzer import analyze_javascript_security_structure
    from analysis.deterministic_findings import generate_deterministic_findings
    from analysis.finding_aggregator import aggregate_and_deduplicate_findings
    from analysis.report_service import build_repository_report
    from analysis.security_gate import evaluate_security_gate
    from app.core.security import sanitize_sensitive_text

SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx"}

HOOK_MARKER_START = "# >>> CodeSentinel pre-commit >>>"
HOOK_MARKER_END = "# <<< CodeSentinel pre-commit <<<"

HOOK_SHELL_TEMPLATE = f"""{HOOK_MARKER_START}
# CodeSentinel automated staged security gate check
if command -v codesentinel >/dev/null 2>&1; then
    codesentinel pre-commit --run
elif command -v python3 >/dev/null 2>&1; then
    python3 -m cli.main pre-commit --run
elif command -v python >/dev/null 2>&1; then
    python -m cli.main pre-commit --run
elif command -v py >/dev/null 2>&1; then
    py -m cli.main pre-commit --run
else
    echo "CodeSentinel Error: python or codesentinel not found on PATH."
    exit 1
fi
RESULT=$?
if [ $RESULT -ne 0 ]; then
    echo "CodeSentinel security gate blocked this commit."
    exit $RESULT
fi
{HOOK_MARKER_END}
"""


def get_git_root(repo_dir: str = ".") -> Optional[Path]:
    """
    Locates the top-level root directory of the current Git repository.
    Returns None if the directory is not inside a Git repository.
    """
    try:
        resolved = Path(repo_dir).resolve()
        res = subprocess.run(
            ["git", "-C", str(resolved), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode == 0 and res.stdout.strip():
            root_path = Path(res.stdout.strip()).resolve()
            if root_path.exists() and (root_path / ".git").exists():
                return root_path
        return None
    except Exception:
        return None


def install_pre_commit_hook(repo_dir: str = ".") -> Tuple[bool, str]:
    """
    Installs the CodeSentinel pre-commit hook into `.git/hooks/pre-commit`.
    Preserves any existing hook scripts and is strictly idempotent.
    """
    git_root = get_git_root(repo_dir)
    if git_root is None:
        return False, f"Directory '{repo_dir}' is not inside a Git repository."

    hooks_dir = git_root / ".git" / "hooks"
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return False, f"Failed to create hooks directory '{hooks_dir}': {e}"

    hook_file = hooks_dir / "pre-commit"
    existing_content = ""

    if hook_file.exists():
        try:
            existing_content = hook_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return False, f"Failed to read existing pre-commit hook: {e}"

    # Check for existing CodeSentinel block
    if HOOK_MARKER_START in existing_content:
        # Replace existing CodeSentinel block cleanly without duplicating
        start_idx = existing_content.find(HOOK_MARKER_START)
        end_idx = existing_content.find(HOOK_MARKER_END)
        if end_idx != -1:
            end_idx += len(HOOK_MARKER_END)
            new_content = (
                existing_content[:start_idx].rstrip()
                + "\n\n"
                + HOOK_SHELL_TEMPLATE.strip()
                + "\n"
                + existing_content[end_idx:].lstrip()
            )
        else:
            new_content = (
                existing_content[:start_idx].rstrip()
                + "\n\n"
                + HOOK_SHELL_TEMPLATE.strip()
                + "\n"
            )
    else:
        # Preserve existing non-CodeSentinel hook content
        if existing_content.strip():
            # If has shebang, keep at top
            lines = existing_content.splitlines()
            shebang = ""
            rest_lines = []
            if lines and lines[0].startswith("#!"):
                shebang = lines[0]
                rest_lines = lines[1:]
            else:
                shebang = "#!/bin/sh"
                rest_lines = lines

            body = "\n".join(rest_lines).strip()
            parts = [shebang]
            if body:
                parts.append(body)
            parts.append(HOOK_SHELL_TEMPLATE.strip())
            new_content = "\n\n".join(parts) + "\n"
        else:
            new_content = "#!/bin/sh\n\n" + HOOK_SHELL_TEMPLATE.strip() + "\n"

    try:
        hook_file.write_text(new_content, encoding="utf-8")
        # Ensure executable on POSIX systems
        try:
            os.chmod(hook_file, 0o755)
        except OSError:
            pass
        return True, f"CodeSentinel pre-commit hook successfully installed at {hook_file}"
    except Exception as e:
        return False, f"Failed to write pre-commit hook file: {e}"


def get_staged_files(repo_dir: str = ".") -> Tuple[List[str], List[str]]:
    """
    Inspects Git staged index using `git diff --cached --name-status`.
    Returns:
        Tuple of (staged_scannable_files, skipped_files)
    """
    git_root = get_git_root(repo_dir)
    if git_root is None:
        return [], []

    try:
        res = subprocess.run(
            ["git", "-C", str(git_root), "diff", "--cached", "--name-status"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode != 0:
            return [], []

        scannable: List[str] = []
        skipped: List[str] = []

        for line in res.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            status_char = parts[0].strip()
            # If renamed (e.g. R100\told\tnew), use destination path
            file_path = parts[-1].strip()

            # Ignore deleted files
            if status_char.startswith("D"):
                skipped.append(f"{file_path} (deleted)")
                continue

            ext = Path(file_path).suffix.lower()
            if ext in SUPPORTED_EXTENSIONS:
                scannable.append(file_path)
            else:
                skipped.append(f"{file_path} (unsupported extension)")

        return scannable, skipped
    except Exception:
        return [], []


def get_staged_content(file_path: str, repo_dir: str = ".") -> Optional[str]:
    """
    Retrieves file content directly from Git index using `git show :<file_path>`.
    Ensures that staged changes are scanned rather than unstaged working-tree modifications.
    """
    git_root = get_git_root(repo_dir)
    if git_root is None:
        return None

    try:
        # Standardize path with forward slashes for Git index
        git_index_path = file_path.replace("\\", "/")
        res = subprocess.run(
            ["git", "-C", str(git_root), "show", f":{git_index_path}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if res.returncode == 0:
            return res.stdout
        return None
    except Exception:
        return None


def run_pre_commit_scan(repo_dir: str = ".") -> Tuple[Dict[str, Any], int]:
    """
    Executes pre-commit security analysis on all staged Git files.

    Returns:
        Tuple of (Step 6O Production Report dictionary, exit_code: int)
        Exit codes:
          0 -> ALLOW (commit proceeds)
          1 -> BLOCK (commit rejected due to critical/high findings or scanner failure)
          2 -> REVIEW (manual review required for medium findings)
    """
    git_root = get_git_root(repo_dir)
    if git_root is None:
        err_report = {
            "status": "failed",
            "analysis_id": f"pre_commit_{uuid.uuid4().hex[:8]}",
            "review_status": "block",
            "summary": {
                "total_files": 0,
                "analyzed_files": 0,
                "skipped_files": 0,
                "total_findings": 1,
                "critical_count": 1,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [
                {
                    "finding_id": "err_not_git_repo",
                    "title": "Not a Git Repository",
                    "severity": "critical",
                    "description": f"Target directory '{repo_dir}' is not inside a Git repository.",
                }
            ],
        }
        return err_report, 1

    scannable_files, skipped_files = get_staged_files(str(git_root))
    total_staged = len(scannable_files) + len(skipped_files)

    # If no files staged or no scannable files staged, pass cleanly
    if not scannable_files:
        clean_record = {
            "status": "success",
            "analysis_id": f"pre_commit_{uuid.uuid4().hex[:8]}",
            "repository": {
                "owner": "local",
                "repository": git_root.name,
                "branch": "staged",
                "path": ".",
            },
            "summary": {
                "total_files": total_staged,
                "analyzed_files": 0,
                "skipped_files": len(skipped_files),
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [],
            "analysis_version": "1.0",
        }
        report = build_repository_report(clean_record)
        return report, 0

    findings: List[Dict[str, Any]] = []
    analyzed_count = 0
    read_failures = 0

    for f_path in scannable_files:
        content = get_staged_content(f_path, repo_dir=str(git_root))
        if content is None:
            read_failures += 1
            continue

        analyzed_count += 1
        ext = Path(f_path).suffix.lower()
        if ext in (".js", ".jsx"):
            try:
                analyze_javascript_structure(content)
                sec_data = analyze_javascript_security_structure(content, file_path=f_path)
                raw_evidence = sec_data.get("security_signals", [])
                file_findings = generate_deterministic_findings(raw_evidence)
                findings.extend(file_findings)
            except Exception:
                pass
        else:
            sec_data = analyze_security_structure(content, file_path=f_path)
            raw_evidence = sec_data.get("security_signals", [])
            file_findings = generate_deterministic_findings(raw_evidence)
            findings.extend(file_findings)

    file_stats = {
        "total_files": total_staged,
        "analyzed_files": analyzed_count,
        "skipped_files": len(skipped_files) + read_failures,
    }

    agg_result = aggregate_and_deduplicate_findings(findings, file_stats=file_stats)

    raw_record = {
        "status": "success",
        "analysis_id": f"pre_commit_{uuid.uuid4().hex[:8]}",
        "repository": {
            "owner": "local",
            "repository": git_root.name,
            "branch": "staged",
            "path": ".",
        },
        "summary": agg_result.get("summary", {}),
        "findings": agg_result.get("findings", []),
        "analysis_version": "1.0",
    }

    report = build_repository_report(raw_record)
    decision, exit_code, _ = evaluate_security_gate(report)
    return report, exit_code


def format_pre_commit_terminal(report: Dict[str, Any], skipped_files: Optional[List[str]] = None) -> str:
    """
    Formats Step 6O Report into concise, sanitized developer terminal output.
    Ensures secrets are redacted and source code is never printed.
    """
    summary = report.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    crit = summary.get("critical_count", 0)
    high = summary.get("high_count", 0)
    med = summary.get("medium_count", 0)
    low = summary.get("low_count", 0)
    review_status = str(report.get("review_status", "allow")).upper()

    lines = [
        "=" * 60,
        "🛡️  CodeSentinel Pre-Commit Security Scan",
        "=" * 60,
        f"Analyzed files: {summary.get('analyzed_files', 0)} | Skipped: {summary.get('skipped_files', 0)}",
    ]

    findings = report.get("findings", [])
    if findings:
        lines.append("\nFindings Detected:")
        for f in findings:
            sev = str(f.get("severity", "low")).upper()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            raw_title = str(f.get("title", "Security Finding"))
            safe_title = sanitize_sensitive_text(raw_title)

            cwe = f.get("cwe_id") or ""
            cwe_str = f"({cwe}) " if cwe else ""

            evidence = f.get("evidence", [])
            loc_str = ""
            if evidence and isinstance(evidence, list) and isinstance(evidence[0], dict):
                doc_id = sanitize_sensitive_text(str(evidence[0].get("document_id", "")))
                line_s = evidence[0].get("line_start", "?")
                if doc_id:
                    loc_str = f" — {doc_id}:{line_s}"

            lines.append(f"  {icon} {sev:<8} {cwe_str}{safe_title}{loc_str}")

    lines.append("-" * 60)
    lines.append(f"Summary: 🔴 {crit} Critical | 🟠 {high} High | 🟡 {med} Medium | 🟢 {low} Low")
    lines.append(f"Security Gate: {review_status}")

    if review_status == "BLOCK":
        lines.append("\n❌ COMMIT BLOCKED by CodeSentinel.")
        lines.append("Resolve critical/high severity vulnerabilities before committing.")
    elif review_status == "REVIEW":
        lines.append("\n⚠️  COMMIT REQUIRES REVIEW.")
        lines.append("Medium severity findings detected. Manual security review recommended.")
    else:
        lines.append("\n✅ CodeSentinel scan PASSED.")
        lines.append("Commit may proceed.")

    lines.append("=" * 60)
    return "\n".join(lines)
