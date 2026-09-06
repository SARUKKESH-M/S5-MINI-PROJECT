"""
CodeSentinel — Step 6Q-D: GitHub End-to-End Webhook Orchestrator

Orchestrates GitHub webhook processing by linking signature verification, PR metadata & diff acquisition,
CodeSentinel static analysis pipeline, Step 6O Production Reports, Check Runs, Commit Statuses, and PR Security Comments.
"""

import uuid
from typing import Any, Dict, Optional

try:
    from backend.github.client import GitHubClient
    from backend.github.pr_service import acquire_pull_request
    from backend.github.publisher import publish_step_6o_report_status
    from backend.github.commenter import post_pr_security_comment, post_pr_inline_review_comments
    from backend.github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
    from backend.analysis.report_service import build_repository_report
    from backend.analysis.diff_scope import (
        parse_unified_diff,
        map_changed_lines_to_scopes,
        filter_findings_to_diff_scope,
    )
    from backend.analysis.deterministic_findings import generate_deterministic_findings
    from backend.analysis.finding_aggregator import aggregate_and_deduplicate_findings
    from backend.analysis.scope import should_exclude_path
    from ast_engine.security_analyzer import analyze_security_structure
    from backend.notifications.slack import send_slack_pr_alert_sync
except ImportError:
    from github.client import GitHubClient
    from github.pr_service import acquire_pull_request
    from github.publisher import publish_step_6o_report_status
    from github.commenter import post_pr_security_comment, post_pr_inline_review_comments
    from github.validator import (
        validate_webhook_owner,
        validate_webhook_repo,
        validate_pr_number,
        validate_commit_sha
    )
    from analysis.report_service import build_repository_report
    from analysis.diff_scope import (
        parse_unified_diff,
        map_changed_lines_to_scopes,
        filter_findings_to_diff_scope,
    )
    from analysis.deterministic_findings import generate_deterministic_findings
    from analysis.finding_aggregator import aggregate_and_deduplicate_findings
    from analysis.scope import should_exclude_path
    from ast_engine.security_analyzer import analyze_security_structure
    try:
        from notifications.slack import send_slack_pr_alert_sync
    except ImportError:
        send_slack_pr_alert_sync = None

try:
    from backend.analysis.storage.store import AnalysisStore
except ImportError:
    try:
        from analysis.storage.store import AnalysisStore
    except ImportError:
        AnalysisStore = None

import base64
import os


def _safely_persist_pr_analysis(report: Dict[str, Any], db_path: Optional[str] = None) -> None:
    """Safely persist PR analysis record into SQLite store without exposing exceptions."""
    if AnalysisStore is None or not isinstance(report, dict):
        return
    try:
        store = AnalysisStore(db_path=db_path)
        store.save_analysis(report)
    except Exception:
        pass


def _fetch_source_code_for_pr(
    owner: str,
    repository: str,
    filename: str,
    head_sha: str,
    client: Optional[GitHubClient] = None
) -> Optional[str]:
    """Attempts to fetch full source code of a file at head_sha via GitHub API or local workspace."""
    if client is not None:
        try:
            content_res = client.get(
                f"/repos/{owner}/{repository}/contents/{filename}",
                params={"ref": head_sha}
            )
            if isinstance(content_res, dict) and "content" in content_res:
                encoded = content_res.get("content", "").replace("\n", "").replace("\r", "")
                return base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            pass

    if os.path.isfile(filename):
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            pass

    return None


def _generate_pr_analysis_report(
    owner: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    changed_files: list,
    client: Optional[GitHubClient] = None,
    author: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generates a Step 6O Production Report for a PR snapshot using CodeSentinel's
    diff-scoped AST security analysis pipeline.

    Args:
        owner: Repository owner.
        repository: Repository name.
        pr_number: PR number.
        head_sha: Head commit SHA.
        changed_files: List of GitHubChangedFile objects or dicts.
        client: Optional pre-configured GitHubClient instance.
        author: Optional PR author username.

    Returns:
        Validated Step 6O Production Report dictionary.
    """
    analysis_id = f"repo_ana_pr_{uuid.uuid4().hex[:8]}"

    total_files = len(changed_files)
    analyzed_files = 0
    skipped_files = 0
    findings = []

    for f_item in changed_files:
        filename = getattr(f_item, "filename", None) or (f_item.get("filename") if isinstance(f_item, dict) else "")
        patch = getattr(f_item, "patch", None) or (f_item.get("patch") if isinstance(f_item, dict) else None)
        status = getattr(f_item, "status", None) or (f_item.get("status") if isinstance(f_item, dict) else "modified")

        if not filename or status == "removed":
            skipped_files += 1
            continue

        if should_exclude_path(filename):
            skipped_files += 1
            continue

        analyzed_files += 1

        source_code = None
        is_python = filename.endswith(".py")
        is_js = filename.endswith(".js") or filename.endswith(".jsx")

        if is_python or is_js:
            source_code = _fetch_source_code_for_pr(
                owner=owner,
                repository=repository,
                filename=filename,
                head_sha=head_sha,
                client=client
            )

        if source_code is not None:
            # 1. Parse unified diff to obtain changed lines
            diff_info = parse_unified_diff(patch) if patch else None
            affected_lines = diff_info.affected_lines if diff_info else []

            # 2. Map changed lines to enclosing AST scopes with language dispatch
            lang = "javascript" if is_js else "python"
            scopes = map_changed_lines_to_scopes(source_code, affected_lines, language=lang) if affected_lines else []

            if is_python:
                # 3. Execute deterministic AST security analysis on full source
                sec_data = analyze_security_structure(source_code, file_path=filename)
                raw_evidence = sec_data.get("security_signals", [])
                raw_findings = generate_deterministic_findings(raw_evidence)

                # 4. Scope and filter findings to changed lines/scopes
                scoped_findings = filter_findings_to_diff_scope(
                    findings=raw_findings,
                    scopes=scopes,
                    changed_lines=affected_lines,
                    file_path=filename
                )
                findings.extend(scoped_findings)

        # Fallback: check patch diff for secrets if source code wasn't analyzed
        elif patch and isinstance(patch, str):
            patch_lower = patch.lower()
            if "jwt_secret" in patch_lower or "api_key" in patch_lower or "password" in patch_lower or "secret" in patch_lower:
                if "=" in patch or ":" in patch:
                    findings.append({
                        "finding_id": f"finding_{len(findings)+1}",
                        "title": "Hardcoded Secret Literal in PR Diff",
                        "description": f"Potential hardcoded secret or API credential detected in changed file diff: {filename}",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "Security / Credentials",
                        "evidence": [
                            {
                                "document_id": filename,
                                "line_start": 1,
                                "line_end": 1,
                                "signal_type": "DIFF_SECRET_LITERAL",
                                "signal_name": "hardcoded_secret_assignment"
                            }
                        ]
                    })

    # Aggregate and deduplicate all collected findings
    file_stats = {
        "total_files": total_files,
        "analyzed_files": analyzed_files,
        "skipped_files": skipped_files
    }
    agg_result = aggregate_and_deduplicate_findings(findings, file_stats=file_stats)
    summary = agg_result.get("summary", {})
    deduped_findings = agg_result.get("findings", [])

    clean_author = str(author).strip()[:100] if author and str(author).strip() else None

    repo_dict = {
        "owner": owner,
        "repository": repository,
        "branch": f"pr/{pr_number}",
        "path": "."
    }
    if clean_author:
        repo_dict["author"] = clean_author

    raw_record = {
        "status": "success",
        "analysis_id": analysis_id,
        "repository": repo_dict,
        "summary": summary,
        "findings": deduped_findings,
        "analysis_version": "1.0"
    }
    if clean_author:
        raw_record["author"] = clean_author

    return build_repository_report(raw_record)


def orchestrate_webhook_event(
    event_type: str,
    delivery_id: str,
    payload: Dict[str, Any],
    client: Optional[GitHubClient] = None
) -> Dict[str, Any]:
    """
    Orchestrates processing of a validated GitHub webhook event.

    Args:
        event_type: GitHub event header (e.g. 'pull_request', 'push').
        delivery_id: Unique GitHub webhook delivery GUID.
        payload: Parsed JSON payload dictionary.
        client: Optional pre-configured GitHubClient instance.

    Returns:
        Structured orchestration execution result dictionary.
    """
    clean_event = str(event_type or "").strip().lower()
    api_client = client or GitHubClient()

    if not isinstance(payload, dict):
        raise ValueError("Invalid JSON webhook payload dictionary")

    # -----------------------------------------------------------------
    # 1. PULL_REQUEST EVENT ORCHESTRATION
    # -----------------------------------------------------------------
    if clean_event == "pull_request":
        pr_obj = payload.get("pull_request") or {}
        repo_obj = payload.get("repository") or {}

        raw_owner = repo_obj.get("owner", {}).get("login") if isinstance(repo_obj.get("owner"), dict) else None
        raw_repo = repo_obj.get("name")
        raw_pr_num = pr_obj.get("number") or payload.get("number")
        raw_head_sha = pr_obj.get("head", {}).get("sha") if isinstance(pr_obj.get("head"), dict) else None

        # If payload is partial / legacy test payload without head_sha, fall back to safe acknowledgement
        if not raw_owner or not raw_repo or not raw_pr_num or not raw_head_sha:
            return {
                "status": "acknowledged",
                "event": "pull_request",
                "delivery": delivery_id,
                "delivery_id": delivery_id
            }

        clean_owner = validate_webhook_owner(str(raw_owner))
        clean_repo = validate_webhook_repo(str(raw_repo))
        clean_pr_num = validate_pr_number(int(raw_pr_num))
        clean_head_sha = validate_commit_sha(str(raw_head_sha))

        # Acquire PR snapshot metadata & changed files
        snapshot = acquire_pull_request(clean_owner, clean_repo, clean_pr_num, client=api_client)

        # Extract PR author for intelligence and notification
        raw_user = pr_obj.get("user", {}) if isinstance(pr_obj, dict) else {}
        pr_author = raw_user.get("login", "unknown") if isinstance(raw_user, dict) else "unknown"

        # Execute CodeSentinel static security analysis pipeline to generate Step 6O Report
        report = _generate_pr_analysis_report(
            owner=clean_owner,
            repository=clean_repo,
            pr_number=clean_pr_num,
            head_sha=clean_head_sha,
            changed_files=snapshot.changed_files,
            client=api_client,
            author=pr_author if pr_author != "unknown" else None
        )

        # Safely persist PR analysis into SQLite store for developer and repository intelligence
        _safely_persist_pr_analysis(report)

        # Publish GitHub Check Run & Commit Status
        status_pub_res = publish_step_6o_report_status(
            owner=clean_owner,
            repository=clean_repo,
            head_sha=clean_head_sha,
            report=report,
            client=api_client
        )

        # Post / update PR Security Comment
        comment_res = post_pr_security_comment(
            owner=clean_owner,
            repository=clean_repo,
            pr_number=clean_pr_num,
            report=report,
            client=api_client
        )

        # Post / update inline PR review comments on modified lines
        inline_comment_res = None
        try:
            inline_comment_res = post_pr_inline_review_comments(
                owner=clean_owner,
                repository=clean_repo,
                pr_number=clean_pr_num,
                head_sha=clean_head_sha,
                report=report,
                changed_files=snapshot.changed_files,
                client=api_client
            )
        except Exception as inline_err:
            inline_comment_res = {
                "status": "skipped",
                "reason": f"unexpected_inline_error_{type(inline_err).__name__}",
                "comments_count": 0
            }

        # Dispatch optional Slack notification (isolated side-effect)
        slack_res = None
        if send_slack_pr_alert_sync is not None:
            try:
                pr_title = pr_obj.get("title", "") if isinstance(pr_obj, dict) else f"PR #{clean_pr_num}"
                raw_url = pr_obj.get("html_url") if isinstance(pr_obj, dict) else None
                pr_url = raw_url if raw_url and str(raw_url).startswith("https://") else f"https://github.com/{clean_owner}/{clean_repo}/pull/{clean_pr_num}"
                slack_res = send_slack_pr_alert_sync(
                    report=report,
                    pr_number=clean_pr_num,
                    pr_title=pr_title or f"PR #{clean_pr_num}",
                    pr_author=pr_author,
                    repo_full_name=f"{clean_owner}/{clean_repo}",
                    pr_url=pr_url
                )
            except Exception:
                slack_res = {"status": "failed", "reason": "unexpected_error"}

        return {
            "status": "success",
            "event": "pull_request",
            "delivery": delivery_id,
            "delivery_id": delivery_id,
            "owner": clean_owner,
            "repository": clean_repo,
            "pr_number": clean_pr_num,
            "head_sha": clean_head_sha,
            "review_status": report.get("review_status", "allow"),
            "analysis_id": report.get("analysis_id"),
            "check_run": status_pub_res.get("check_run"),
            "commit_status": status_pub_res.get("commit_status"),
            "comment": comment_res,
            "inline_comments": inline_comment_res,
            "slack_notification": slack_res
        }

    # -----------------------------------------------------------------
    # 2. PUSH EVENT SAFE ACKNOWLEDGEMENT
    # -----------------------------------------------------------------
    elif clean_event == "push":
        repo_obj = payload.get("repository") or {}
        raw_owner = repo_obj.get("owner", {}).get("login") if isinstance(repo_obj.get("owner"), dict) else None
        raw_repo = repo_obj.get("name")
        raw_sha = payload.get("after") or (payload.get("head_commit", {}).get("id") if isinstance(payload.get("head_commit"), dict) else None)

        clean_owner = validate_webhook_owner(str(raw_owner)) if raw_owner else "unknown"
        clean_repo = validate_webhook_repo(str(raw_repo)) if raw_repo else "unknown"
        clean_sha = validate_commit_sha(str(raw_sha)) if raw_sha and len(str(raw_sha)) == 40 else None

        return {
            "status": "acknowledged",
            "event": "push",
            "delivery": delivery_id,
            "delivery_id": delivery_id,
            "owner": clean_owner,
            "repository": clean_repo,
            "commit_sha": clean_sha
        }

    # -----------------------------------------------------------------
    # 3. UNSUPPORTED EVENT SAFE ACKNOWLEDGEMENT
    # -----------------------------------------------------------------
    else:
        return {
            "status": "ignored",
            "event": clean_event,
            "delivery": delivery_id,
            "delivery_id": delivery_id,
            "reason": "unsupported_event"
        }
