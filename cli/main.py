"""
CodeSentinel — Unified Command Line Interface (CLI)

Provides developer-friendly CLI commands (analyze, scan, gate, report, health,
readiness, info, policies, metrics, version) while reusing backend services,
preserving Step 6O contracts, and maintaining 100% static analysis non-execution.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

# Ensure workspace root and backend are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from backend.analysis.security_scan import run_security_scan
    from backend.analysis.security_gate import run_security_gate, evaluate_security_gate, validate_security_report
    from backend.analysis.ci_report import generate_ci_security_summary
    from backend.analysis.policy import list_available_policies, get_policy_profile
    from backend.app.core.health import get_platform_health, get_platform_readiness
    from backend.app.core.capabilities import get_platform_capabilities
    from backend.app.core.metrics import metrics_collector
    from backend.app.core.security import sanitize_sensitive_text
    from cli.formatter import format_security_report_terminal, format_json_output, format_terminal_header
except ImportError:
    from analysis.security_scan import run_security_scan
    from analysis.security_gate import run_security_gate, evaluate_security_gate, validate_security_report
    from analysis.ci_report import generate_ci_security_summary
    from analysis.policy import list_available_policies, get_policy_profile
    from app.core.health import get_platform_health, get_platform_readiness
    from app.core.capabilities import get_platform_capabilities
    from app.core.metrics import metrics_collector
    from app.core.security import sanitize_sensitive_text
    from cli.formatter import format_security_report_terminal, format_json_output, format_terminal_header


def build_parser() -> argparse.ArgumentParser:
    """Builds the unified CodeSentinel CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="CodeSentinel — Autonomous Static Security Analysis & DevSecOps Platform CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")

    subparsers = parser.add_subparsers(dest="command", help="Available CodeSentinel CLI commands")

    # 1. analyze
    analyze_parser = subparsers.add_parser("analyze", help="Execute static security analysis on a target directory")
    analyze_parser.add_argument("-t", "--target-dir", default=".", help="Target repository directory path (default: '.')")
    analyze_parser.add_argument("-p", "--policy", default="default", choices=["default", "strict", "ci", "developer"], help="Analysis policy profile")
    analyze_parser.add_argument("-m", "--mode", default="full", choices=["full", "incremental"], help="Analysis mode")
    analyze_parser.add_argument("--changed-files", help="Comma-separated list of changed file paths for incremental mode")
    analyze_parser.add_argument("-e", "--exclude", help="Comma-separated list of fnmatch exclude patterns")
    analyze_parser.add_argument("-o", "--output", help="Optional output JSON report path")
    analyze_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 2. scan
    scan_parser = subparsers.add_parser("scan", help="Run automated static security scan and produce Step 6O report")
    scan_parser.add_argument("-t", "--target-dir", default=".", help="Target directory path (default: '.')")
    scan_parser.add_argument("-p", "--policy", default="default", choices=["default", "strict", "ci", "developer"], help="Analysis policy profile")
    scan_parser.add_argument("-o", "--output", help="Optional output JSON report path")
    scan_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 3. gate
    gate_parser = subparsers.add_parser("gate", help="Evaluate Step 6O Production Security Report against CI Security Gate")
    gate_parser.add_argument("-r", "--report", required=True, help="Path to Step 6O Production Report JSON file")
    gate_parser.add_argument("--json", action="store_true", help="Output raw JSON decision format")

    # 4. report
    report_parser = subparsers.add_parser("report", help="Format and print a Step 6O Production Report")
    report_parser.add_argument("-i", "--input", required=True, help="Path to input report JSON file")
    report_parser.add_argument("-f", "--format", default="terminal", choices=["terminal", "markdown", "json"], help="Report output format")
    report_parser.add_argument("-o", "--output", help="Optional file path to write formatted report")

    # 5. health
    health_parser = subparsers.add_parser("health", help="Check platform health diagnostics")
    health_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 6. readiness
    readiness_parser = subparsers.add_parser("readiness", help="Check platform readiness status")
    readiness_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 7. info
    info_parser = subparsers.add_parser("info", help="Display platform version and enabled capabilities")
    info_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 8. policies
    policies_parser = subparsers.add_parser("policies", help="List available security analysis policy profiles")
    policies_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 9. metrics
    metrics_parser = subparsers.add_parser("metrics", help="Display structured internal observability metrics")
    metrics_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # 10. version
    subparsers.add_parser("version", help="Display CodeSentinel CLI version information")

    return parser


def cmd_version(args: argparse.Namespace) -> int:
    """Executes 'version' command."""
    print("CodeSentinel CLI v1.0.0 (API v1)")
    print("Core Analysis Engine: Static AST + Hybrid RAG + LLM Context Builder")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Executes 'health' command."""
    health_data = get_platform_health()
    if getattr(args, "json", False):
        print(format_json_output(health_data))
    else:
        print(format_terminal_header("CodeSentinel Platform Health"))
        print(f"Status:      {health_data.get('status', 'unknown').upper()}")
        print(f"Environment: {health_data.get('environment', 'development')}")
        print("Checks:")
        for chk, details in health_data.get("checks", {}).items():
            print(f"  - {chk:<20}: [{details.get('status', 'ok').upper()}] {details.get('details', '')}")
    return 0 if health_data.get("status") in ("healthy", "degraded") else 1


def cmd_readiness(args: argparse.Namespace) -> int:
    """Executes 'readiness' command."""
    readiness_data = get_platform_readiness()
    if getattr(args, "json", False):
        print(format_json_output(readiness_data))
    else:
        ready = readiness_data.get("ready", False)
        status_str = "READY" if ready else "NOT READY"
        print(format_terminal_header("CodeSentinel Platform Readiness"))
        print(f"Status: {status_str} ({readiness_data.get('status', 'unknown')})")
    return 0 if readiness_data.get("ready", False) else 1


def cmd_info(args: argparse.Namespace) -> int:
    """Executes 'info' command."""
    info_data = get_platform_capabilities()
    if getattr(args, "json", False):
        print(format_json_output(info_data))
    else:
        print(format_terminal_header("CodeSentinel Platform Information"))
        print(f"Service:     {info_data.get('service')}")
        print(f"Version:     {info_data.get('version')}")
        print(f"API Version: {info_data.get('api_version')}")
        print("Capabilities:")
        for cap in info_data.get("enabled_capabilities", []):
            print(f"  - {cap}")
    return 0


def cmd_policies(args: argparse.Namespace) -> int:
    """Executes 'policies' command."""
    policies = list_available_policies()
    if getattr(args, "json", False):
        print(format_json_output(policies))
    else:
        print(format_terminal_header("CodeSentinel Security Policy Profiles"))
        for pol in policies:
            print(f"\nProfile: {pol['name'].upper()}")
            print(f"  Severity Threshold: {pol['severity_threshold']}")
            print(f"  Max Files:          {pol['max_files']}")
            print(f"  Review Action:      {pol['review_action']}")
            print(f"  Block Action:       {pol['block_action']}")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    """Executes 'metrics' command."""
    metrics = metrics_collector.get_summary()
    if getattr(args, "json", False):
        print(format_json_output(metrics))
    else:
        print(format_terminal_header("CodeSentinel Observability Metrics"))
        for k, v in metrics.items():
            print(f"  {k:<30}: {v}")
    return 0


def cmd_scan_or_analyze(args: argparse.Namespace) -> int:
    """Executes 'scan' or 'analyze' command."""
    target_dir = getattr(args, "target_dir", ".")
    output_path = getattr(args, "output", None)
    policy_name = getattr(args, "policy", "default")

    # Validate target directory existence
    target_p = Path(target_dir).resolve()
    if not target_p.exists():
        print(sanitize_sensitive_text(f"Error: Target directory '{target_dir}' does not exist."))
        return 1

    try:
        report = run_security_scan(target_dir=str(target_p), output_path=output_path)
    except Exception as e:
        print(sanitize_sensitive_text(f"Error executing security scan: {e}"))
        return 1

    # Output formatting
    if getattr(args, "json", False):
        print(format_json_output(report))
    else:
        print(format_security_report_terminal(report))

    # Evaluate gate exit code: ALLOW=0, REVIEW=2, BLOCK=1
    decision, exit_code, _ = evaluate_security_gate(report)
    return exit_code


def cmd_gate(args: argparse.Namespace) -> int:
    """Executes 'gate' command."""
    report_file = getattr(args, "report", None)
    if not report_file or not Path(report_file).exists():
        print(sanitize_sensitive_text(f"Error: Report file '{report_file}' not found."))
        return 1

    exit_code = run_security_gate(report_file)
    return exit_code


def cmd_report(args: argparse.Namespace) -> int:
    """Executes 'report' command."""
    input_file = getattr(args, "input", None)
    output_fmt = getattr(args, "format", "terminal")
    output_file = getattr(args, "output", None)

    if not input_file or not Path(input_file).exists():
        print(sanitize_sensitive_text(f"Error: Report file '{input_file}' not found."))
        return 1

    try:
        data_text = Path(input_file).read_text(encoding="utf-8")
        report = json.loads(data_text)
        is_valid, err, _ = validate_security_report(report)
        if not is_valid:
            print(sanitize_sensitive_text(f"Error: Invalid Step 6O report format: {err}"))
            return 1
    except Exception as e:
        print(sanitize_sensitive_text(f"Error reading report file: {e}"))
        return 1

    if output_fmt == "json":
        formatted_output = format_json_output(report)
    elif output_fmt == "markdown":
        formatted_output = generate_ci_security_summary(report)
    else:
        formatted_output = format_security_report_terminal(report)

    if output_file:
        try:
            Path(output_file).write_text(formatted_output, encoding="utf-8")
            print(f"Report written to '{output_file}'")
        except Exception as e:
            print(sanitize_sensitive_text(f"Error writing report output file: {e}"))
            return 1
    else:
        print(formatted_output)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI dispatcher entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    command_handlers = {
        "version": cmd_version,
        "health": cmd_health,
        "readiness": cmd_readiness,
        "info": cmd_info,
        "policies": cmd_policies,
        "metrics": cmd_metrics,
        "analyze": cmd_scan_or_analyze,
        "scan": cmd_scan_or_analyze,
        "gate": cmd_gate,
        "report": cmd_report,
    }

    handler = command_handlers.get(args.command)
    if handler:
        try:
            return handler(args)
        except Exception as e:
            print(sanitize_sensitive_text(f"CLI Error: {e}"))
            return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
