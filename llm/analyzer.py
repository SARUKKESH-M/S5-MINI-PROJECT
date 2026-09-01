"""LLM Security Analysis Engine for CodeSentinel.

Consumes Step 6G LLM-ready security context and executes structured security analysis
via MockLLMProvider. Enforces strict evidence grounding, exact finding schema sanitization,
MAX_FINDINGS / MAX_DESCRIPTION_LENGTH bounds, and prompt injection safety.
"""

from typing import Any, Dict, List, Optional, Set
from llm.provider import LLMProvider, MockLLMProvider
from llm.client import LLMClient
from llm.prompts import SYSTEM_PROMPT, build_analysis_user_prompt

MAX_FINDINGS = 20
MAX_DESCRIPTION_LENGTH = 2000

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical", "unknown"}
ALLOWED_CONFIDENCES = {"low", "medium", "high"}

FORBIDDEN_RAW_SOURCE_FIELDS = {
    "source_code",
    "raw_source",
    "full_source",
    "original_source",
    "code",
    "raw_code",
}


def _sanitize_context_for_provider(context_input: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively strip raw-source code fields before forwarding to provider."""
    if isinstance(context_input, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in context_input.items():
            if k in FORBIDDEN_RAW_SOURCE_FIELDS:
                continue
            cleaned[k] = _sanitize_context_for_provider(v)
        return cleaned
    elif isinstance(context_input, list):
        return [_sanitize_context_for_provider(item) for item in context_input]
    return context_input


def _collect_valid_document_ids(context_input: Dict[str, Any]) -> Set[str]:
    """Collect all valid document_ids present in the Step 6G context input."""
    valid_ids: Set[str] = set()

    if not isinstance(context_input, dict):
        return valid_ids

    ctx = context_input.get("context", {})
    if isinstance(ctx, dict):
        for section_name in ("security_evidence", "code_structure", "security_knowledge"):
            section = ctx.get(section_name, [])
            if isinstance(section, list):
                for item in section:
                    if isinstance(item, dict) and item.get("document_id"):
                        valid_ids.add(str(item["document_id"]))

    ctx_docs = context_input.get("context_documents", [])
    if isinstance(ctx_docs, list):
        for item in ctx_docs:
            if isinstance(item, dict) and item.get("document_id"):
                valid_ids.add(str(item["document_id"]))

    return valid_ids


def analyze_security_context(
    context_input: Optional[Dict[str, Any]],
    provider: Optional[LLMProvider] = None,
) -> Dict[str, Any]:
    """Perform security finding analysis on Step 6G context.

    Parameters:
      context_input: Output dictionary from Step 6G (build_security_analysis_context).
      provider: Optional LLMProvider instance (defaults to MockLLMProvider).

    Returns:
      JSON-serializable summary and list of validated, grounded structured findings.
    """
    if not isinstance(context_input, dict) or context_input.get("status") != "success":
        return {
            "status": "success",
            "query": "",
            "summary": {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
            "findings": [],
            "provider": "mock",
            "analysis_version": "1.0",
            "finding_count": 0,
        }

    query = str(context_input.get("query", ""))
    valid_doc_ids = _collect_valid_document_ids(context_input)
    sanitized_context = _sanitize_context_for_provider(context_input)

    user_prompt = build_analysis_user_prompt(sanitized_context)
    active_provider = provider or MockLLMProvider()

    raw_response = active_provider.analyze(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        context_input=sanitized_context,
    )

    raw_findings = raw_response.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []

    validated_findings: List[Dict[str, Any]] = []

    for raw_finding in raw_findings:
        if not isinstance(raw_finding, dict):
            continue

        title = str(raw_finding.get("title") or "Security Finding")
        description = str(raw_finding.get("description") or "")
        category = str(raw_finding.get("category") or "General Security")

        # 1. Truncate description > MAX_DESCRIPTION_LENGTH (2000 chars)
        if len(description) > MAX_DESCRIPTION_LENGTH:
            description = description[:MAX_DESCRIPTION_LENGTH] + "...[truncated]"

        # 2. Sanitize Severity enum
        sev_raw = str(raw_finding.get("severity", "unknown")).lower()
        severity = sev_raw if sev_raw in ALLOWED_SEVERITIES else "unknown"

        # 3. Sanitize Confidence enum
        conf_raw = str(raw_finding.get("confidence", "low")).lower()
        confidence = conf_raw if conf_raw in ALLOWED_CONFIDENCES else "low"

        # 4. Filter & Validate Grounded Evidence
        raw_evidence = raw_finding.get("evidence", [])
        if not isinstance(raw_evidence, list):
            raw_evidence = []

        valid_evidence: List[Dict[str, Any]] = []
        for ev_item in raw_evidence:
            if not isinstance(ev_item, dict):
                continue

            doc_id = str(ev_item.get("document_id", ""))
            # Strict Evidence Grounding: Discard evidence referencing unknown document IDs
            if not doc_id or doc_id not in valid_doc_ids:
                continue

            line_start = ev_item.get("line_start")
            line_end = ev_item.get("line_end")

            valid_evidence.append({
                "document_id": doc_id,
                "line_start": line_start if isinstance(line_start, int) else None,
                "line_end": line_end if isinstance(line_end, int) else None,
                "signal_type": str(ev_item.get("signal_type") or "unknown"),
                "signal_name": str(ev_item.get("signal_name") or "unknown"),
            })

        # Discard finding if zero valid evidence items remain
        if not valid_evidence:
            continue

        # Construct exact, clean finding schema (NO remediation, NO cwe_id, NO severity_score)
        validated_findings.append({
            "finding_id": "", # Assigned sequentially below
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "evidence": valid_evidence,
        })

    # 5. Limit Findings to MAX_FINDINGS (20 max) & Assign Deterministic IDs
    bounded_findings = validated_findings[:MAX_FINDINGS]
    final_findings: List[Dict[str, Any]] = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for idx, f in enumerate(bounded_findings, start=1):
        f["finding_id"] = f"finding_{idx}"
        final_findings.append(f)

        sev = f["severity"]
        if sev in counts:
            counts[sev] += 1

    summary = {
        "total_findings": len(final_findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
    }

    return {
        "status": "success",
        "query": query,
        "summary": summary,
        "findings": final_findings,
        "provider": raw_response.get("provider", "mock"),
        "analysis_version": "1.0",
        "finding_count": len(final_findings),
    }
