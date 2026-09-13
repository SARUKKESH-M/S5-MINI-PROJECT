"""Best-effort RAG and offline explanation enrichment for deterministic findings.

Phase 4 Architectural Invariants:
  - Deterministic AST findings are authoritative.
  - RAG retrieves security knowledge using structured signals (CWE, topic, rule type).
  - RAG query never injects raw full source code or unredacted secrets.
  - Finding properties (severity, title, evidence) cannot be modified or removed by RAG.
  - Retrieval failure degrades gracefully (findings remain intact, Step 6O unaffected).
"""

import re
from typing import Any, Dict, List, Optional

from rag.context_builder import build_security_analysis_context
from llm.provider import LLMProvider, MockLLMProvider, get_llm_provider


SIGNAL_TOPIC_MAPPING = {
    "unsafe_database_execution": "sql_injection",
    "database_execution_call": "sql_injection",
    "string_construction": "sql_injection",
    "command_execution_call": "command_execution",
    "dynamic_code_execution": "dynamic_code_execution",
    "dynamic_execution_call": "dynamic_code_execution",
    "possible_hardcoded_secret": "credential_handling",
    "credential_propagation_to_authorization_sink": "credential_handling",
    "weak_cryptography": "weak_cryptography",
    "insecure_deserialization": "deserialization",
    "path_traversal": "path_traversal",
    "cross_site_scripting": "xss",
    "dom_xss_call": "xss",
    "missing_authentication": "authentication",
    "cross_site_request_forgery": "csrf",
    "unrestricted_file_upload": "file_upload",
    "sensitive_data_exposure": "sensitive_data_exposure",
    "null_pointer_dereference": "null_reference",
}


def build_structured_rag_query(finding: Dict[str, Any]) -> str:
    """Build a structured, normalized RAG query from finding metadata without raw source code.

    Prefers structured signals:
      - CWE identifier(s)
      - Vulnerability / rule / signal type
      - Normalized security topic / category
      - Short normalized title
      - Severity hint where useful
    Never passes raw source code or unredacted secrets into the retrieval query.
    """
    if not isinstance(finding, dict):
        return "general_security"

    parts: List[str] = []

    # 1. CWE identifier
    cwe = finding.get("cwe") or finding.get("cwe_id")
    if cwe and isinstance(cwe, str) and cwe.strip():
        parts.append(cwe.strip())

    # 2. Evidence signal type
    evidence = finding.get("evidence")
    signal_type = ""
    if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict):
        signal_type = str(evidence[0].get("signal_type", "")).strip()

    topic = SIGNAL_TOPIC_MAPPING.get(signal_type)
    if topic:
        parts.append(topic)
    elif signal_type and signal_type != "unknown":
        parts.append(signal_type)

    # 3. Category
    category = finding.get("category")
    if category and isinstance(category, str) and category.strip().lower() not in ("general security", "unknown", ""):
        parts.append(category.strip())

    # 4. Title (sanitized alphanumeric tokens only, bounded length)
    title = finding.get("title")
    if title and isinstance(title, str) and title.strip():
        clean_title = " ".join(re.findall(r"[a-zA-Z0-9_\-]+", title)[:8])
        if clean_title:
            parts.append(clean_title)

    # 5. Severity hint
    sev = str(finding.get("severity", "")).lower()
    if sev in ("critical", "high"):
        parts.append(f"{sev} severity")

    # Deduplicate tokens while preserving order
    seen = set()
    deduped: List[str] = []
    for p in parts:
        for word in p.split():
            low = word.lower()
            if low not in seen:
                seen.add(low)
                deduped.append(word)

    query = " ".join(deduped).strip()
    return query or "general_security"


def _find_exact_curated_knowledge(cwe_id: str) -> Optional[Dict[str, Any]]:
    """Look up curated OWASP knowledge document by exact CWE ID."""
    if not cwe_id or not isinstance(cwe_id, str):
        return None
    clean_cwe = cwe_id.strip().upper()
    try:
        from knowledge.curated_owasp import CURATED_OWASP_KNOWLEDGE
        for doc in CURATED_OWASP_KNOWLEDGE:
            meta = doc.get("metadata", {})
            doc_cwe = str(meta.get("cwe_id", "")).strip().upper()
            if doc_cwe == clean_cwe:
                return doc
    except Exception:
        return None
    return None


def enrich_findings(
    findings: List[Dict[str, Any]],
    db_path: Optional[str] = None,
    provider: Optional[LLMProvider] = None,
) -> List[Dict[str, Any]]:
    """Attach RAG provenance and structured explanations without allowing retrieval failure to remove findings."""
    try:
        from rag.ingestion import ensure_curated_knowledge_ingested
        ensure_curated_knowledge_ingested(db_path=db_path)
    except Exception:
        pass

    try:
        from llm.explanation_contract import generate_deterministic_fallback_explanation
    except ImportError:
        from explanation_contract import generate_deterministic_fallback_explanation

    enriched: List[Dict[str, Any]] = []
    snapshots: List[Dict[str, Any]] = []

    # Request-local deduplication cache for equivalent RAG and curated knowledge queries
    rag_context_cache: Dict[str, Dict[str, Any]] = {}
    curated_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    for finding in findings:
        item = dict(finding)
        # Snapshot authoritative fields to guarantee absolute immutability
        orig_title = item.get("title")
        orig_severity = item.get("severity")
        orig_evidence = item.get("evidence")
        orig_finding_id = item.get("finding_id")
        orig_category = item.get("category")
        snapshots.append({
            "title": orig_title,
            "severity": orig_severity,
            "evidence": orig_evidence,
            "finding_id": orig_finding_id,
            "category": orig_category
        })

        retrieved_docs: List[Dict[str, Any]] = []

        # 1. Exact CWE Priority Lookup in Curated OWASP Knowledge (Cached per call)
        exact_cwe = item.get("cwe") or item.get("cwe_id")
        if exact_cwe:
            clean_cwe_key = str(exact_cwe).strip().upper()
            if clean_cwe_key in curated_cache:
                curated_match = curated_cache[clean_cwe_key]
            else:
                curated_match = _find_exact_curated_knowledge(clean_cwe_key)
                curated_cache[clean_cwe_key] = curated_match
        else:
            curated_match = None

        if curated_match:
            retrieved_docs.append(curated_match)
            item["_retrieved_knowledge_doc"] = curated_match
            if not item.get("cwe_id") and curated_match.get("metadata", {}).get("cwe_id"):
                item["cwe_id"] = curated_match["metadata"]["cwe_id"]
            if not item.get("references") and curated_match.get("metadata", {}).get("cwe_id"):
                item["references"] = [f"OWASP / {curated_match['metadata']['cwe_id']}"]
            if not item.get("security_guidance") and curated_match.get("metadata", {}).get("title"):
                item["security_guidance"] = curated_match["metadata"]["title"]

        query = build_structured_rag_query(item)

        # 2. Vector / Hybrid RAG Retrieval (Deduplicated per stable query signature)
        cache_key = f"{query.strip().lower()}::topk=3::{db_path or 'default'}"
        if cache_key in rag_context_cache:
            context = rag_context_cache[cache_key]
        else:
            try:
                context = build_security_analysis_context(query, top_k=3, db_path=db_path)
            except Exception:
                context = {}
            rag_context_cache[cache_key] = context

        if context.get("status") == "success" and context.get("security_knowledge_context_count", 0) > 0:
            item["enriched_by"] = ["rag"]
            sec_docs = context.get("context", {}).get("security_knowledge", [])
            if sec_docs:
                for d in sec_docs:
                    if d not in retrieved_docs:
                        retrieved_docs.append(d)
                top_doc = sec_docs[0]
                if not item.get("_retrieved_knowledge_doc"):
                    item["_retrieved_knowledge_doc"] = top_doc
                meta = top_doc.get("metadata", {})
                # Contextual enrichment without overriding authoritative findings
                if not item.get("cwe_id") and meta.get("cwe_id"):
                    item["cwe_id"] = meta.get("cwe_id")
                if not item.get("references") and meta.get("cwe_id"):
                    item["references"] = [f"OWASP / {meta.get('cwe_id')}"]
                if not item.get("security_guidance") and meta.get("title"):
                    item["security_guidance"] = meta.get("title")
        else:
            item["enriched_by"] = ["rag"] if curated_match else []

        item["retrieved_knowledge"] = retrieved_docs

        # Enforce authoritative immutability
        if orig_title is not None:
            item["title"] = orig_title
        if orig_severity is not None:
            item["severity"] = orig_severity
        if orig_evidence is not None:
            item["evidence"] = orig_evidence
        if orig_finding_id is not None:
            item["finding_id"] = orig_finding_id

        enriched.append(item)

    active_provider = get_llm_provider(provider=provider)
    try:
        results = active_provider.explain_findings(enriched)
    except Exception:
        results = MockLLMProvider().explain_findings(enriched)

    # Final post-processing pass: enforce structured explanation existence & restore snapshots
    finalized: List[Dict[str, Any]] = []
    for idx, res_item in enumerate(results):
        item = dict(res_item)
        snap = snapshots[idx] if idx < len(snapshots) else {}

        # Unconditional authoritative restoration
        if snap.get("title") is not None:
            item["title"] = snap["title"]
        if snap.get("severity") is not None:
            item["severity"] = snap["severity"]
        if snap.get("evidence") is not None:
            item["evidence"] = snap["evidence"]
        if snap.get("finding_id") is not None:
            item["finding_id"] = snap["finding_id"]
        if snap.get("category") is not None and not item.get("category"):
            item["category"] = snap["category"]

        # Ensure structured_explanation exists
        if not item.get("structured_explanation") or not isinstance(item.get("structured_explanation"), dict):
            k_doc = item.get("_retrieved_knowledge_doc")
            item["structured_explanation"] = generate_deterministic_fallback_explanation(item, knowledge_doc=k_doc)
            if not item.get("explanation"):
                item["explanation"] = item["structured_explanation"]["why_it_matters"]
            if not item.get("recommendation"):
                item["recommendation"] = item["structured_explanation"]["remediation"]

        # Clean internal ephemeral keys
        item.pop("_retrieved_knowledge_doc", None)
        finalized.append(item)

    return finalized
