"""RAG Context Ranking and Deduplication Module for CodeSentinel.

Purpose:
  Provides a deterministic post-retrieval processing layer for CodeSentinel RAG pipeline.
  Accepts hybrid retrieval results (AST evidence and Security Knowledge Base entries),
  removes exact/near-duplicate documents, ranks items deterministically based on
  source priorities and token/metadata relevance, and limits output context.

Deterministic Ranking Strategy:
  Relevance score formula:
    relevance_score = source_priority + metadata_bonus + token_overlap_bonus

  Source Priorities:
    - AST Security Evidence (document_type == 'security_evidence'): 3.0
    - AST Function Structure (document_type == 'function_structure'): 2.0
    - AST Module Structure (document_type == 'module_structure'): 1.5
    - Security Knowledge Base (document_type == 'security_knowledge'): 1.0
    - Unknown Document Type: 0.5

  Token Overlap Bonus:
    - 0.5 * number of shared normalized alphanumeric word tokens between query and document content.

  Metadata Topic Bonus:
    - 0.25 bonus for each metadata field (signal_type, signal_name, document_type, security_topic,
      function_name, class_name, category, title) containing tokens matching the query.

Deduplication Strategy:
  1. Primary: Exact matching document_id. Keeps document with higher metadata completeness score.
  2. Secondary: Fingerprint fallback (normalized whitespace/case content). Keeps item with higher metadata completeness score.

Source Separation:
  - Preserves distinction between 'ast' (AST-derived code evidence) and 'security_knowledge' (general security knowledge).

Security Boundaries:
  - Static data handling: Never executes target source code or retrieved content.
  - Excludes raw secrets and unmasked credential strings.
  - Generates NO security verdicts, severity scores, or remediation advice.

Preparation Boundary:
  - Prepares structured, ranked evidence context for a future security reasoning layer.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple


def _extract_tokens(text: Optional[str]) -> Set[str]:
    """Extract normalized alphanumeric word tokens from a text string."""
    if not text or not isinstance(text, str):
        return set()
    cleaned = text.lower()
    tokens = set(re.findall(r"[a-zA-Z0-9]+", cleaned))
    for word in re.findall(r"\w+", cleaned):
        tokens.add(word)
    return tokens


def _count_metadata_completeness(metadata: Optional[Dict[str, Any]]) -> int:
    """Calculate metadata completeness score by counting non-empty, non-None values."""
    if not metadata or not isinstance(metadata, dict):
        return 0
    count = 0
    for k, v in metadata.items():
        if v is not None and v != "":
            count += 1
    return count


def _normalize_content_fingerprint(content: Optional[str]) -> str:
    """Normalize content text for exact fingerprint deduplication."""
    if not content or not isinstance(content, str):
        return ""
    # Strip all whitespace and convert to lowercase
    return re.sub(r"\s+", "", content.lower())


def _determine_source_category(meta: Dict[str, Any], default_category: str = "ast") -> str:
    """Determine source category ('ast' or 'security_knowledge') from document metadata."""
    doc_type = str(meta.get("document_type", "")).lower()
    source = str(meta.get("source", "")).lower()
    source_type = str(meta.get("source_type", "")).lower()

    if doc_type == "security_knowledge" or source_type == "knowledge_base" or source == "local_security_knowledge":
        return "security_knowledge"
    if source == "ast_engine" or doc_type in ("security_evidence", "function_structure", "module_structure"):
        return "ast"
    return default_category


def _calculate_source_priority(meta: Dict[str, Any]) -> float:
    """Determine deterministic base source priority score from document metadata."""
    doc_type = str(meta.get("document_type", "")).lower()

    if doc_type == "security_evidence" or meta.get("signal_type"):
        return 3.0
    elif doc_type == "function_structure":
        return 2.0
    elif doc_type == "module_structure":
        return 1.5
    elif doc_type == "security_knowledge":
        return 1.0
    return 0.5


def _calculate_token_overlap_bonus(query_tokens: Set[str], content: str) -> float:
    """Calculate deterministic token overlap bonus (0.5 per shared token)."""
    if not query_tokens or not content:
        return 0.0
    content_tokens = _extract_tokens(content)
    overlap = query_tokens.intersection(content_tokens)
    return 0.5 * len(overlap)


def _calculate_metadata_bonus(query_tokens: Set[str], meta: Dict[str, Any]) -> float:
    """Calculate deterministic metadata topic matching bonus (0.25 per matching field)."""
    if not query_tokens or not meta:
        return 0.0

    target_fields = [
        "cwe_id",
        "signal_type",
        "signal_name",
        "document_type",
        "security_topic",
        "function_name",
        "class_name",
        "category",
        "title",
    ]

    bonus = 0.0
    for field in target_fields:
        val = meta.get(field)
        if val and isinstance(val, str):
            field_tokens = _extract_tokens(val)
            if query_tokens.intersection(field_tokens):
                bonus += 0.25

    return bonus


def _calculate_cwe_bonus(query_tokens: Set[str], meta: Dict[str, Any]) -> float:
    """Calculate deterministic exact CWE match bonus (1.0 bonus for exact CWE match)."""
    if not query_tokens or not meta:
        return 0.0
    doc_cwe = str(meta.get("cwe_id", "") or "").strip().lower()
    if not doc_cwe:
        return 0.0
    cwe_tokens = _extract_tokens(doc_cwe)
    if cwe_tokens and cwe_tokens.issubset(query_tokens):
        return 1.0
    if doc_cwe.replace("-", "") in [t.replace("-", "") for t in query_tokens]:
        return 1.0
    return 0.0


def rank_and_deduplicate_context(
    hybrid_result: Optional[Dict[str, Any]],
    top_k: int = 10,
) -> Dict[str, Any]:
    """Process hybrid RAG retrieval results with deterministic deduplication and ranking.

    Parameters:
      hybrid_result: Result dict from Step 6E (retrieve_hybrid_context).
      top_k: Maximum number of ranked documents to return (default: 10).

    Returns:
      JSON-serializable dict containing status, query, results, result_count,
      ast_result_count, knowledge_result_count, deduplicated_count, and ranking_version.
    """
    if not isinstance(hybrid_result, dict):
        hybrid_result = {}

    query = str(hybrid_result.get("query", "") or "")
    raw_ast_results = hybrid_result.get("ast_results") or []
    raw_knowledge_results = hybrid_result.get("knowledge_results") or []

    if not isinstance(raw_ast_results, list):
        raw_ast_results = []
    if not isinstance(raw_knowledge_results, list):
        raw_knowledge_results = []

    ast_count = len(raw_ast_results)
    knowledge_count = len(raw_knowledge_results)

    # Handle Non-positive top_k
    if top_k <= 0:
        return {
            "status": "success",
            "query": query,
            "results": [],
            "result_count": 0,
            "ast_result_count": ast_count,
            "knowledge_result_count": knowledge_count,
            "deduplicated_count": 0,
            "ranking_version": "1.0",
        }

    # Aggregate candidate documents with source categories
    candidates: List[Tuple[Dict[str, Any], str]] = []
    for doc in raw_ast_results:
        if isinstance(doc, dict):
            candidates.append((doc, "ast"))
    for doc in raw_knowledge_results:
        if isinstance(doc, dict):
            candidates.append((doc, "security_knowledge"))

    if not candidates:
        return {
            "status": "success",
            "query": query,
            "results": [],
            "result_count": 0,
            "ast_result_count": ast_count,
            "knowledge_result_count": knowledge_count,
            "deduplicated_count": 0,
            "ranking_version": "1.0",
        }

    # -----------------------------------------------------------------------
    # Step 1: Deduplication Phase
    # -----------------------------------------------------------------------
    # Primary deduplication by document_id
    doc_id_map: Dict[str, Tuple[Dict[str, Any], str, int]] = {}

    for doc, default_cat in candidates:
        doc_id = doc.get("document_id")
        if not doc_id:
            # Generate fallback ID if missing
            doc_id = f"gen_id_{len(doc_id_map) + 1}"

        doc_id_str = str(doc_id)
        meta = doc.get("metadata") or {}
        completeness = _count_metadata_completeness(meta)

        if doc_id_str not in doc_id_map:
            doc_id_map[doc_id_str] = (doc, default_cat, completeness)
        else:
            _, _, existing_comp = doc_id_map[doc_id_str]
            if completeness > existing_comp:
                doc_id_map[doc_id_str] = (doc, default_cat, completeness)

    id_deduped_docs = list(doc_id_map.values())

    # Secondary deduplication by content fingerprint
    fingerprint_map: Dict[str, Tuple[Dict[str, Any], str, int]] = {}

    for doc, cat, completeness in id_deduped_docs:
        content = doc.get("content", "")
        fp = _normalize_content_fingerprint(content)

        if not fp:
            # Content empty, fallback to document ID as fingerprint key
            fp = f"id_fp_{doc.get('document_id', '')}"

        if fp not in fingerprint_map:
            fingerprint_map[fp] = (doc, cat, completeness)
        else:
            _, _, existing_comp = fingerprint_map[fp]
            if completeness > existing_comp:
                fingerprint_map[fp] = (doc, cat, completeness)

    deduplicated_candidates = list(fingerprint_map.values())
    deduplicated_count = len(deduplicated_candidates)

    # -----------------------------------------------------------------------
    # Step 2: Scoring Phase
    # -----------------------------------------------------------------------
    query_tokens = _extract_tokens(query)
    scored_documents: List[Dict[str, Any]] = []

    for doc, default_cat, _ in deduplicated_candidates:
        doc_id = str(doc.get("document_id", ""))
        content = str(doc.get("content", ""))
        metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}

        category = _determine_source_category(metadata, default_category=default_cat)
        priority = _calculate_source_priority(metadata)
        token_bonus = _calculate_token_overlap_bonus(query_tokens, content)
        meta_bonus = _calculate_metadata_bonus(query_tokens, metadata)
        cwe_bonus = _calculate_cwe_bonus(query_tokens, metadata)

        relevance_score = round(priority + token_bonus + meta_bonus + cwe_bonus, 4)

        scored_documents.append({
            "document_id": doc_id,
            "content": content,
            "metadata": metadata,
            "source_category": category,
            "relevance_score": relevance_score,
            "source_priority": priority,
        })

    # -----------------------------------------------------------------------
    # Step 3: Deterministic Sorting & Rank Assignment
    # -----------------------------------------------------------------------
    # Sort order: 1) relevance_score DESC, 2) source_priority DESC, 3) document_id ASC
    scored_documents.sort(key=lambda item: (-item["relevance_score"], -item["source_priority"], item["document_id"]))

    # Apply top_k cut-off
    limited_results = scored_documents[:top_k]

    # Assign 1-based consecutive ranks
    final_results: List[Dict[str, Any]] = []
    for idx, item in enumerate(limited_results, start=1):
        final_results.append({
            "document_id": item["document_id"],
            "content": item["content"],
            "metadata": item["metadata"],
            "source_category": item["source_category"],
            "rank": idx,
            "relevance_score": item["relevance_score"],
        })

    return {
        "status": "success",
        "query": query,
        "results": final_results,
        "result_count": len(final_results),
        "ast_result_count": ast_count,
        "knowledge_result_count": knowledge_count,
        "deduplicated_count": deduplicated_count,
        "ranking_version": "1.0",
    }
