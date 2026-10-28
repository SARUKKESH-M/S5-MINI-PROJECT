"""RAG Context Builder Module for CodeSentinel.

Purpose:
  Creates the final structured context layer for CodeSentinel RAG pipeline.
  Transforms ranked and deduplicated retrieval results (from Steps 6E & 6F) into an
  LLM-ready security analysis context object.

Context Size Boundaries:
  - MAX_CONTEXT_DOCUMENTS: 20 (caps total returned context documents).
  - MAX_CONTENT_LENGTH: 4000 (truncates oversized content strings deterministically).

Categorization Scheme:
  - context["security_evidence"]: AST-derived security evidence signals.
  - context["code_structure"]: AST function/module structures and unknown/fallback types.
  - context["security_knowledge"]: General security knowledge base entries.

Security & Safety Boundaries:
  - Static context construction only: Never calls an LLM, model API, or external network endpoint.
  - Never executes target source code.
  - Excludes raw, unmasked source code blocks and secret literals.
  - Generates NO vulnerability verdicts, severity scores, confidence ratings, or remediation advice.

Preparation Boundary:
  - Prepares structured, bounded, deterministic context for a future security reasoning stage.
"""

from typing import Any, Dict, List, Optional
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.context_ranker import rank_and_deduplicate_context

MAX_CONTEXT_DOCUMENTS = 20
MAX_CONTENT_LENGTH = 4000


def build_security_analysis_context(
    query: str,
    top_k: int = 5,
    db_path: Optional[str] = None,
    ast_collection_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an LLM-ready security analysis context object from RAG retrieval and ranking.

    Parameters:
      query: Natural language or structural search query string.
      top_k: Max candidate documents requested per collection before context limits (default: 5).
      db_path: Optional database storage path override.
      ast_collection_name: Optional analysis-scoped AST collection name (defaults to DEFAULT_COLLECTION_NAME).

    Returns:
      JSON-serializable dict containing status, query, context (sectioned documents),
      context_documents, context_document_count, ast_context_count,
      security_knowledge_context_count, and context_version.
    """
    # 1. Empty/Whitespace Query or Invalid top_k Handling
    if not query or not query.strip() or top_k <= 0:
        return {
            "status": "success",
            "query": query or "",
            "context": {
                "security_evidence": [],
                "code_structure": [],
                "security_knowledge": [],
            },
            "context_documents": [],
            "context_document_count": 0,
            "ast_context_count": 0,
            "security_knowledge_context_count": 0,
            "context_version": "1.0",
        }

    try:
        # 2. Step 6E: Hybrid RAG Retrieval
        hybrid_res = retrieve_hybrid_context(
            query=query,
            top_k_ast=top_k,
            top_k_knowledge=top_k,
            db_path=db_path,
            ast_collection_name=ast_collection_name,
        )

        # 3. Step 6F: Ranking & Deduplication across all retrieved candidates
        ranked_res = rank_and_deduplicate_context(
            hybrid_result=hybrid_res,
            top_k=MAX_CONTEXT_DOCUMENTS * 2,
        )

        ranked_docs = ranked_res.get("results") or []
        if not isinstance(ranked_docs, list):
            ranked_docs = []

        # 4. Deterministic Balanced Selection:
        # Prevent high-priority AST evidence from starving relevant security knowledge.
        ast_candidates = [d for d in ranked_docs if d.get("source_category") == "ast"]
        knowledge_candidates = [d for d in ranked_docs if d.get("source_category") == "security_knowledge"]

        # Target quota per category is bounded by top_k and half of MAX_CONTEXT_DOCUMENTS
        category_quota = min(top_k, MAX_CONTEXT_DOCUMENTS // 2)

        selected_ast = ast_candidates[:category_quota]
        selected_knowledge = knowledge_candidates[:category_quota]

        # If one category underfills its quota, allow the other to utilize remaining capacity
        remaining_slots = MAX_CONTEXT_DOCUMENTS - (len(selected_ast) + len(selected_knowledge))
        if remaining_slots > 0:
            if len(ast_candidates) > len(selected_ast):
                extra_ast = ast_candidates[len(selected_ast) : len(selected_ast) + remaining_slots]
                selected_ast.extend(extra_ast)
                remaining_slots -= len(extra_ast)
            if remaining_slots > 0 and len(knowledge_candidates) > len(selected_knowledge):
                extra_kn = knowledge_candidates[len(selected_knowledge) : len(selected_knowledge) + remaining_slots]
                selected_knowledge.extend(extra_kn)

        combined_selected = selected_ast + selected_knowledge
        # Sort combined selection deterministically by relevance_score DESC, document_id ASC
        combined_selected.sort(key=lambda item: (-item.get("relevance_score", 0.0), str(item.get("document_id", ""))))

        # Apply strict MAX_CONTEXT_DOCUMENTS bound and reassign 1-based ranks
        bounded_docs = combined_selected[:MAX_CONTEXT_DOCUMENTS]
        for idx, item in enumerate(bounded_docs, start=1):
            item["rank"] = idx

        security_evidence_list: List[Dict[str, Any]] = []
        code_structure_list: List[Dict[str, Any]] = []
        security_knowledge_list: List[Dict[str, Any]] = []
        context_documents: List[Dict[str, Any]] = []

        ast_context_count = 0
        security_knowledge_context_count = 0

        for item in bounded_docs:
            if not isinstance(item, dict):
                continue

            doc_id = str(item.get("document_id", ""))
            raw_content = str(item.get("content", ""))
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            source_cat = str(item.get("source_category", "ast"))
            rank = item.get("rank", 1)
            rel_score = item.get("relevance_score", 0.0)

            # Content length protection: Truncate content exceeding MAX_CONTENT_LENGTH
            if len(raw_content) > MAX_CONTENT_LENGTH:
                content = raw_content[:MAX_CONTENT_LENGTH] + "...[truncated]"
            else:
                content = raw_content

            doc_type = str(metadata.get("document_type", "unknown"))

            # Track counts by source category
            if source_cat == "ast":
                ast_context_count += 1
            elif source_cat == "security_knowledge":
                security_knowledge_context_count += 1

            formatted_doc = {
                "document_id": doc_id,
                "content": content,
                "metadata": metadata,
                "source_category": source_cat,
                "document_type": doc_type,
                "rank": rank,
                "relevance_score": rel_score,
            }

            context_documents.append(formatted_doc)

            # Categorize document into context sections
            doc_type_lower = doc_type.lower()
            if doc_type_lower == "security_evidence" or (source_cat == "ast" and metadata.get("signal_type")):
                security_evidence_list.append(formatted_doc)
            elif doc_type_lower == "security_knowledge" or source_cat == "security_knowledge":
                security_knowledge_list.append(formatted_doc)
            else:
                # function_structure, module_structure, or unknown types go to code_structure
                code_structure_list.append(formatted_doc)

        return {
            "status": "success",
            "query": query,
            "context": {
                "security_evidence": security_evidence_list,
                "code_structure": code_structure_list,
                "security_knowledge": security_knowledge_list,
            },
            "context_documents": context_documents,
            "context_document_count": len(context_documents),
            "ast_context_count": ast_context_count,
            "security_knowledge_context_count": security_knowledge_context_count,
            "context_version": "1.0",
        }

    except Exception as exc:
        return {
            "status": "error",
            "query": query,
            "context": {
                "security_evidence": [],
                "code_structure": [],
                "security_knowledge": [],
            },
            "context_documents": [],
            "context_document_count": 0,
            "ast_context_count": 0,
            "security_knowledge_context_count": 0,
            "context_version": "1.0",
            "error_message": str(exc),
        }
