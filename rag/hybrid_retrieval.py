"""Hybrid RAG Retrieval Module for CodeSentinel.

Queries both persistent ChromaDB collections:
  1. codesentinel_ast_knowledge (AST-derived code evidence)
  2. codesentinel_security_knowledge (General security knowledge base)

Combines retrieved context into a single deterministic, JSON-serializable output
while maintaining strict separation between AST evidence and security knowledge.
Treats all source code and retrieved documents strictly as static text without execution.
"""

from typing import Any, Dict, List, Optional
from rag.vector_store import (
    DEFAULT_COLLECTION_NAME,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
    get_security_knowledge_collection,
)
from rag.retrieval import retrieve_documents


def retrieve_hybrid_context(
    query: str,
    top_k_ast: int = 5,
    top_k_knowledge: int = 5,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve hybrid RAG context from both AST evidence and security knowledge collections.

    Parameters:
      query: Natural language or structural search query string.
      top_k_ast: Max number of AST evidence results (default: 5).
      top_k_knowledge: Max number of security knowledge results (default: 5).
      db_path: Optional database storage path override.

    Returns:
      JSON-serializable dict containing status, query, ast_results, knowledge_results,
      ast_result_count, knowledge_result_count, and total_result_count.
    """
    # 1. Empty/Whitespace Query Handling
    if not query or not query.strip():
        return {
            "status": "success",
            "query": query or "",
            "ast_results": [],
            "knowledge_results": [],
            "ast_result_count": 0,
            "knowledge_result_count": 0,
            "total_result_count": 0,
        }

    try:
        ast_results: List[Dict[str, Any]] = []
        knowledge_results: List[Dict[str, Any]] = []

        # 2. AST Evidence Retrieval (codesentinel_ast_knowledge)
        if top_k_ast > 0:
            ast_retrieval = retrieve_documents(
                query=query,
                top_k=top_k_ast,
                collection_name=DEFAULT_COLLECTION_NAME,
            )
            if ast_retrieval.get("status") == "success":
                ast_results = ast_retrieval.get("results", [])

        # 3. Security Knowledge Retrieval (codesentinel_security_knowledge)
        if top_k_knowledge > 0:
            coll = get_security_knowledge_collection(db_path=db_path)
            total_count = coll.count()

            if total_count > 0:
                n_results = min(top_k_knowledge, total_count)
                query_response = coll.query(
                    query_texts=[query],
                    n_results=n_results,
                )

                ids_list = query_response.get("ids", [[]])[0]
                docs_list = query_response.get("documents", [[]])[0]
                meta_list = query_response.get("metadatas", [[]])[0]

                for doc_id, content, meta in zip(ids_list, docs_list, meta_list):
                    knowledge_results.append({
                        "document_id": doc_id,
                        "content": content,
                        "metadata": meta,
                    })

        # 4. Construct Deterministic Combined Output
        return {
            "status": "success",
            "query": query,
            "ast_results": ast_results,
            "knowledge_results": knowledge_results,
            "ast_result_count": len(ast_results),
            "knowledge_result_count": len(knowledge_results),
            "total_result_count": len(ast_results) + len(knowledge_results),
        }

    except Exception as exc:
        return {
            "status": "error",
            "query": query,
            "ast_results": [],
            "knowledge_results": [],
            "ast_result_count": 0,
            "knowledge_result_count": 0,
            "total_result_count": 0,
            "error_message": str(exc),
        }
