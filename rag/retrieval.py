"""RAG Document Retrieval Module for CodeSentinel.

Performs vector similarity search against the persistent ChromaDB collection.
Returns deterministic, JSON-serializable evidence document results while maintaining
secret masking and non-execution safety boundaries.
"""

from typing import Any, Dict, List, Optional
from rag.vector_store import get_collection, DEFAULT_COLLECTION_NAME


def retrieve_documents(
    query: str,
    top_k: int = 5,
    collection_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve relevant RAG documents for a query from the ChromaDB vector store.

    Parameters:
      query: Natural language or structural search query string.
      top_k: Maximum number of results to retrieve (default: 5).
      collection_name: Optional custom collection name (defaults to DEFAULT_COLLECTION_NAME).

    Returns:
      JSON-serializable dict containing status, query, results, and result_count.
    """
    target_coll_name = collection_name or DEFAULT_COLLECTION_NAME

    # Input Validation: Handle non-positive top_k or empty query safely
    if top_k <= 0 or not query or not query.strip():
        return {
            "status": "success",
            "query": query,
            "results": [],
            "result_count": 0,
        }

    try:
        collection = get_collection(collection_name=target_coll_name)
        total_count = collection.count()

        # Handle empty collection safely
        if total_count == 0:
            return {
                "status": "success",
                "query": query,
                "results": [],
                "result_count": 0,
            }

        # Cap n_results to total stored document count
        n_results = min(top_k, total_count)

        # Query ChromaDB collection
        query_response = collection.query(
            query_texts=[query],
            n_results=n_results,
        )

        results: List[Dict[str, Any]] = []

        ids_list = query_response.get("ids", [[]])[0]
        docs_list = query_response.get("documents", [[]])[0]
        meta_list = query_response.get("metadatas", [[]])[0]

        for doc_id, content, meta in zip(ids_list, docs_list, meta_list):
            results.append({
                "document_id": doc_id,
                "content": content,
                "metadata": meta,
            })

        return {
            "status": "success",
            "query": query,
            "results": results,
            "result_count": len(results),
        }

    except Exception as exc:
        return {
            "status": "error",
            "query": query,
            "results": [],
            "result_count": 0,
            "error_message": str(exc),
        }
