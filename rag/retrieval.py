"""RAG Document Retrieval Module for CodeSentinel.

Performs vector similarity search against the persistent ChromaDB collection.
Returns deterministic, JSON-serializable evidence document results while maintaining
secret masking and non-execution safety boundaries.
"""

import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional
from rag.vector_store import get_collection, DEFAULT_COLLECTION_NAME

MAX_QUERY_CACHE_SIZE = 512
_QUERY_EMB_CACHE: "OrderedDict[str, List[List[float]]]" = OrderedDict()
_QUERY_EMB_LOCK = threading.Lock()


def get_query_embedding(query: str, collection: Any = None) -> Optional[List[List[float]]]:
    """Retrieve or compute cached query embedding vector using ChromaDB's embedding function."""
    if not query or not query.strip():
        return None
    with _QUERY_EMB_LOCK:
        if query in _QUERY_EMB_CACHE:
            _QUERY_EMB_CACHE.move_to_end(query)
            return _QUERY_EMB_CACHE[query]

    if collection is not None and hasattr(collection, "_embedding_function") and collection._embedding_function:
        try:
            computed = collection._embedding_function([query])
            if computed is not None and len(computed) > 0:
                emb = [list(e) if not isinstance(e, list) else e for e in computed]
                with _QUERY_EMB_LOCK:
                    _QUERY_EMB_CACHE[query] = emb
                    if len(_QUERY_EMB_CACHE) > MAX_QUERY_CACHE_SIZE:
                        _QUERY_EMB_CACHE.popitem(last=False)
                return emb
        except Exception:
            pass
    return None


def reset_query_embedding_cache() -> None:
    """Clear query embedding cache."""
    with _QUERY_EMB_LOCK:
        _QUERY_EMB_CACHE.clear()


def retrieve_documents(
    query: str,
    top_k: int = 5,
    collection_name: Optional[str] = None,
    query_embeddings: Optional[List[List[float]]] = None,
) -> Dict[str, Any]:
    """Retrieve relevant RAG documents for a query from the ChromaDB vector store.

    Parameters:
      query: Natural language or structural search query string.
      top_k: Maximum number of results to retrieve (default: 5).
      collection_name: Optional custom collection name (defaults to DEFAULT_COLLECTION_NAME).
      query_embeddings: Optional precomputed query embedding vector to bypass re-embedding.

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

        # Attempt to resolve query embedding
        q_emb = query_embeddings
        if q_emb is None:
            q_emb = get_query_embedding(query, collection=collection)

        # Query ChromaDB collection
        query_response = None
        if q_emb is not None:
            try:
                query_response = collection.query(
                    query_embeddings=q_emb,
                    n_results=n_results,
                )
            except Exception:
                query_response = None

        if query_response is None:
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
