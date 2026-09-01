"""RAG Document Ingestion Module for CodeSentinel.

Stores RAG-ready document objects produced by the AST Engine adapter (Step 5F)
into the persistent ChromaDB collection created in Step 6A.
Preserves all structural metadata while using upsert semantics for idempotency.
"""

from typing import Any, Dict, List, Optional
from rag.vector_store import (
    get_collection,
    DEFAULT_COLLECTION_NAME,
    get_security_knowledge_collection,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)


def _clean_metadata_for_chroma(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Clean metadata dictionary to ensure compatibility with ChromaDB types.

    Converts None values to empty strings or suitable primitive defaults
    since ChromaDB requires str, int, float, or bool values in metadata dicts.
    """
    cleaned: Dict[str, Any] = {}
    for key, val in metadata.items():
        if val is None:
            cleaned[key] = ""
        elif isinstance(val, (str, int, float, bool)):
            cleaned[key] = val
        else:
            cleaned[key] = str(val)
    return cleaned


def ingest_documents(
    documents: List[Dict[str, Any]],
    collection_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest a list of RAG document objects into the persistent ChromaDB vector store.

    Parameters:
      documents: List of document dicts, each with 'document_id', 'content', and 'metadata'.
      collection_name: Optional custom collection name; defaults to DEFAULT_COLLECTION_NAME.

    Returns:
      Summary dict containing status, ingested_count, and collection_name.
    """
    target_coll_name = collection_name or DEFAULT_COLLECTION_NAME

    if not documents:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    ids: List[str] = []
    contents: List[str] = []
    metadatas: List[Dict[str, Any]] = []

    for doc in documents:
        doc_id = doc.get("document_id")
        content = doc.get("content", "")
        meta = doc.get("metadata", {})

        if doc_id and content:
            ids.append(str(doc_id))
            contents.append(str(content))
            metadatas.append(_clean_metadata_for_chroma(meta))

    if not ids:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    collection = get_collection(collection_name=target_coll_name)

    # Use upsert to guarantee idempotency and avoid duplicate ID errors
    collection.upsert(
        ids=ids,
        documents=contents,
        metadatas=metadatas,
    )

    return {
        "status": "success",
        "ingested_count": len(ids),
        "collection_name": target_coll_name,
    }


def ingest_security_knowledge(
    documents: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest general security knowledge documents into the dedicated ChromaDB collection.

    Flow:
      Security Knowledge Documents
              ↓
      load_security_knowledge()
              ↓
      chunk_security_knowledge()
              ↓
      codesentinel_security_knowledge

    Parameters:
      documents: List of raw security document dicts.
      db_path: Optional database storage path override.

    Returns:
      Dict with status, ingested_count (number of chunks ingested), and collection_name.
    """
    from knowledge.loader import load_security_knowledge, chunk_security_knowledge

    target_coll_name = SECURITY_KNOWLEDGE_COLLECTION_NAME

    if not documents or not isinstance(documents, list):
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 1: Load and validate documents
    validated_docs = load_security_knowledge(documents)

    if not validated_docs:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 2: Chunk each validated document
    all_chunks: List[Dict[str, Any]] = []
    for doc in validated_docs:
        doc_chunks = chunk_security_knowledge(doc)
        all_chunks.extend(doc_chunks)

    if not all_chunks:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 3: Prepare vectors for ChromaDB upsert
    ids: List[str] = []
    contents: List[str] = []
    metadatas: List[Dict[str, Any]] = []

    for chunk in all_chunks:
        chunk_id = chunk.get("document_id")
        content = chunk.get("content", "")
        meta = chunk.get("metadata", {})

        if chunk_id and content:
            ids.append(str(chunk_id))
            contents.append(str(content))
            metadatas.append(_clean_metadata_for_chroma(meta))

    if not ids:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 4: Upsert into codesentinel_security_knowledge collection
    collection = get_security_knowledge_collection(db_path=db_path)
    collection.upsert(
        ids=ids,
        documents=contents,
        metadatas=metadatas,
    )

    return {
        "status": "success",
        "ingested_count": len(ids),
        "collection_name": target_coll_name,
    }

