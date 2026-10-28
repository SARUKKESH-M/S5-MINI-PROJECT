"""RAG Document Ingestion Module for CodeSentinel.

Stores RAG-ready document objects produced by the AST Engine adapter (Step 5F)
into the persistent ChromaDB collection created in Step 6A.
Preserves all structural metadata while using upsert semantics for idempotency.
"""

import os
import threading
from typing import Any, Dict, List, Optional
from app.core.config import settings
from rag.vector_store import (
    get_collection,
    DEFAULT_COLLECTION_NAME,
    get_security_knowledge_collection,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)

_CURATED_INGESTED_LOCK = threading.Lock()
_VERIFIED_KNOWLEDGE_PATHS: set = set()


def reset_curated_knowledge_cache() -> None:
    """Reset the verified curated knowledge in-memory cache (for isolated tests)."""
    with _CURATED_INGESTED_LOCK:
        _VERIFIED_KNOWLEDGE_PATHS.clear()


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
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest a list of RAG document objects into the persistent ChromaDB vector store.

    Parameters:
      documents: List of document dicts, each with 'document_id', 'content', and 'metadata'.
      collection_name: Optional custom collection name; defaults to DEFAULT_COLLECTION_NAME.
      db_path: Optional database storage path override.

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

    collection = get_collection(collection_name=target_coll_name, db_path=db_path)

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


def ensure_curated_knowledge_ingested(
    db_path: Optional[str] = None,
    force: bool = False,
) -> Dict[str, Any]:
    """Ensure that the 12 curated OWASP/CWE knowledge documents are ingested into ChromaDB.

    Checks the dedicated security knowledge collection. If the curated catalog is already present
    and force is False, returns existing status without redundant disk writes.
    If missing or force is True, ingests CURATED_OWASP_KNOWLEDGE deterministically and idempotently.

    Thread-safe and process-cached by normalized database path.

    Parameters:
      db_path: Optional database storage path override.
      force: If True, re-upserts all documents regardless of current collection state.

    Returns:
      Dict with status, ingested_count, and collection_name.
    """
    from knowledge.curated_owasp import CURATED_OWASP_KNOWLEDGE

    target_path = os.path.normcase(os.path.abspath(db_path or settings.CHROMA_DB_PATH))

    if not force:
        with _CURATED_INGESTED_LOCK:
            if target_path in _VERIFIED_KNOWLEDGE_PATHS:
                return {
                    "status": "success",
                    "ingested_count": 0,
                    "collection_name": SECURITY_KNOWLEDGE_COLLECTION_NAME,
                    "already_present": True,
                }

    collection = get_security_knowledge_collection(db_path=db_path)
    canonical_sample_chunk_id = "knowledge_cwe_89_sql_injection_chunk_1"

    if not force and collection.count() > 0:
        try:
            existing = collection.get(ids=[canonical_sample_chunk_id])
            if existing and existing.get("ids"):
                with _CURATED_INGESTED_LOCK:
                    _VERIFIED_KNOWLEDGE_PATHS.add(target_path)
                return {
                    "status": "success",
                    "ingested_count": 0,
                    "collection_name": SECURITY_KNOWLEDGE_COLLECTION_NAME,
                    "already_present": True,
                }
        except Exception:
            pass

    res = ingest_security_knowledge(CURATED_OWASP_KNOWLEDGE, db_path=db_path)
    if isinstance(res, dict) and res.get("status") == "success":
        with _CURATED_INGESTED_LOCK:
            _VERIFIED_KNOWLEDGE_PATHS.add(target_path)

    return res


