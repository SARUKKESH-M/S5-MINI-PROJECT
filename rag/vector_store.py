"""ChromaDB Vector Store Abstraction for CodeSentinel.

Provides persistent storage access for the CodeSentinel RAG pipeline.
Uses the project's centralized configuration (CHROMA_DB_PATH) and ensures
safe, deterministic collection creation and retrieval.
"""

import logging
import os
import re
import threading
from typing import Any, Optional
import chromadb
from app.core.config import settings

# Default deterministic collection name for CodeSentinel AST evidence & knowledge
DEFAULT_COLLECTION_NAME = "codesentinel_ast_knowledge"

# Deterministic collection name for general security knowledge (Step 6D)
SECURITY_KNOWLEDGE_COLLECTION_NAME = "codesentinel_security_knowledge"

_PROTECTED_COLLECTIONS = {
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
}

_CLIENT_LOCK = threading.Lock()
_CLIENTS_BY_PATH: dict = {}
_client_instance: Optional[Any] = None

logger = logging.getLogger("codesentinel.rag.vector_store")


def initialize_vector_store(db_path: Optional[str] = None) -> Any:
    """Initialize or retrieve the persistent ChromaDB client instance.

    Uses db_path if specified, or defaults to settings.CHROMA_DB_PATH.
    Safe for repeated initialization calls and thread-safe across paths.
    """
    global _client_instance
    target_path = os.path.normcase(os.path.abspath(db_path or settings.CHROMA_DB_PATH))

    with _CLIENT_LOCK:
        if target_path not in _CLIENTS_BY_PATH:
            os.makedirs(target_path, exist_ok=True)
            client = chromadb.PersistentClient(path=target_path)
            _CLIENTS_BY_PATH[target_path] = client
            if _client_instance is None or target_path == os.path.normcase(os.path.abspath(settings.CHROMA_DB_PATH)):
                _client_instance = client
        return _CLIENTS_BY_PATH[target_path]


def get_collection(
    collection_name: str = DEFAULT_COLLECTION_NAME,
    db_path: Optional[str] = None,
) -> Any:
    """Retrieve or create a deterministic ChromaDB collection.

    Repeated calls are safe and will return the existing collection.
    """
    client = initialize_vector_store(db_path=db_path)
    # get_or_create_collection guarantees idempotency and safety on repeated calls
    collection = client.get_or_create_collection(name=collection_name)
    return collection


def get_security_knowledge_collection(db_path: Optional[str] = None) -> Any:
    """Retrieve or create the dedicated security knowledge ChromaDB collection.

    Guarantees isolation from codesentinel_ast_knowledge.
    Repeated calls are safe and idempotent.
    """
    return get_collection(
        collection_name=SECURITY_KNOWLEDGE_COLLECTION_NAME,
        db_path=db_path,
    )


def generate_transient_ast_collection_name(analysis_id: str) -> str:
    """Deterministically generates a safe, valid ChromaDB collection name for an analysis run.

    ChromaDB requirements: 3-63 characters, starts and ends with alphanumeric, only [a-zA-Z0-9_-].
    """
    clean_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(analysis_id or "run")).strip("_")
    if not clean_id:
        clean_id = "run"
    candidate = f"ast_{clean_id}"
    if len(candidate) > 63:
        candidate = candidate[:63]
    if not candidate[-1].isalnum():
        candidate = candidate[:-1] + "0"
    return candidate


def delete_transient_collection(collection_name: Optional[str], db_path: Optional[str] = None) -> bool:
    """Safely deletes an analysis-scoped transient ChromaDB collection.

    Guards against deleting permanent knowledge collections or empty names.
    Logs failure through safe observability without exposing source code, secrets, or credentials.
    Returns True if successfully deleted, False otherwise. Never raises on missing collection.
    """
    if not collection_name or not isinstance(collection_name, str):
        return False

    clean_name = collection_name.strip()
    if not clean_name:
        return False

    if clean_name in _PROTECTED_COLLECTIONS:
        logger.warning("Refusing to delete protected collection: name=%s", clean_name)
        return False

    try:
        client = initialize_vector_store(db_path=db_path)
        client.delete_collection(name=clean_name)
        return True
    except Exception as exc:
        logger.warning(
            "Failed to delete transient collection: name=%s, error_type=%s",
            clean_name,
            type(exc).__name__,
        )
        return False
