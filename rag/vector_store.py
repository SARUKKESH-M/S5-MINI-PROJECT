"""ChromaDB Vector Store Abstraction for CodeSentinel.

Provides persistent storage access for the CodeSentinel RAG pipeline.
Uses the project's centralized configuration (CHROMA_DB_PATH) and ensures
safe, deterministic collection creation and retrieval.
"""

import os
from typing import Any, Optional
import chromadb
from app.core.config import settings

# Default deterministic collection name for CodeSentinel AST evidence & knowledge
DEFAULT_COLLECTION_NAME = "codesentinel_ast_knowledge"

# Deterministic collection name for general security knowledge (Step 6D)
SECURITY_KNOWLEDGE_COLLECTION_NAME = "codesentinel_security_knowledge"

_client_instance: Optional[Any] = None


def initialize_vector_store(db_path: Optional[str] = None) -> Any:
    """Initialize or retrieve the persistent ChromaDB client instance.

    Uses db_path if specified, or defaults to settings.CHROMA_DB_PATH.
    Safe for repeated initialization calls.
    """
    global _client_instance
    target_path = db_path or settings.CHROMA_DB_PATH

    # Ensure local directory exists
    os.makedirs(target_path, exist_ok=True)

    if _client_instance is None:
        _client_instance = chromadb.PersistentClient(path=target_path)

    return _client_instance


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

