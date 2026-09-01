"""Security Knowledge Document Loader and Chunking Module for CodeSentinel.

Handles validation, cleaning, and deterministic chunking of security knowledge
documents prior to vector store ingestion.
"""

from typing import Any, Dict, List, Optional


def _clean_metadata_value(val: Any) -> Any:
    """Clean a metadata value to ensure ChromaDB compatibility (str, int, float, bool)."""
    if val is None:
        return ""
    if isinstance(val, (str, int, float, bool)):
        return val
    return str(val)


def load_security_knowledge(
    documents: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Validate and prepare security knowledge documents for RAG storage.

    Parameters:
      documents: List of raw security document dicts.

    Returns:
      List of validated, cleaned security document dicts.
    """
    if not isinstance(documents, list):
        return []

    validated_docs: List[Dict[str, Any]] = []

    for doc in documents:
        if not isinstance(doc, dict):
            continue

        doc_id = doc.get("document_id")
        content = doc.get("content")
        metadata = doc.get("metadata")

        # Validate required top-level fields
        if not doc_id or not isinstance(doc_id, str):
            continue
        if content is None or not isinstance(content, str):
            continue
        if metadata is None or not isinstance(metadata, dict):
            continue

        # Clean metadata dictionary for ChromaDB primitive type safety
        cleaned_meta = {
            k: _clean_metadata_value(v)
            for k, v in metadata.items()
        }

        # Ensure document_type is set to security_knowledge
        cleaned_meta["document_type"] = "security_knowledge"
        if "source_type" not in cleaned_meta:
            cleaned_meta["source_type"] = "knowledge_base"

        validated_docs.append({
            "document_id": doc_id,
            "content": content,
            "metadata": cleaned_meta,
        })

    return validated_docs


def chunk_security_knowledge(
    document: Dict[str, Any],
    chunk_size: int = 1000,
    overlap: int = 100,
) -> List[Dict[str, Any]]:
    """Split a single security knowledge document into deterministic chunks.

    Parameters:
      document: Document dict containing 'document_id', 'content', and 'metadata'.
      chunk_size: Maximum character count per chunk (default: 1000).
      overlap: Character overlap between consecutive chunks (default: 100).

    Returns:
      List of chunk dicts, each with chunk document_id, content, and updated metadata.
    """
    if not isinstance(document, dict):
        return []

    # Validate parameters safely
    if chunk_size <= 0:
        return []
    if overlap < 0 or overlap >= chunk_size:
        return []

    doc_id = document.get("document_id")
    content = document.get("content", "")
    metadata = document.get("metadata", {})

    if not doc_id or not content or not isinstance(content, str):
        return []

    step = chunk_size - overlap
    content_len = len(content)

    if content_len == 0:
        return []

    chunks: List[Dict[str, Any]] = []
    chunk_index = 1

    start = 0
    while start < content_len:
        end = min(start + chunk_size, content_len)
        chunk_text = content[start:end]

        if chunk_text:
            chunk_id = f"{doc_id}_chunk_{chunk_index}"
            chunk_metadata = {
                k: _clean_metadata_value(v)
                for k, v in metadata.items()
            }
            chunk_metadata["document_type"] = "security_knowledge"
            chunk_metadata["parent_document_id"] = str(doc_id)
            chunk_metadata["chunk_index"] = chunk_index

            chunks.append({
                "document_id": chunk_id,
                "content": chunk_text,
                "metadata": chunk_metadata,
            })

            chunk_index += 1

        if end >= content_len:
            break
        start += step

    return chunks
