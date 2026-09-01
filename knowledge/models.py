"""Data models and helper functions for CodeSentinel security knowledge documents.

Provides a standardized, JSON-serializable format for security knowledge documents
separately from AST-derived evidence documents.
"""

from typing import Any, Dict


def create_knowledge_document(
    document_id: str,
    title: str,
    content: str,
    source: str,
    category: str,
    security_topic: str,
    language: str = "python",
) -> Dict[str, Any]:
    """Create a standardized, JSON-serializable security knowledge document representation.

    Parameters:
      document_id: Unique deterministic identifier for the knowledge document.
      title: Human-readable title of the document.
      content: Static text content (educational guidance, secure coding rules, etc.).
      source: Source system or catalog identifier.
      category: Classification category (e.g., 'secure_coding').
      security_topic: Targeted security topic (e.g., 'sql_parameterization').
      language: Target programming language (defaults to 'python').

    Returns:
      Dict structured with document_id, content, and standard metadata.
    """
    return {
        "document_id": document_id,
        "content": content,
        "metadata": {
            "schema_version": "1.0",
            "language": language,
            "document_type": "security_knowledge",
            "title": title,
            "source": source,
            "category": category,
            "security_topic": security_topic,
            "source_type": "knowledge_base",
        },
    }
