"""RAG Adapter module for CodeSentinel AST Engine.

Acts as the integration boundary between the AST Engine and the future RAG ingestion layer.
Converts source code into RAG-compatible document representations while enforcing:
  - Deterministic document IDs and ordering
  - Masking of secret literals
  - Non-execution static text handling
  - Structural evidence preservation (no severity or vulnerability verdicts)
"""

from typing import Any, Dict, List
from ast_engine.rag_documents import build_rag_documents


def prepare_ast_documents_for_rag(source_code: str, file_path: str = "") -> List[Dict[str, Any]]:
    """Prepare RAG-compatible document objects from Python source code AST evidence.

    Composes build_rag_documents() and validates compliance with the RAG ingestion contract:
      - Each item contains 'document_id', 'content', and 'metadata'
      - Metadata preserves schema_version, language, document_type, function_name, class_name, line_start, line_end, signal_type, signal_name, and source='ast_engine'
      - Raw secret values and full source code blocks are strictly excluded
    """
    rag_docs = build_rag_documents(source_code, file_path=file_path)

    # Ensure adapter output complies with standard RAG ingestion schema
    adapted_docs: List[Dict[str, Any]] = []
    for doc in rag_docs:
        meta = doc.get("metadata", {})
        adapted_docs.append({
            "document_id": doc.get("document_id"),
            "content": doc.get("content"),
            "metadata": {
                "schema_version": meta.get("schema_version", "1.0"),
                "language": meta.get("language", "python"),
                "document_type": meta.get("document_type"),
                "function_name": meta.get("function_name"),
                "class_name": meta.get("class_name"),
                "line_start": meta.get("line_start"),
                "line_end": meta.get("line_end"),
                "signal_type": meta.get("signal_type"),
                "signal_name": meta.get("signal_name"),
                "source": meta.get("source", "ast_engine"),
                "file_path": meta.get("file_path", file_path),
                "evidence_id": meta.get("evidence_id", ""),
                "category": meta.get("category", ""),
            },
        })

    return adapted_docs
