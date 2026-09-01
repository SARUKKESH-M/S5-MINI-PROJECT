"""CodeSentinel RAG (Retrieval-Augmented Generation) package."""

from rag.vector_store import (
    initialize_vector_store,
    get_collection,
    DEFAULT_COLLECTION_NAME,
    get_security_knowledge_collection,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)
from rag.ingestion import ingest_documents, ingest_security_knowledge
from rag.retrieval import retrieve_documents
from rag.hybrid_retrieval import retrieve_hybrid_context
from rag.context_ranker import rank_and_deduplicate_context
from rag.context_builder import build_security_analysis_context

__all__ = [
    "initialize_vector_store",
    "get_collection",
    "DEFAULT_COLLECTION_NAME",
    "get_security_knowledge_collection",
    "SECURITY_KNOWLEDGE_COLLECTION_NAME",
    "ingest_documents",
    "ingest_security_knowledge",
    "retrieve_documents",
    "retrieve_hybrid_context",
    "rank_and_deduplicate_context",
    "build_security_analysis_context",
]
