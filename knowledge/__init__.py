"""Security Knowledge Base Package for CodeSentinel.

Provides data models, loaders, sample datasets, and ingestion tools for general
security knowledge separately from AST evidence.
"""

from knowledge.models import create_knowledge_document
from knowledge.loader import load_security_knowledge, chunk_security_knowledge
from knowledge.sample_data import SAMPLE_SECURITY_KNOWLEDGE
from rag.ingestion import ingest_security_knowledge

__all__ = [
    "create_knowledge_document",
    "load_security_knowledge",
    "chunk_security_knowledge",
    "SAMPLE_SECURITY_KNOWLEDGE",
    "ingest_security_knowledge",
]
