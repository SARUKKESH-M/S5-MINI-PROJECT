"""AST Engine package for CodeSentinel using Tree-sitter."""

from ast_engine.python_parser import parse_python_source, extract_function_names
from ast_engine.structural_analyzer import analyze_python_structure
from ast_engine.security_analyzer import analyze_security_structure
from ast_engine.evidence_normalizer import normalize_security_evidence
from ast_engine.rag_documents import build_rag_documents
from ast_engine.rag_adapter import prepare_ast_documents_for_rag
from ast_engine.inspection import build_ast_inspection

__all__ = [
    "parse_python_source",
    "extract_function_names",
    "analyze_python_structure",
    "analyze_security_structure",
    "normalize_security_evidence",
    "build_rag_documents",
    "prepare_ast_documents_for_rag",
    "build_ast_inspection",
]
