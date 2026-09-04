"""RAG-Ready Security Evidence Normalizer for CodeSentinel.

Composes structural analysis and security evidence into a clean, deterministic,
JSON-serializable schema designed for consumption by the future RAG retrieval layer.
Treats source code strictly as static, untrusted data without dynamic execution.
"""

from typing import Any, Dict, List
from ast_engine.structural_analyzer import analyze_python_structure
from ast_engine.security_analyzer import analyze_security_structure


def normalize_security_evidence(source_code: str, file_path: str = "") -> Dict[str, Any]:
    """Normalize Python source AST evidence into a deterministic schema for RAG.

    Returns a JSON-serializable dictionary containing:
      - schema_version
      - language
      - parse_status
      - code_summary (class_count, function_count, import_count)
      - imports
      - functions
      - security_evidence (with deterministic IDs and signal details)
      - rag_context (signal_types, security_relevant)
    """
    # Compose existing structural and security analysis functions
    struct_res = analyze_python_structure(source_code)
    sec_res = analyze_security_structure(source_code, file_path=file_path)

    # Determine unified parse status
    if struct_res.get("parse_status") == "error" or sec_res.get("parse_status") == "error":
        parse_status = "error"
    elif struct_res.get("parse_status") == "has_errors" or sec_res.get("parse_status") == "has_errors":
        parse_status = "has_errors"
    else:
        parse_status = "success"

    classes = struct_res.get("classes", [])
    functions = struct_res.get("functions", [])
    imports = struct_res.get("imports", [])
    raw_signals = sec_res.get("security_signals", [])

    # Build Code Summary
    code_summary = {
        "class_count": len(classes),
        "function_count": len(functions),
        "import_count": len(imports),
    }

    # Build Normalized Security Evidence with deterministic IDs
    normalized_evidence: List[Dict[str, Any]] = []
    signal_types_order: List[str] = []
    seen_types = set()

    for idx, signal in enumerate(raw_signals, start=1):
        sig_type = signal.get("signal_type", "unknown")
        sig_name = signal.get("name", "unknown")
        sig_line = signal.get("line", 0)
        sig_evidence = signal.get("evidence", "")
        sig_vars = signal.get("related_variables", [])

        if sig_type not in seen_types:
            seen_types.add(sig_type)
            signal_types_order.append(sig_type)

        normalized_evidence.append({
            "id": signal.get("evidence_id", f"security_signal_{idx}"),
            "evidence_id": signal.get("evidence_id", f"security_signal_{idx}"),
            "file_path": signal.get("file_path", file_path),
            "type": sig_type,
            "signal_type": sig_type,
            "name": sig_name,
            "line": sig_line,
            "evidence": sig_evidence,
            "related_variables": sig_vars,
            "category": signal.get("category", ""),
            "severity": signal.get("severity", ""),
            "confidence": signal.get("confidence", ""),
            "call_name": signal.get("call_name", sig_name),
            "argument_assessment": signal.get("argument_assessment", {}),
            "message": signal.get("message", ""),
        })

    # Build RAG Context
    rag_context = {
        "signal_types": signal_types_order,
        "security_relevant": len(normalized_evidence) > 0,
    }

    return {
        "schema_version": "1.0",
        "language": "python",
        "file_path": file_path,
        "parse_status": parse_status,
        "code_summary": code_summary,
        "imports": imports,
        "functions": functions,
        "security_evidence": normalized_evidence,
        "rag_context": rag_context,
    }
