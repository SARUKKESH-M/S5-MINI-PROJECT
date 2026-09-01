"""RAG Document Preparation module for CodeSentinel.

Converts normalized AST and security evidence into small, deterministic, RAG-ready document objects.
Treats source code strictly as static, untrusted data without dynamic execution or secret exposure.
"""

from typing import Any, Dict, List
from ast_engine.evidence_normalizer import normalize_security_evidence


def build_rag_documents(source_code: str) -> List[Dict[str, Any]]:
    """Build deterministic RAG document objects from normalized AST evidence.

    Converts normalized evidence into a list of documents:
      - 1 module_structure document
      - N function_structure documents
      - N security_evidence documents

    Returns JSON-serializable list of document dictionaries.
    """
    normalized = normalize_security_evidence(source_code)
    documents: List[Dict[str, Any]] = []

    schema_version = normalized.get("schema_version", "1.0")
    language = normalized.get("language", "python")
    parse_status = normalized.get("parse_status", "success")

    code_summary = normalized.get("code_summary", {})
    imports = normalized.get("imports", [])
    functions = normalized.get("functions", [])
    security_evidence = normalized.get("security_evidence", [])

    # 1. MODULE STRUCTURE DOCUMENT
    class_count = code_summary.get("class_count", 0)
    function_count = code_summary.get("function_count", 0)
    import_count = code_summary.get("import_count", 0)

    imports_str = ", ".join(imports) if imports else "none"

    # Gather class and function names for module summary
    func_names = [f.get("name", "anonymous") for f in functions if f.get("name")]
    func_names_str = ", ".join(func_names) if func_names else "none"

    # Gather unique class names from functions or summary
    class_names = list(dict.fromkeys([f.get("class_name") for f in functions if f.get("class_name")]))
    class_names_str = ", ".join(class_names) if class_names else "none"

    module_content = (
        f"Python module contains {class_count} class(es), {function_count} function(s), and {import_count} import(s).\n"
        f"Parse status: {parse_status}.\n"
        f"Imports: {imports_str}.\n"
        f"Classes: {class_names_str}.\n"
        f"Functions: {func_names_str}."
    )

    documents.append({
        "document_id": "module_structure_1",
        "content": module_content,
        "metadata": {
            "schema_version": schema_version,
            "language": language,
            "document_type": "module_structure",
            "function_name": None,
            "class_name": None,
            "line_start": None,
            "line_end": None,
            "signal_type": None,
            "signal_name": None,
            "source": "ast_engine",
        },
    })

    # 2. FUNCTION STRUCTURE DOCUMENTS
    for idx, fn in enumerate(functions, start=1):
        fn_name = fn.get("name", "anonymous")
        is_async = fn.get("is_async", False)
        is_method = fn.get("is_method", False)
        class_name = fn.get("class_name")
        params = fn.get("parameters", [])
        return_cnt = fn.get("return_statement_count", 0)
        start_line = fn.get("start_line")
        end_line = fn.get("end_line")
        calls = fn.get("calls", [])
        assigns = fn.get("assignments", [])
        cf = fn.get("control_flow", {})

        params_str = ", ".join(params) if params else "none"
        calls_str = ", ".join(calls) if calls else "none"
        assigns_str = ", ".join(assigns) if assigns else "none"
        cf_str = f"if={cf.get('if', 0)}, for={cf.get('for', 0)}, while={cf.get('while', 0)}, try={cf.get('try', 0)}, except={cf.get('except', 0)}, with={cf.get('with', 0)}"

        sync_str = "asynchronous" if is_async else "synchronous"
        method_str = f"method in class {class_name}" if is_method and class_name else ("method" if is_method else "top-level function")

        fn_content = (
            f"Function {fn_name} is a {sync_str} {method_str}.\n"
            f"Parameters: {params_str}.\n"
            f"Return statements: {return_cnt}.\n"
            f"Calls: {calls_str}.\n"
            f"Assignments: {assigns_str}.\n"
            f"Control flow: {cf_str}."
        )

        documents.append({
            "document_id": f"function_structure_{idx}",
            "content": fn_content,
            "metadata": {
                "schema_version": schema_version,
                "language": language,
                "document_type": "function_structure",
                "function_name": fn_name,
                "class_name": class_name,
                "line_start": start_line,
                "line_end": end_line,
                "signal_type": None,
                "signal_name": None,
                "source": "ast_engine",
            },
        })

    # 3. SECURITY EVIDENCE DOCUMENTS
    for idx, ev in enumerate(security_evidence, start=1):
        sig_type = ev.get("type", "unknown")
        sig_name = ev.get("name", "unknown")
        sig_line = ev.get("line")
        sig_evidence = ev.get("evidence", "")
        sig_vars = ev.get("related_variables", [])

        vars_str = ", ".join(sig_vars) if sig_vars else "none"

        sec_content = (
            f"Security evidence: {sig_type}.\n"
            f"Name: {sig_name}.\n"
            f"Line: {sig_line}.\n"
            f"Evidence: {sig_evidence}.\n"
            f"Related variables: {vars_str}."
        )

        documents.append({
            "document_id": f"security_evidence_{idx}",
            "content": sec_content,
            "metadata": {
                "schema_version": schema_version,
                "language": language,
                "document_type": "security_evidence",
                "function_name": None,
                "class_name": None,
                "line_start": sig_line,
                "line_end": sig_line,
                "signal_type": sig_type,
                "signal_name": sig_name,
                "source": "ast_engine",
            },
        })

    return documents
