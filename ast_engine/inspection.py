"""AST Inspection Representation Module for CodeSentinel.

Generates a deterministic, user-safe, JSON-serializable structural AST inspection object
designed specifically for future rendering in a frontend visualization panel.
Treats source code strictly as static, untrusted data without dynamic execution or secret exposure.
"""

from typing import Any, Dict, List
from ast_engine.evidence_normalizer import normalize_security_evidence


def build_ast_inspection(source_code: str) -> Dict[str, Any]:
    """Build a structural AST inspection object for visual rendering.

    Returns a JSON-serializable dictionary containing:
      - schema_version
      - language
      - parse_status
      - summary (class_count, function_count, import_count, security_evidence_count)
      - imports (tree-friendly dict list)
      - classes (tree-friendly class and method objects)
      - functions (detailed structural function metadata)
      - security_evidence (normalized security evidence signals)
    """
    normalized = normalize_security_evidence(source_code)

    schema_version = normalized.get("schema_version", "1.0")
    language = normalized.get("language", "python")
    parse_status = normalized.get("parse_status", "success")

    code_summary = normalized.get("code_summary", {})
    raw_imports = normalized.get("imports", [])
    raw_functions = normalized.get("functions", [])
    security_evidence = normalized.get("security_evidence", [])

    # 1. Summary Section
    summary = {
        "class_count": code_summary.get("class_count", 0),
        "function_count": code_summary.get("function_count", 0),
        "import_count": code_summary.get("import_count", 0),
        "security_evidence_count": len(security_evidence),
    }

    # 2. Imports Section
    formatted_imports: List[Dict[str, str]] = [{"name": imp} for imp in raw_imports]

    # 3. Functions Section
    # Preserves structural data extracted from Step 5B
    functions: List[Dict[str, Any]] = raw_functions

    # 4. Classes Section
    # Map methods into their parent classes
    classes_map: Dict[str, Dict[str, Any]] = {}
    for fn in functions:
        class_name = fn.get("class_name")
        if class_name:
            if class_name not in classes_map:
                classes_map[class_name] = {
                    "name": class_name,
                    "start_line": fn.get("start_line"),
                    "end_line": fn.get("end_line"),
                    "methods": [],
                }
            else:
                # Update line range bounds
                fn_start = fn.get("start_line")
                fn_end = fn.get("end_line")
                if fn_start and (classes_map[class_name]["start_line"] is None or fn_start < classes_map[class_name]["start_line"]):
                    classes_map[class_name]["start_line"] = fn_start
                if fn_end and (classes_map[class_name]["end_line"] is None or fn_end > classes_map[class_name]["end_line"]):
                    classes_map[class_name]["end_line"] = fn_end

            classes_map[class_name]["methods"].append({
                "name": fn.get("name"),
                "is_async": fn.get("is_async", False),
            })

    classes_list = list(classes_map.values())

    return {
        "schema_version": schema_version,
        "language": language,
        "parse_status": parse_status,
        "summary": summary,
        "imports": formatted_imports,
        "classes": classes_list,
        "functions": functions,
        "security_evidence": security_evidence,
    }
