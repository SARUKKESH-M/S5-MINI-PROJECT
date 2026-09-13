"""Structured Explanation Contract and Deterministic Fallback Engine for CodeSentinel.

Phase 34: LLM/RAG Security Explanation V2
Enforces a bounded, validated, evidence-grounded explanation schema for authoritative
findings. Guarantees that model-generated text is subordinate to deterministic signals
and cannot alter security decisions or leak raw secrets.
"""

from typing import Any, Dict, List, Optional
import re

try:
    from backend.app.core.security import sanitize_sensitive_text
except ImportError:
    try:
        from app.core.security import sanitize_sensitive_text
    except ImportError:
        def sanitize_sensitive_text(text: str) -> str:
            return text


# Bounded field length limits (characters)
MAX_SUMMARY_LEN = 300
MAX_WHY_IT_MATTERS_LEN = 1000
MAX_EVIDENCE_EXPLANATION_LEN = 800
MAX_ATTACK_SCENARIO_LEN = 1000
MAX_REMEDIATION_LEN = 1000
MAX_SAFER_PATTERN_LEN = 1200
MAX_LIMITATIONS_LEN = 400
MAX_REFERENCES_COUNT = 5
MAX_REFERENCE_ITEM_LEN = 120


def _clean_str(val: Any, max_len: int, fallback: str = "") -> str:
    """Cleans and bounds a string field safely."""
    if val is None:
        return fallback
    text = str(val).strip()
    if not text:
        return fallback
    # Strip potential HTML script tags or dangerous markdown injection
    text = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "[REDACTED_SCRIPT]", text, flags=re.DOTALL | re.IGNORECASE)
    text = sanitize_sensitive_text(text)
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def _clean_references(refs: Any, cwe_hint: Optional[str] = None) -> List[str]:
    """Validates and bounds reference list."""
    cleaned: List[str] = []
    seen = set()

    if isinstance(refs, list):
        for r in refs:
            if r and isinstance(r, (str, int)):
                clean_r = str(r).strip()
                if clean_r and clean_r not in seen:
                    seen.add(clean_r)
                    if len(clean_r) > MAX_REFERENCE_ITEM_LEN:
                        clean_r = clean_r[:MAX_REFERENCE_ITEM_LEN]
                    cleaned.append(clean_r)
                    if len(cleaned) >= MAX_REFERENCES_COUNT:
                        break

    if not cleaned and cwe_hint:
        cleaned.append(f"OWASP / {cwe_hint}")

    return cleaned[:MAX_REFERENCES_COUNT]


def validate_and_sanitize_explanation(
    raw_dict: Any,
    authoritative_finding: Dict[str, Any],
    provenance: str = "llm"
) -> Dict[str, Any]:
    """
    Validates, sanitizes, and bounds a structured explanation dictionary.

    Enforces that:
    1. All 8 required explanation contract fields are present and typed.
    2. Model-generated text cannot overwrite authoritative finding metadata.
    3. Output lengths and reference counts are strictly bounded.
    4. Secrets, scripts, and sensitive tokens are scrubbed.
    """
    if not isinstance(raw_dict, dict):
        raw_dict = {}

    title = authoritative_finding.get("title", "Security Finding")
    category = authoritative_finding.get("category", "General Security")
    cwe = authoritative_finding.get("cwe") or authoritative_finding.get("cwe_id")

    fallback_summary = f"{title} identified during static security analysis."
    fallback_why = f"This pattern represents a potential {category} weakness that could be leveraged if input is untrusted."
    fallback_remediation = "Review the affected operation to ensure strict input validation and safe API usage."
    fallback_limitations = "Static AST analysis; exploitability depends on runtime context and execution paths."

    summary = _clean_str(raw_dict.get("summary"), MAX_SUMMARY_LEN, fallback_summary)
    why_it_matters = _clean_str(raw_dict.get("why_it_matters") or raw_dict.get("explanation"), MAX_WHY_IT_MATTERS_LEN, fallback_why)
    evidence_explanation = _clean_str(raw_dict.get("evidence_explanation"), MAX_EVIDENCE_EXPLANATION_LEN, "Identified by deterministic AST signals on modified code lines.")
    attack_scenario = _clean_str(raw_dict.get("attack_scenario"), MAX_ATTACK_SCENARIO_LEN, f"An attacker supplying maliciously crafted input may trigger unauthorized {category.lower()} behavior.")
    remediation = _clean_str(raw_dict.get("remediation") or raw_dict.get("recommendation"), MAX_REMEDIATION_LEN, fallback_remediation)
    safer_pattern = _clean_str(raw_dict.get("safer_pattern"), MAX_SAFER_PATTERN_LEN, "Use parameterized or sanitized interfaces rather than dynamic construction.")
    limitations = _clean_str(raw_dict.get("limitations"), MAX_LIMITATIONS_LEN, fallback_limitations)
    references = _clean_references(raw_dict.get("references"), cwe_hint=str(cwe) if cwe else None)

    return {
        "summary": summary,
        "why_it_matters": why_it_matters,
        "evidence_explanation": evidence_explanation,
        "attack_scenario": attack_scenario,
        "remediation": remediation,
        "safer_pattern": safer_pattern,
        "references": references,
        "limitations": limitations,
        "provenance": provenance
    }


def generate_deterministic_fallback_explanation(
    finding: Dict[str, Any],
    knowledge_doc: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generates a deterministic, grounded structured explanation from authoritative
    finding metadata and curated OWASP/CWE knowledge without external network calls.
    """
    title = str(finding.get("title") or "Security Finding").strip()
    category = str(finding.get("category") or "General Security").strip()
    cwe = finding.get("cwe") or finding.get("cwe_id")
    rule = finding.get("rule") or finding.get("rule_id")

    # Extract primary evidence signal
    evidence = finding.get("evidence", [])
    ev = evidence[0] if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) else {}
    doc_id = str(ev.get("document_id") or finding.get("file_path") or finding.get("file") or "source file")
    line = ev.get("line_start") or finding.get("line") or 1
    signal_type = str(ev.get("signal_type") or rule or "security_signal")
    signal_name = str(ev.get("signal_name") or "operation")

    # If knowledge_doc was not supplied, attempt to resolve from curated knowledge
    k_content = ""
    k_remediation = ""
    k_safer = ""
    k_cwe = str(cwe) if cwe else ""

    if knowledge_doc and isinstance(knowledge_doc, dict):
        k_content = str(knowledge_doc.get("content") or "")
        k_meta = knowledge_doc.get("metadata", {})
        if not k_cwe and k_meta.get("cwe_id"):
            k_cwe = str(k_meta.get("cwe_id"))
    else:
        # Resolve from CURATED_OWASP_KNOWLEDGE
        try:
            from knowledge.curated_owasp import CURATED_OWASP_KNOWLEDGE
            for c_doc in CURATED_OWASP_KNOWLEDGE:
                meta = c_doc.get("metadata", {})
                cwe_match = k_cwe and meta.get("cwe_id") == k_cwe
                sig_lower = signal_type.lower()
                topic = str(meta.get("security_topic") or "").lower()
                topic_match = topic in sig_lower or sig_lower in topic
                if cwe_match or topic_match:
                    k_content = str(c_doc.get("content") or "")
                    if not k_cwe and meta.get("cwe_id"):
                        k_cwe = str(meta.get("cwe_id"))
                    break
        except Exception:
            pass

    # Extract secure fix & patterns from curated text if available
    if k_content:
        if "Secure Fix / Remediation:" in k_content:
            parts = k_content.split("Secure Fix / Remediation:")
            k_remediation = parts[1].split("CWE Reference:")[0].strip()
            # If code examples exist in remediation, separate into safer_pattern
            if "1." in k_remediation:
                k_safer = k_remediation

    # 1. Summary
    summary = f"{title} detected in '{doc_id}' at line {line}."

    # 2. Why it matters
    title_lower = title.lower()
    if "sql injection" in title_lower or "cwe-89" in str(k_cwe).lower():
        why_it_matters = (
            "SQL injection occurs when untrusted input is concatenated into query strings, "
            "allowing an attacker to manipulate query logic, bypass authentication, or extract sensitive database contents."
        )
        attack_scenario = (
            "An attacker provides SQL metacharacters (e.g. \"' OR '1'='1\") to alter database queries, "
            "potentially dumping tables or gaining administrative access."
        )
        remediation = (
            "1. Use parameterized queries with bound placeholders (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))).\n"
            "2. Utilize an established ORM abstraction with parameterized filtering."
        )
        safer_pattern = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        if not k_cwe:
            k_cwe = "CWE-89"

    elif "command injection" in title_lower or "cwe-78" in str(k_cwe).lower():
        why_it_matters = (
            "Command injection occurs when untrusted input is passed to an operating system shell without sanitization, "
            "enabling arbitrary process execution with the privileges of the running application."
        )
        attack_scenario = (
            "An attacker supplies command separators (e.g. \"; rm -rf /\" or \"| whoami\") to execute unauthorized "
            "operating system commands and compromise the host environment."
        )
        remediation = (
            "1. Avoid invoking system shells (shell=True in Python, exec in Node.js).\n"
            "2. Pass command arguments as a validated list or array vector directly to subprocess.run or execFile."
        )
        safer_pattern = "subprocess.run(['ls', '-la', target_dir], shell=False, check=True)"
        if not k_cwe:
            k_cwe = "CWE-78"

    elif "path traversal" in title_lower or "cwe-22" in str(k_cwe).lower():
        why_it_matters = (
            "Path traversal (directory traversal) allows an attacker to access arbitrary files on the server "
            "by supplying dot-dot-slash sequence inputs to file system APIs."
        )
        attack_scenario = (
            "An attacker passes \"../../../../etc/passwd\" as a filename parameter to read confidential configuration files "
            "or source code outside the intended directory."
        )
        remediation = (
            "1. Validate file paths against an allowlist or resolve canonical paths using os.path.realpath.\n"
            "2. Ensure the resolved path begins with the trusted base directory."
        )
        safer_pattern = (
            "canonical = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
            "if not canonical.startswith(BASE_DIR):\n"
            "    raise ValueError('Access denied')"
        )
        if not k_cwe:
            k_cwe = "CWE-22"

    elif "deserialization" in title_lower or "pickle" in title_lower or "cwe-502" in str(k_cwe).lower():
        why_it_matters = (
            "Insecure deserialization of untrusted data (such as Python pickle or YAML loaders) can lead to arbitrary code execution "
            "during object instantiation."
        )
        attack_scenario = (
            "An attacker constructs a serialized payload containing malicious __reduce__ methods to execute shell commands "
            "immediately upon unpickling."
        )
        remediation = (
            "1. Never deserialize untrusted input with pickle, cPickle, or marshal.\n"
            "2. Use safe data interchange formats such as JSON or Protocol Buffers."
        )
        safer_pattern = "data = json.loads(payload)"
        if not k_cwe:
            k_cwe = "CWE-502"

    elif "secret" in title_lower or "credential" in title_lower or "cwe-798" in str(k_cwe).lower():
        why_it_matters = (
            "Hardcoded credentials in source files risk credential leakage, unauthorized API access, "
            "and lateral movement across infrastructure when repositories are exposed."
        )
        attack_scenario = (
            "An attacker obtaining read access to the repository extracts the credential literal and authenticates "
            "to production databases or cloud services."
        )
        remediation = (
            "1. Remove credential literals from source code immediately.\n"
            "2. Read secrets at runtime from environment variables or enterprise secret vaults (Vault, AWS Secrets Manager)."
        )
        safer_pattern = "api_key = os.environ.get('API_KEY')"
        if not k_cwe:
            k_cwe = "CWE-798"

    elif "xss" in title_lower or "cross-site scripting" in title_lower or "cwe-79" in str(k_cwe).lower():
        why_it_matters = (
            "Cross-Site Scripting (XSS) occurs when untrusted input is rendered into HTML or DOM nodes without context-aware escaping, "
            "enabling execution of arbitrary client-side scripts."
        )
        attack_scenario = (
            "An attacker injects malicious JavaScript (<script> or onload attributes) into user input, "
            "stealing session tokens or performing unauthorized actions on behalf of authenticated users."
        )
        remediation = (
            "1. Use context-aware output encoding or HTML escaping (e.g. html.escape or textContent).\n"
            "2. In React/DOM, avoid innerHTML or dangerouslySetInnerHTML with untrusted strings."
        )
        safer_pattern = "element.textContent = userInput;"
        if not k_cwe:
            k_cwe = "CWE-79"

    else:
        why_it_matters = f"Static analysis identified a {category} signal ('{signal_type}') that may expose the application to security risks if input is not validated."
        attack_scenario = f"An attacker may exploit this {category.lower()} pattern by supplying unexpected or crafted input to manipulate application control flow."
        remediation = k_remediation or "Validate and sanitize all inputs, adhere to the principle of least privilege, and use safe API equivalents."
        safer_pattern = k_safer or "Ensure input boundaries are checked and operations are isolated."

    # 3. Evidence explanation
    evidence_explanation = (
        f"Detected {signal_type} operation ('{signal_name}') on line {line} of file '{doc_id}'. "
        "Deterministic AST pattern analysis matched security signal rules."
    )

    # 4. References
    refs = []
    if k_cwe:
        refs.append(f"OWASP / {k_cwe}")
    refs.append(f"CWE-{k_cwe.replace('CWE-', '')}" if k_cwe else "OWASP Top 10")

    # 5. Limitations
    limitations = "Deterministic offline explanation derived from static AST evidence and curated OWASP guidance."

    return {
        "summary": _clean_str(summary, MAX_SUMMARY_LEN),
        "why_it_matters": _clean_str(why_it_matters, MAX_WHY_IT_MATTERS_LEN),
        "evidence_explanation": _clean_str(evidence_explanation, MAX_EVIDENCE_EXPLANATION_LEN),
        "attack_scenario": _clean_str(attack_scenario, MAX_ATTACK_SCENARIO_LEN),
        "remediation": _clean_str(remediation, MAX_REMEDIATION_LEN),
        "safer_pattern": _clean_str(safer_pattern, MAX_SAFER_PATTERN_LEN),
        "references": _clean_references(refs),
        "limitations": _clean_str(limitations, MAX_LIMITATIONS_LEN),
        "provenance": "deterministic_fallback"
    }
