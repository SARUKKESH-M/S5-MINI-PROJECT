"""Sample Security Knowledge Dataset for CodeSentinel.

Provides generic, educational secure coding guidance for testing vector store
ingestion and retrieval without external network dependencies. Contains no real secrets.
"""

from typing import Any, Dict, List
from knowledge.models import create_knowledge_document

SAMPLE_SECURITY_KNOWLEDGE: List[Dict[str, Any]] = [
    create_knowledge_document(
        document_id="knowledge_sql_parameterization_1",
        title="SQL Query Parameterization Guidelines",
        content=(
            "To prevent SQL injection vulnerabilities, application code must use parameterized queries "
            "or object-relational mapping (ORM) abstractions rather than concatenating user input directly "
            "into raw SQL queries. Using parameterized statements ensures that database drivers treat user inputs "
            "strictly as data rather than executable SQL code."
        ),
        source="local_security_knowledge",
        category="secure_coding",
        security_topic="sql_parameterization",
        language="python",
    ),
    create_knowledge_document(
        document_id="knowledge_command_execution_1",
        title="Command Execution Safety Best Practices",
        content=(
            "Executing system commands dynamically with unvalidated external input poses command injection risks. "
            "When system command invocation is required, applications should avoid shell=True in Python subprocess calls "
            "and pass command arguments as explicit argument arrays. Input validation and allowlists should be enforced "
            "prior to executing shell instructions."
        ),
        source="local_security_knowledge",
        category="secure_coding",
        security_topic="command_execution_safety",
        language="python",
    ),
    create_knowledge_document(
        document_id="knowledge_dynamic_code_execution_1",
        title="Dynamic Code Execution Risks",
        content=(
            "Functions such as eval(), exec(), or compile() in Python dynamically evaluate string inputs as Python code. "
            "Invoking these functions on untrusted data or user input allows arbitrary code execution. Developers should "
            "replace dynamic code execution with structured parsing, explicit lookup tables, or safe mathematical expression evaluators."
        ),
        source="local_security_knowledge",
        category="secure_coding",
        security_topic="dynamic_code_execution_risks",
        language="python",
    ),
    create_knowledge_document(
        document_id="knowledge_external_input_handling_1",
        title="External Input Validation & Sanitization",
        content=(
            "All data received from untrusted sources such as HTTP request bodies, headers, URL query parameters, "
            "and external file uploads must be thoroughly validated and sanitized. Schema validation frameworks "
            "(such as Pydantic) should be used to enforce strict data types, string length bounds, and expected values."
        ),
        source="local_security_knowledge",
        category="secure_coding",
        security_topic="external_input_handling",
        language="python",
    ),
    create_knowledge_document(
        document_id="knowledge_secret_management_1",
        title="Hardcoded Secret Prevention & Credential Management",
        content=(
            "Hardcoding sensitive credentials, API keys, private tokens, or passwords directly into source code repositories "
            "exposes credentials to unauthorized access. Sensitive configuration values must be loaded at runtime from "
            "environment variables, secure secret storage vaults, or encrypted configuration files."
        ),
        source="local_security_knowledge",
        category="secure_coding",
        security_topic="hardcoded_secret_management",
        language="python",
    ),
]
