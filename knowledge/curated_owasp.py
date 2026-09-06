"""Curated OWASP and CWE Security Knowledge Base for CodeSentinel.

Migrated from CodeSentinel_old curated patterns and adapted to the NEW
structured knowledge document model. Provides canonical definitions, concrete
vulnerable code examples, secure fix patterns, CWE references, and severities
for 12 high-priority software security weakness categories.
"""

from typing import Any, Dict, List
from knowledge.models import create_knowledge_document

CURATED_OWASP_KNOWLEDGE: List[Dict[str, Any]] = [
    create_knowledge_document(
        document_id="knowledge_cwe_89_sql_injection",
        title="SQL Injection Prevention & Parameterization Guidelines",
        content=(
            "Overview:\n"
            "SQL Injection (CWE-89) occurs when untrusted user input is directly concatenated "
            "or interpolated into SQL queries, enabling attackers to manipulate query logic, "
            "bypass authentication, or access unauthorized database records.\n\n"
            "Vulnerable Patterns:\n"
            "  query = 'SELECT * FROM users WHERE id=' + user_id\n"
            "  cursor.execute('SELECT * FROM ' + table_name)\n"
            "  cursor.execute(f'SELECT * FROM accounts WHERE name = {user_input}')\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Use parameterized queries with bound placeholders:\n"
            "     cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n"
            "     cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
            "  2. Use an ORM abstraction with parameterized filtering:\n"
            "     User.query.filter_by(id=user_id).first()\n\n"
            "CWE Reference: CWE-89\n"
            "Baseline Severity: CRITICAL"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="sql_injection",
        language="python",
        cwe_id="CWE-89",
        severity="critical",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_79_xss",
        title="Cross-Site Scripting (XSS) Prevention Guidelines",
        content=(
            "Overview:\n"
            "Cross-Site Scripting (CWE-79) occurs when untrusted user input is rendered into HTML, "
            "JavaScript, or DOM templates without context-aware escaping or sanitization, allowing "
            "attackers to execute arbitrary scripts in victim browsers.\n\n"
            "Vulnerable Patterns:\n"
            "  return '<div>' + user_input + '</div>'\n"
            "  innerHTML = userComment\n"
            "  response.write(f'<h1>Welcome {username}</h1>')\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Use html.escape() for raw HTML injection prevention:\n"
            "     import html\n"
            "     safe_text = html.escape(user_input)\n"
            "  2. Use modern templating engines with auto-escaping enabled by default (e.g. Jinja2):\n"
            "     render_template('profile.html', user_input=user_input)\n\n"
            "CWE Reference: CWE-79\n"
            "Baseline Severity: HIGH"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="xss",
        language="python",
        cwe_id="CWE-79",
        severity="high",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_798_hardcoded_credentials",
        title="Hardcoded Credential & Secret Protection Guidelines",
        content=(
            "Overview:\n"
            "Use of Hardcoded Credentials (CWE-798) occurs when passwords, private API keys, cryptographic "
            "secrets, or database connection tokens are embedded directly within source code or configuration "
            "files committed to version control repositories.\n\n"
            "Vulnerable Patterns:\n"
            "  password = 'admin123'\n"
            "  API_KEY = 'sk-hardcoded-key-12345'\n"
            "  SECRET_KEY = 'my-super-secret-key'\n"
            "  DB_PASSWORD = 'pass123'\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Load credentials dynamically at runtime from environment variables:\n"
            "     import os\n"
            "     api_key = os.getenv('API_KEY')\n"
            "  2. Use local uncommitted environment configuration (.env with python-dotenv):\n"
            "     from dotenv import load_dotenv\n"
            "     load_dotenv()\n"
            "  3. Use enterprise secret management vaults (e.g. HashiCorp Vault, AWS Secrets Manager).\n\n"
            "CWE Reference: CWE-798\n"
            "Baseline Severity: CRITICAL"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="credential_handling",
        language="python",
        cwe_id="CWE-798",
        severity="critical",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_78_command_injection",
        title="OS Command Injection Defense Guidelines",
        content=(
            "Overview:\n"
            "OS Command Injection (CWE-78) occurs when an application executes system commands using "
            "externally supplied input without strict validation, escaping, or argument separation, allowing "
            "attackers to execute arbitrary shell commands on the host operating system.\n\n"
            "Vulnerable Patterns:\n"
            "  os.system('ping ' + user_input)\n"
            "  subprocess.call('ls ' + directory, shell=True)\n"
            "  os.popen(f'cat {user_file}')\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Use subprocess with an explicit argument list and shell=False:\n"
            "     import subprocess\n"
            "     subprocess.run(['ping', '-c', '1', user_input], shell=False, check=True)\n"
            "  2. Validate and sanitize all user parameters against strict allowlists before execution.\n\n"
            "CWE Reference: CWE-78\n"
            "Baseline Severity: CRITICAL"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="command_execution",
        language="python",
        cwe_id="CWE-78",
        severity="critical",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_327_weak_cryptography",
        title="Weak Cryptographic Hashing Prevention Guidelines",
        content=(
            "Overview:\n"
            "Use of a Broken or Risky Cryptographic Algorithm (CWE-327) occurs when obsolete hashing "
            "functions (such as MD5 or SHA-1) are employed for password storage, integrity checks, or "
            "authentication tokens, leaving them vulnerable to collision attacks and rainbow table precomputation.\n\n"
            "Vulnerable Patterns:\n"
            "  hashlib.md5(password.encode()).hexdigest()\n"
            "  hashlib.sha1(password.encode()).hexdigest()\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Use modern, adaptive salted password hashing algorithms (bcrypt, argon2, or scrypt):\n"
            "     import bcrypt\n"
            "     hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())\n"
            "  2. For cryptographic digests, use SHA-256 or SHA-3:\n"
            "     import hashlib\n"
            "     digest = hashlib.sha256(data).hexdigest()\n\n"
            "CWE Reference: CWE-327\n"
            "Baseline Severity: CRITICAL"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="weak_cryptography",
        language="python",
        cwe_id="CWE-327",
        severity="critical",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_502_insecure_deserialization",
        title="Insecure Object Deserialization Defense Guidelines",
        content=(
            "Overview:\n"
            "Deserialization of Untrusted Data (CWE-502) occurs when an application deserializes "
            "untrusted binary streams or complex serialization formats, enabling remote code execution via "
            "instantiation of malicious object payloads (e.g. Python pickle __reduce__ gadgets).\n\n"
            "Vulnerable Patterns:\n"
            "  pickle.loads(user_data)\n"
            "  yaml.load(yaml_stream)  # without SafeLoader\n"
            "  _pickle.loads(serialized_bytes)\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Use safe, standard data-interchange formats like JSON:\n"
            "     import json\n"
            "     obj = json.loads(user_data)\n"
            "  2. When using PyYAML, always specify yaml.safe_load:\n"
            "     import yaml\n"
            "     obj = yaml.safe_load(yaml_stream)\n"
            "  3. Never deserialize pickle payloads received across network boundaries.\n\n"
            "CWE Reference: CWE-502\n"
            "Baseline Severity: CRITICAL"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="deserialization",
        language="python",
        cwe_id="CWE-502",
        severity="critical",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_22_path_traversal",
        title="Path Traversal & Directory Traversal Defense Guidelines",
        content=(
            "Overview:\n"
            "Improper Limitation of a Pathname to a Restricted Directory (CWE-22) occurs when user input "
            "is concatenated into filesystem paths without boundary checking, allowing attackers to access "
            "restricted files using relative path sequences (e.g. '../../etc/passwd').\n\n"
            "Vulnerable Patterns:\n"
            "  open('/uploads/' + filename)\n"
            "  os.path.join(base_dir, user_input)\n"
            "  with open(f'data/{user_path}', 'r') as f:\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Strip directory traversal tokens using os.path.basename:\n"
            "     safe_filename = os.path.basename(filename)\n"
            "  2. Resolve and verify that the canonical path resides within the target directory:\n"
            "     from pathlib import Path\n"
            "     target = (Path(base_dir) / filename).resolve()\n"
            "     if not target.is_relative_to(Path(base_dir).resolve()):\n"
            "         raise ValueError('Access Denied: Path traversal detected')\n"
            "  3. Enforce an allowlist of permitted filenames.\n\n"
            "CWE Reference: CWE-22\n"
            "Baseline Severity: HIGH"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="path_traversal",
        language="python",
        cwe_id="CWE-22",
        severity="high",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_306_missing_authentication",
        title="Missing Authentication for Critical Functions Guidelines",
        content=(
            "Overview:\n"
            "Missing Authentication for Critical Function (CWE-306) occurs when sensitive endpoints, "
            "administrative APIs, or state-altering workflows are accessible without verifying the user's "
            "identity or credentials.\n\n"
            "Vulnerable Patterns:\n"
            "  @app.post('/api/admin/delete-user')\n"
            "  def delete_user(user_id: int):  # Missing auth dependency or decorator\n"
            "  def update_settings():  # No token validation or session check\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Enforce authentication dependencies on all protected routes:\n"
            "     @app.post('/api/admin/delete-user', dependencies=[Depends(verify_admin_token)])\n"
            "  2. Apply framework security decorators (e.g. @login_required):\n"
            "     @login_required\n"
            "  3. Validate JWT bearer tokens on incoming Authorization headers.\n\n"
            "CWE Reference: CWE-306\n"
            "Baseline Severity: HIGH"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="authentication",
        language="python",
        cwe_id="CWE-306",
        severity="high",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_352_csrf",
        title="Cross-Site Request Forgery (CSRF) Mitigation Guidelines",
        content=(
            "Overview:\n"
            "Cross-Site Request Forgery (CWE-352) allows a malicious website to trick an authenticated user's "
            "browser into transmitting unauthorized, state-changing requests to a trusted application without "
            "the user's knowledge or explicit consent.\n\n"
            "Vulnerable Patterns:\n"
            "  State-changing POST, PUT, or DELETE endpoints without CSRF token verification\n"
            "  Authentication relying solely on ambient browser cookies without SameSite protections\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Implement anti-CSRF token verification on all state-changing endpoints:\n"
            "     validate_csrf_token(request.headers.get('X-CSRF-Token'))\n"
            "  2. Configure SameSite cookie attributes (SameSite=Strict or SameSite=Lax):\n"
            "     response.set_cookie('session_id', val, httponly=True, samesite='lax', secure=True)\n"
            "  3. Verify Origin and Referer request headers.\n\n"
            "CWE Reference: CWE-352\n"
            "Baseline Severity: MEDIUM"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="csrf",
        language="python",
        cwe_id="CWE-352",
        severity="medium",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_434_unrestricted_file_upload",
        title="Unrestricted File Upload Validation Guidelines",
        content=(
            "Overview:\n"
            "Unrestricted Upload of File with Dangerous Type (CWE-434) occurs when an application accepts "
            "uploaded files without verifying their file type, extension, size, or content, allowing attackers "
            "to upload executable scripts or webshells.\n\n"
            "Vulnerable Patterns:\n"
            "  file.save(os.path.join(upload_dir, file.filename))\n"
            "  with open(f'/var/www/uploads/{upload.filename}', 'wb') as dest:\n"
            "      dest.write(upload.file.read())\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Validate file extension against an explicit allowlist (e.g. ['.png', '.jpg', '.pdf']):\n"
            "     ext = os.path.splitext(file.filename)[1].lower()\n"
            "     if ext not in ALLOWED_EXTENSIONS:\n"
            "         raise ValueError('Invalid file extension')\n"
            "  2. Validate MIME content types and enforce strict file size limits.\n"
            "  3. Generate randomized storage names (e.g. uuid.uuid4()) instead of trusting user filenames.\n\n"
            "CWE Reference: CWE-434\n"
            "Baseline Severity: HIGH"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="file_upload",
        language="python",
        cwe_id="CWE-434",
        severity="high",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_200_sensitive_data_exposure",
        title="Sensitive Data Exposure & Information Leakage Prevention Guidelines",
        content=(
            "Overview:\n"
            "Exposure of Sensitive Information to an Unauthorized Actor (CWE-200) occurs when an application "
            "inadvertently reveals confidential data (such as passwords, secret tokens, private keys, or stack "
            "traces) through logs, diagnostic outputs, or excessive API response payloads.\n\n"
            "Vulnerable Patterns:\n"
            "  print(f'User password: {password}')\n"
            "  logging.info(f'Authentication token: {api_key}')\n"
            "  return {'user_id': user.id, 'password_hash': user.password}\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Never log secrets, passwords, tokens, or personal identifiable information.\n"
            "  2. Sanitize and redact sensitive data from logging handlers and error responses.\n"
            "  3. Use explicit response models / DTOs (e.g. Pydantic schemas) that exclude private fields:\n"
            "     class UserResponse(BaseModel):\n"
            "         id: int\n"
            "         email: str\n"
            "         # password and token fields omitted\n\n"
            "CWE Reference: CWE-200\n"
            "Baseline Severity: HIGH"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="sensitive_data_exposure",
        language="python",
        cwe_id="CWE-200",
        severity="high",
    ),
    create_knowledge_document(
        document_id="knowledge_cwe_476_none_reference",
        title="Null Pointer / None Reference Handling Guidelines",
        content=(
            "Overview:\n"
            "NULL Pointer Dereference / Unchecked None Reference (CWE-476) occurs when an application accesses "
            "attributes or invokes methods on an object that evaluates to None, causing unhandled AttributeError "
            "exceptions, service crashes, or Denial of Service (DoS).\n\n"
            "Vulnerable Patterns:\n"
            "  user.name  # without verifying if user is None\n"
            "  user_profile.address.city  # chained attribute access\n\n"
            "Secure Fix / Remediation:\n"
            "  1. Perform explicit None checks before accessing object attributes:\n"
            "     if user is not None:\n"
            "         name = user.name\n"
            "  2. Use guard clauses or safe retrieval helpers:\n"
            "     if not user:\n"
            "         return None\n"
            "  3. Use getattr() with safe defaults: getattr(user, 'name', 'Unknown')\n\n"
            "CWE Reference: CWE-476\n"
            "Baseline Severity: MEDIUM"
        ),
        source="owasp_curated",
        category="secure_coding",
        security_topic="null_reference",
        language="python",
        cwe_id="CWE-476",
        severity="medium",
    ),
]
