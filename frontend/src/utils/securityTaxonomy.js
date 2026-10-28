/**
 * Security Taxonomy and Authoritative Remediation Mapping
 * 
 * Grounded strictly in backend AST signals (SIGNAL_CWE_MAPPING in finding_enrichment.py).
 * Pure presentation-layer taxonomy helper. Unmapped signals are treated as unknown (never guessed).
 */

// Grounded mapping directly matching backend/analysis/finding_enrichment.py SIGNAL_CWE_MAPPING
export const SIGNAL_CWE_MAPPING = {
  unsafe_database_execution: 'CWE-89',
  database_execution_call: 'CWE-89',
  command_execution_call: 'CWE-78',
  possible_hardcoded_secret: 'CWE-798',
  credential_propagation_to_authorization_sink: 'CWE-798',
  path_traversal_call: 'CWE-22',
  path_traversal: 'CWE-22',
  insecure_deserialization_call: 'CWE-502',
  insecure_deserialization: 'CWE-502',
  dom_xss_call: 'CWE-79',
  reflected_xss_call: 'CWE-79',
  cross_site_scripting: 'CWE-79',
  weak_cryptography: 'CWE-327',
  weak_crypto_call: 'CWE-327',
  weak_hash_call: 'CWE-327',
  weak_cipher_call: 'CWE-327',
  missing_authentication: 'CWE-306',
  cross_site_request_forgery: 'CWE-352',
  unrestricted_file_upload: 'CWE-434',
  sensitive_data_exposure: 'CWE-200',
  null_pointer_dereference: 'CWE-476',
};

// Canonical details for verified CWEs
export const CWE_DETAILS = {
  'CWE-89': {
    name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
    owasp: 'A03:2021-Injection',
  },
  'CWE-78': {
    name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
    owasp: 'A03:2021-Injection',
  },
  'CWE-798': {
    name: 'Use of Hard-coded Credentials',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-22': {
    name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-502': {
    name: 'Deserialization of Untrusted Data',
    owasp: 'A08:2021-Software and Data Integrity Failures',
  },
  'CWE-79': {
    name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
    owasp: 'A03:2021-Injection',
  },
  'CWE-327': {
    name: 'Use of a Broken or Risky Cryptographic Algorithm',
    owasp: 'A02:2021-Cryptographic Failures',
  },
  'CWE-306': {
    name: 'Missing Authentication for Critical Function',
    owasp: 'A07:2021-Identification and Authentication Failures',
  },
  'CWE-352': {
    name: 'Cross-Site Request Forgery (CSRF)',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-434': {
    name: 'Unrestricted Upload of File with Dangerous Type',
    owasp: 'A04:2021-Insecure Design',
  },
  'CWE-200': {
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
    owasp: 'A01:2021-Broken Access Control',
  },
  'CWE-476': {
    name: 'NULL Pointer Dereference',
    owasp: null,
  },
};

// General remediation guidance for recognized vulnerability categories / CWEs
const GENERAL_REMEDIATION_GUIDANCE = {
  'CWE-89': 'Use parameterized queries, prepared statements, or a vetted ORM rather than concatenating user input directly into SQL strings.',
  'CWE-78': 'Avoid passing unsanitized input to system shells. Use safe APIs that accept argument lists (e.g., subprocess with shell=False) and validate against a strict allowlist.',
  'CWE-798': 'Store credentials and API tokens in environment variables or a dedicated secret management service. Rotate exposed secrets immediately and omit secrets from version control.',
  'CWE-22': 'Canonicalize paths before access and restrict operations to a designated base directory. Validate input against path traversal sequences (such as ../).',
  'CWE-502': 'Avoid deserializing untrusted data with formats that permit code execution (e.g., pickle, PyYAML load without SafeLoader). Use safe serialization formats like JSON with schema validation.',
  'CWE-79': 'Contextually encode and sanitize untrusted input before rendering into HTML or DOM nodes. Enforce a strong Content Security Policy (CSP).',
  'CWE-327': 'Replace deprecated cryptographic algorithms (e.g., MD5, SHA-1, DES) with modern, robust standards such as SHA-256, SHA-3, AES-GCM, or Argon2/bcrypt for password hashing.',
  'CWE-306': 'Enforce access control and authentication checks at server-side API endpoints before processing sensitive actions.',
  'CWE-352': 'Require anti-CSRF tokens for state-changing requests or configure cookies with SameSite=Lax or SameSite=Strict attributes.',
  'CWE-434': 'Validate file extensions, MIME types, and contents against an allowlist. Store uploads outside the web document root and disable script execution.',
  'CWE-200': 'Ensure error messages, stack traces, and debug logs do not leak internal credentials, database structure, or sensitive personal data.',
  'CWE-476': 'Perform explicit null/undefined checks and use safe navigation operators or default initializers before accessing object attributes.',
};

// Internal WeakMap memoization caches to avoid re-resolving unchanged finding objects
const taxonomyCache = new WeakMap();
const remediationCache = new WeakMap();

/**
 * Resolve verified CWE and OWASP taxonomy for a finding.
 * Returns null identifiers if no grounded mapping exists.
 * Memoized via WeakMap for $O(1)$ performance during search filtering.
 */
export function getFindingTaxonomy(finding) {
  if (!finding || typeof finding !== 'object') {
    return { cweId: null, cweName: null, owasp: null };
  }

  if (taxonomyCache.has(finding)) {
    return taxonomyCache.get(finding);
  }

  // 1. Direct CWE field if provided (e.g. from analysis or metadata)
  let cweId = finding.cwe || finding.cwe_id || null;
  if (typeof cweId === 'string') {
    cweId = cweId.trim().toUpperCase();
    if (!cweId.startsWith('CWE-')) {
      const num = parseInt(cweId, 10);
      cweId = !isNaN(num) ? `CWE-${num}` : null;
    }
  } else {
    cweId = null;
  }

  // 2. If no direct CWE, inspect evidence array for grounded signal_type mapping
  if (!cweId && Array.isArray(finding.evidence) && finding.evidence.length > 0) {
    for (const ev of finding.evidence) {
      if (ev && typeof ev === 'object' && ev.signal_type) {
        const sig = String(ev.signal_type).trim().toLowerCase();
        if (SIGNAL_CWE_MAPPING[sig]) {
          cweId = SIGNAL_CWE_MAPPING[sig];
          break;
        }
      }
    }
  }

  // 3. Fallback to finding.ast_signal or finding.rule_id if it directly matches a signal key
  if (!cweId) {
    const rawSig = String(finding.ast_signal || finding.rule_id || '').trim().toLowerCase();
    if (SIGNAL_CWE_MAPPING[rawSig]) {
      cweId = SIGNAL_CWE_MAPPING[rawSig];
    }
  }

  let result;
  // 4. Return grounded details or null (never fabricate)
  if (cweId && CWE_DETAILS[cweId]) {
    result = {
      cweId,
      cweName: CWE_DETAILS[cweId].name,
      owasp: CWE_DETAILS[cweId].owasp,
    };
  } else if (cweId) {
    result = {
      cweId,
      cweName: null,
      owasp: null,
    };
  } else {
    result = { cweId: null, cweName: null, owasp: null };
  }

  taxonomyCache.set(finding, result);
  return result;
}

/**
 * Resolve remediation guidance for a finding.
 * Distinguishes specific report remediation from general taxonomy guidance.
 * Memoized via WeakMap for $O(1)$ performance.
 */
export function getRemediationGuidance(finding) {
  if (!finding || typeof finding !== 'object') {
    return null;
  }

  if (remediationCache.has(finding)) {
    return remediationCache.get(finding);
  }

  let result = null;

  // 1. Specific remediation provided directly in finding object
  const specific = finding.remediation || finding.recommendation || null;
  if (typeof specific === 'string' && specific.trim()) {
    result = {
      text: specific.trim(),
      isSpecific: true,
      disclaimer: null,
    };
  } else {
    // 2. Grounded category/CWE general guidance fallback
    const taxonomy = getFindingTaxonomy(finding);
    if (taxonomy.cweId && GENERAL_REMEDIATION_GUIDANCE[taxonomy.cweId]) {
      result = {
        text: GENERAL_REMEDIATION_GUIDANCE[taxonomy.cweId],
        isSpecific: false,
        disclaimer: 'General security guidance — verify against your specific application context and architecture.',
      };
    }
  }

  remediationCache.set(finding, result);
  return result;
}

