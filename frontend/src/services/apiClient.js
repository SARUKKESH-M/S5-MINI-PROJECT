/**
 * CodeSentinel Central Frontend API Client
 * 
 * Provides unified, secret-safe HTTP communication with the CodeSentinel backend
 * using native browser fetch() and relative URLs (handled via Vite proxy in development).
 * Strictly communicates only with confirmed endpoints in the current backend.
 */

const API_BASE_URL = (import.meta.env.VITE_BACKEND_URL || '').replace(/\/+$/, '');

/**
 * Core fetch wrapper with JSON serialization and robust error normalization.
 * 
 * @param {string} endpoint - API path (e.g., '/platform/health')
 * @param {RequestInit} [options] - Standard fetch options
 * @returns {Promise<any>} Parsed JSON response
 */
export async function apiFetch(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const defaultHeaders = {
    'Accept': 'application/json',
  };

  if (options.body && typeof options.body === 'string') {
    defaultHeaders['Content-Type'] = 'application/json';
  }

  const config = {
    credentials: options.credentials || 'include',
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);

    // Parse JSON if possible, else text
    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    if (!response.ok) {
      const errorMsg = (typeof data === 'object' && data?.detail)
        ? (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail))
        : (typeof data === 'string' && data.length > 0 ? data : `HTTP Error ${response.status}: ${response.statusText}`);

      const err = new Error(errorMsg);
      err.status = response.status;
      err.data = data;

      // Notify application of session invalidation or deactivation
      if (typeof window !== 'undefined') {
        if (response.status === 401 && !endpoint.includes('/auth/me') && !endpoint.includes('/auth/google')) {
          window.dispatchEvent(new CustomEvent('codesentinel:session-expired', {
            detail: { endpoint, status: 401, message: errorMsg }
          }));
        } else if (response.status === 403 && !endpoint.includes('/auth/google') && !endpoint.startsWith('/admin')) {
          window.dispatchEvent(new CustomEvent('codesentinel:access-denied', {
            detail: { endpoint, status: 403, message: errorMsg }
          }));
        }
      }

      throw err;
    }

    return data;
  } catch (error) {
    // If it's already an HTTP error with status, rethrow
    if (error.status) {
      throw error;
    }
    // Network errors (e.g. server offline)
    const networkError = new Error(error.message || 'Network request failed');
    networkError.status = 0;
    throw networkError;
  }
}

/**
 * Perform a GET request.
 * 
 * @param {string} endpoint 
 * @param {Record<string, any>} [params] Query string parameters
 * @returns {Promise<any>}
 */
export async function apiGet(endpoint, params = null) {
  let url = endpoint;
  if (params && typeof params === 'object') {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null) {
        query.append(key, String(val));
      }
    });
    const queryString = query.toString();
    if (queryString) {
      url += (url.includes('?') ? '&' : '?') + queryString;
    }
  }
  return apiFetch(url, { method: 'GET' });
}

/**
 * Perform a POST request with JSON payload.
 * 
 * @param {string} endpoint 
 * @param {any} [body] Object payload to serialize as JSON
 * @returns {Promise<any>}
 */
export async function apiPost(endpoint, body = null) {
  return apiFetch(endpoint, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
}

/**
 * Perform a PATCH request with JSON payload.
 * 
 * @param {string} endpoint 
 * @param {any} [body] Object payload to serialize as JSON
 * @returns {Promise<any>}
 */
export async function apiPatch(endpoint, body = null) {
  return apiFetch(endpoint, {
    method: 'PATCH',
    body: body ? JSON.stringify(body) : undefined,
  });
}

/**
 * Perform a DELETE request.
 * 
 * @param {string} endpoint 
 * @returns {Promise<any>}
 */
export async function apiDelete(endpoint) {
  return apiFetch(endpoint, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Confirmed Platform & Health Endpoints
// ---------------------------------------------------------------------------

/** Basic health check (GET /health) */
export async function getHealth() {
  return apiGet('/health');
}

/** Comprehensive platform health check and component diagnostics (GET /platform/health) */
export async function getPlatformHealth() {
  return apiGet('/platform/health');
}

/** Platform operational readiness check (GET /platform/readiness) */
export async function getPlatformReadiness() {
  return apiGet('/platform/readiness');
}

/** Platform 6-series release readiness verification (GET /platform/readiness/release) */
export async function getPlatformReleaseReadiness() {
  return apiGet('/platform/readiness/release');
}

/** Platform capabilities and version info (GET /platform/info) */
export async function getPlatformInfo() {
  return apiGet('/platform/info');
}

/** Platform security policy profiles (GET /platform/policies) */
export async function getPlatformPolicies() {
  return apiGet('/platform/policies');
}

/** Platform structured telemetry and observability metrics (GET /platform/metrics) */
export async function getPlatformMetrics() {
  return apiGet('/platform/metrics');
}

// ---------------------------------------------------------------------------
// Confirmed Analysis History Endpoints
// ---------------------------------------------------------------------------

/**
 * Retrieve paginated list of historical security analyses (GET /analyses)
 * 
 * @param {Object} [options]
 * @param {number} [options.limit=20]
 * @param {number} [options.offset=0]
 */
export async function getAnalyses({ limit = 20, offset = 0 } = {}) {
  return apiGet('/analyses', { limit, offset });
}

/**
 * Retrieve a single historical analysis report by ID (GET /analyses/{analysis_id})
 * 
 * @param {string} analysisId 
 */
export async function getAnalysis(analysisId) {
  if (!analysisId) throw new Error('analysisId is required');
  return apiGet(`/analyses/${encodeURIComponent(analysisId)}`);
}

/**
 * Retrieve findings for a specific analysis (GET /analyses/{analysis_id}/findings)
 * 
 * @param {string} analysisId 
 */
export async function getAnalysisFindings(analysisId) {
  if (!analysisId) throw new Error('analysisId is required');
  return apiGet(`/analyses/${encodeURIComponent(analysisId)}/findings`);
}

/**
 * Delete a specific analysis record (DELETE /analyses/{analysis_id})
 * 
 * @param {string} analysisId 
 */
export async function deleteAnalysis(analysisId) {
  if (!analysisId) throw new Error('analysisId is required');
  return apiDelete(`/analyses/${encodeURIComponent(analysisId)}`);
}

// ---------------------------------------------------------------------------
// Confirmed Repository Intake & Analysis Endpoints
// ---------------------------------------------------------------------------

/**
 * Validate repository reference for intake (POST /repository/intake)
 * 
 * @param {Object} payload
 * @param {string} payload.repository_url
 * @param {string} [payload.branch='main']
 * @param {string} [payload.path='']
 * @param {string} [payload.local_path]
 */
export async function intakeRepository(payload) {
  return apiPost('/repository/intake', payload);
}

/**
 * Acquire repository into isolated workspace (POST /repository/acquire)
 * 
 * @param {Object} payload
 * @param {string} payload.repository_url
 * @param {string} [payload.branch='main']
 * @param {string} [payload.path='']
 * @param {string} [payload.local_path]
 */
export async function acquireRepository(payload) {
  return apiPost('/repository/acquire', payload);
}

/**
 * Execute multi-file security analysis on an acquired workspace (POST /repository/analyze)
 * 
 * @param {Object} payload
 * @param {string} payload.acquisition_id
 * @param {string} [payload.query='security analysis']
 */
export async function analyzeRepository(payload) {
  return apiPost('/repository/analyze', payload);
}

// ---------------------------------------------------------------------------
// Confirmed Source Code Snippet Analysis Endpoint
// ---------------------------------------------------------------------------

/**
 * Execute static security analysis on raw source code (POST /analyze)
 * 
 * @param {Object} payload
 * @param {string} payload.source_code
 * @param {string} [payload.query='security analysis']
 */
export async function analyzeSourceCode(payload) {
  return apiPost('/analyze', payload);
}

// ---------------------------------------------------------------------------
// False-Positive Feedback Loop Endpoints
// ---------------------------------------------------------------------------

/**
 * Mark a finding as false positive (POST /analyses/{analysis_id}/findings/{finding_id}/false-positive)
 * 
 * @param {string} analysisId 
 * @param {string} findingId 
 * @param {string} [reason=''] 
 * @param {string} [repositoryId=null] 
 * @param {string} [reasonCode='FALSE_POSITIVE'] 
 * @param {string} [expiresAt=null] 
 * @returns {Promise<any>}
 */
export async function markFalsePositive(analysisId, findingId, reason = '', repositoryId = null, reasonCode = 'FALSE_POSITIVE', expiresAt = null) {
  if (!analysisId || !findingId) {
    throw new Error('analysisId and findingId are required to mark false positive');
  }
  const payload = {
    reason,
    reason_code: reasonCode || 'FALSE_POSITIVE',
  };
  if (repositoryId) {
    payload.repository_id = repositoryId;
  }
  if (expiresAt) {
    payload.expires_at = expiresAt;
  }
  return apiPost(`/analyses/${encodeURIComponent(analysisId)}/findings/${encodeURIComponent(findingId)}/false-positive`, payload);
}

/**
 * Revoke false-positive status for a finding (DELETE /analyses/{analysis_id}/findings/{finding_id}/false-positive)
 * 
 * @param {string} analysisId 
 * @param {string} findingId 
 * @returns {Promise<any>}
 */
export async function revokeFalsePositive(analysisId, findingId) {
  if (!analysisId || !findingId) {
    throw new Error('analysisId and findingId are required to revoke false positive');
  }
  return apiDelete(`/analyses/${encodeURIComponent(analysisId)}/findings/${encodeURIComponent(findingId)}/false-positive`);
}

/**
 * Retrieve false-positive feedback for a finding (GET /analyses/{analysis_id}/findings/{finding_id}/feedback)
 * 
 * @param {string} analysisId 
 * @param {string} findingId 
 * @returns {Promise<any>}
 */
export async function getFindingFeedback(analysisId, findingId) {
  if (!analysisId || !findingId) {
    throw new Error('analysisId and findingId are required to get finding feedback');
  }
  return apiGet(`/analyses/${encodeURIComponent(analysisId)}/findings/${encodeURIComponent(findingId)}/feedback`);
}

// ---------------------------------------------------------------------------
// Developer Security Analytics Endpoints
// ---------------------------------------------------------------------------

/**
 * Retrieve developer security analytics aggregated from persistent analysis records (GET /platform/developers)
 * 
 * @param {Object} [params]
 * @param {number} [params.limit=20]
 * @param {string} [params.repository]
 * @param {string} [params.time_window]
 * @returns {Promise<any>}
 */
export async function getDeveloperAnalytics(params = {}) {
  return apiGet('/platform/developers', params);
}

// ---------------------------------------------------------------------------
// Security Analytics V2 Endpoints (Phase 32)
// ---------------------------------------------------------------------------

/**
 * Retrieve consolidated security analytics summary (GET /analytics/summary)
 * 
 * @param {Object} [options]
 * @param {string} [options.timeWindow='30d'] '7d' | '30d' | '90d' | 'all'
 * @param {string} [options.repositoryId] Optional repository filter
 * @returns {Promise<any>}
 */
export async function getAnalyticsSummary({ timeWindow = '30d', repositoryId = null } = {}) {
  const params = {};
  if (timeWindow) params.time_window = timeWindow;
  if (repositoryId) params.repository_id = repositoryId;
  return apiGet('/analytics/summary', params);
}

/**
 * Retrieve vulnerability/CWE category aggregations with severity breakdown (GET /analytics/vulnerabilities)
 * 
 * @param {Object} [options]
 * @param {string} [options.timeWindow='30d'] '7d' | '30d' | '90d' | 'all'
 * @param {string} [options.repositoryId] Optional repository filter
 * @param {number} [options.limit=20] Bounded results count (1-100)
 * @returns {Promise<any>}
 */
export async function getVulnerabilityAnalytics({ timeWindow = '30d', repositoryId = null, limit = 20 } = {}) {
  const params = {};
  if (timeWindow) params.time_window = timeWindow;
  if (repositoryId) params.repository_id = repositoryId;
  if (limit) params.limit = limit;
  return apiGet('/analytics/vulnerabilities', params);
}

/**
 * Retrieve multi-repository security risk metrics (GET /analytics/repositories)
 * 
 * @param {Object} [options]
 * @param {string} [options.timeWindow='30d'] '7d' | '30d' | '90d' | 'all'
 * @param {number} [options.limit=20] Bounded results count (1-100)
 * @returns {Promise<any>}
 */
export async function getRepositoryAnalytics({ timeWindow = '30d', limit = 20 } = {}) {
  const params = {};
  if (timeWindow) params.time_window = timeWindow;
  if (limit) params.limit = limit;
  return apiGet('/analytics/repositories', params);
}

/**
 * Retrieve false-positive suppression intelligence telemetry (GET /analytics/suppressions)
 * 
 * @param {Object} [options]
 * @param {string} [options.timeWindow='30d'] '7d' | '30d' | '90d' | 'all'
 * @param {string} [options.repositoryId] Optional repository filter
 * @returns {Promise<any>}
 */
export async function getSuppressionAnalytics({ timeWindow = '30d', repositoryId = null } = {}) {
  const params = {};
  if (timeWindow) params.time_window = timeWindow;
  if (repositoryId) params.repository_id = repositoryId;
  return apiGet('/analytics/suppressions', params);
}

// ---------------------------------------------------------------------------
// Confirmed Google Authentication & Session Endpoints (Phase A4 / A5)
// ---------------------------------------------------------------------------

/**
 * Exchange Google ID Token for an authenticated CodeSentinel session (POST /auth/google)
 * 
 * @param {string} idToken - Raw JWT token from Google Identity Services
 * @returns {Promise<{ status: string, user: Object }>}
 */
export async function loginWithGoogle(idToken) {
  if (!idToken) {
    throw new Error('Google ID token is required');
  }
  return apiPost('/auth/google', { id_token: idToken });
}

/**
 * Fetch currently authenticated user session information (GET /auth/me)
 * 
 * @returns {Promise<Object>} UserRecord representation
 */
export async function fetchCurrentUser() {
  return apiGet('/auth/me');
}

/**
 * Terminate authenticated user session (POST /auth/logout)
 * 
 * @returns {Promise<{ status: string, message: string }>}
 */
export async function logoutUser() {
  return apiPost('/auth/logout');
}

// ---------------------------------------------------------------------------
// Confirmed Admin Access Management Endpoints (Phase A7)
// ---------------------------------------------------------------------------

/**
 * Retrieve paginated listing of authorized users (GET /admin/users)
 * 
 * @param {Object} [options]
 * @param {number} [options.limit=50]
 * @param {number} [options.offset=0]
 * @param {string} [options.role=null] 'ADMIN' | 'USER'
 * @param {string} [options.status=null] 'ACTIVE' | 'DISABLED'
 * @returns {Promise<{ users: Array<Object>, total_count: number }>}
 */
export async function getAdminUsers({ limit = 50, offset = 0, role = null, status = null } = {}) {
  const params = { limit, offset };
  if (role) params.role = role;
  if (status) params.status = status;
  return apiGet('/admin/users', params);
}

/**
 * Pre-authorize a Google email address (POST /admin/users)
 * 
 * @param {Object} payload
 * @param {string} payload.email
 * @param {string} [payload.role='USER']
 * @param {string} [payload.full_name]
 * @returns {Promise<Object>} Created UserAdminDetailResponse
 */
export async function preAuthorizeUser({ email, role = 'USER', full_name = null }) {
  if (!email || !email.trim()) {
    throw new Error('Email is required for pre-authorization');
  }
  const payload = {
    email: email.trim(),
    role: (role || 'USER').toUpperCase(),
  };
  if (full_name && full_name.trim()) {
    payload.full_name = full_name.trim();
  }
  return apiPost('/admin/users', payload);
}

/**
 * Activate or disable a user account (PATCH /admin/users/{user_id}/status)
 * 
 * @param {string} userId
 * @param {'ACTIVE'|'DISABLED'} status
 * @returns {Promise<Object>} Updated UserAdminDetailResponse
 */
export async function updateUserStatus(userId, status) {
  if (!userId) throw new Error('userId is required');
  if (!status) throw new Error('status is required');
  return apiPatch(`/admin/users/${encodeURIComponent(userId)}/status`, {
    status: status.toUpperCase(),
  });
}

/**
 * Promote or demote a user's role (PATCH /admin/users/{user_id}/role)
 * 
 * @param {string} userId
 * @param {'ADMIN'|'USER'} role
 * @returns {Promise<Object>} Updated UserAdminDetailResponse
 */
export async function updateUserRole(userId, role) {
  if (!userId) throw new Error('userId is required');
  if (!role) throw new Error('role is required');
  return apiPatch(`/admin/users/${encodeURIComponent(userId)}/role`, {
    role: role.toUpperCase(),
  });
}

/**
 * Revoke user authorization and remove user record (DELETE /admin/users/{user_id})
 * 
 * @param {string} userId
 * @returns {Promise<{ status: string, message: string }>}
 */
export async function revokeUserAccess(userId) {
  if (!userId) throw new Error('userId is required');
  return apiDelete(`/admin/users/${encodeURIComponent(userId)}`);
}

