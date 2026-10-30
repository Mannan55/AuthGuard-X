/**
 * AuthGuard-X Centralized API Client
 * Secure fetch wrapper with CSRF token management and error handling.
 * Sprint 1
 */

(function (window) {
  'use strict';

  const API_BASE = window.AUTHGUARD_API_URL || '';
  let cachedCsrfToken = null;

  async function fetchCsrfToken() {
    try {
      const res = await fetch(`${API_BASE}/api/auth/csrf-token`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        cachedCsrfToken = data.csrf_token || null;
        return cachedCsrfToken;
      }
    } catch (err) {
      console.warn('[API] Failed to fetch CSRF token:', err);
    }
    return null;
  }

  async function apiFetch(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = Object.assign(
      {
        'Accept': 'application/json'
      },
      options.headers || {}
    );

    const method = (options.method || 'GET').toUpperCase();
    const isMutating = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);

    // If sending JSON, ensure Content-Type header
    if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    // Attach CSRF token on mutating requests
    if (isMutating) {
      if (!cachedCsrfToken) {
        await fetchCsrfToken();
      }
      if (cachedCsrfToken) {
        headers['X-CSRFToken'] = cachedCsrfToken;
      }
    }

    const config = {
      ...options,
      method,
      headers,
      credentials: 'include'
    };

    let response;
    try {
      response = await fetch(url, config);
    } catch (networkErr) {
      throw new Error(`Network connection error: ${networkErr.message}`);
    }

    // If 400 CSRF token error or similar, retry once with refreshed token
    if (response.status === 400 && isMutating) {
      const text = await response.clone().text();
      if (text.toLowerCase().includes('csrf')) {
        await fetchCsrfToken();
        if (cachedCsrfToken) {
          headers['X-CSRFToken'] = cachedCsrfToken;
          config.headers = headers;
          response = await fetch(url, config);
        }
      }
    }

    // Parse JSON or text
    let data = null;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        data = await response.json();
      } catch (err) {
        data = null;
      }
    }

    if (!response.ok) {
      const errorMsg =
        (data && (data.message || data.error)) ||
        `Request failed with status ${response.status}`;
      const err = new Error(errorMsg);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return data;
  }

  // ── High-Level Service Methods ─────────────────────────────────────
  const API = {
    base: API_BASE,
    fetch: apiFetch,

    auth: {
      async getCsrfToken() {
        return fetchCsrfToken();
      },
      async getSession() {
        return apiFetch('/api/auth/session');
      },
      async login(username, password) {
        // Ensure fresh CSRF token before login
        await fetchCsrfToken();
        const data = await apiFetch('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username, password })
        });
        // Refresh token bound to new authenticated session
        await fetchCsrfToken();
        return data;
      },
      async logout() {
        try {
          const data = await apiFetch('/api/auth/logout', { method: 'POST' });
          cachedCsrfToken = null;
          await fetchCsrfToken();
          return data;
        } catch (err) {
          cachedCsrfToken = null;
          throw err;
        }
      }
    },

    incidents: {
      async list(params = {}) {
        const query = new URLSearchParams();
        Object.entries(params).forEach(([k, v]) => {
          if (v !== undefined && v !== null && v !== '' && v !== 'all') {
            query.append(k, v);
          }
        });
        const qs = query.toString();
        return apiFetch(`/api/incidents${qs ? `?${qs}` : ''}`);
      },
      async getById(id) {
        return apiFetch(`/api/incidents/${id}`);
      },
      async simulate(payload) {
        return apiFetch('/api/incidents/simulate', {
          method: 'POST',
          body: JSON.stringify(payload)
        });
      },
      async resolve(id) {
        return apiFetch(`/api/incidents/${id}/resolve`, {
          method: 'POST'
        });
      },
      async clear() {
        return apiFetch('/api/incidents/clear', {
          method: 'POST'
        });
      }
    },

    metrics: {
      async get() {
        return apiFetch('/api/metrics');
      }
    }
  };

  window.API = API;
})(window);

