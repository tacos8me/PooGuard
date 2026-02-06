import axios from 'axios';

// CSRF token storage
const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAME = 'X-CSRF-Token';

// Methods that require CSRF token
const CSRF_METHODS = ['post', 'put', 'delete', 'patch'];

/**
 * Get CSRF token from cookie
 */
const getCsrfTokenFromCookie = () => {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === CSRF_COOKIE_NAME) {
      return decodeURIComponent(value);
    }
  }
  return null;
};

/**
 * Fetch a new CSRF token from the server
 */
const fetchCsrfToken = async () => {
  try {
    const response = await axios.get('/api/csrf-token', {
      withCredentials: true
    });
    return response.data.csrfToken;
  } catch (error) {
    if (import.meta.env.DEV) {
      console.error('Failed to fetch CSRF token:', error);
    }
    return null;
  }
};

/**
 * Initialize CSRF token on app startup
 * Call this function when the app initializes
 */
export const initializeCsrf = async () => {
  // Check if we already have a token in cookies
  let token = getCsrfTokenFromCookie();

  // If no token exists, fetch one from the server
  if (!token) {
    token = await fetchCsrfToken();
  }

  return token;
};

const api = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Required for CSRF cookies
  timeout: 30000,
});

// Request interceptor to add CSRF token only
// NOTE: JWT auth token is managed by AuthContext to ensure proper refresh handling
api.interceptors.request.use(
  (config) => {
    // Add CSRF token for state-changing requests
    if (CSRF_METHODS.includes(config.method?.toLowerCase())) {
      const csrfToken = getCsrfTokenFromCookie();
      if (csrfToken) {
        config.headers[CSRF_HEADER_NAME] = csrfToken;
      }
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Track if we're currently refreshing the CSRF token to avoid infinite loops
let isRefreshingCsrf = false;
let csrfRefreshPromise = null;

// Response interceptor to handle auth errors and CSRF failures
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Handle CSRF validation failures (403 with CSRF error codes)
    if (
      error.response?.status === 403 &&
      error.response?.data?.code?.startsWith('CSRF_') &&
      !originalRequest._csrfRetry
    ) {
      // Mark request as retried to prevent infinite loops
      originalRequest._csrfRetry = true;

      // If already refreshing, wait for the existing promise
      if (isRefreshingCsrf) {
        await csrfRefreshPromise;
      } else {
        // Refresh the CSRF token
        isRefreshingCsrf = true;
        csrfRefreshPromise = fetchCsrfToken();
        await csrfRefreshPromise;
        isRefreshingCsrf = false;
        csrfRefreshPromise = null;
      }

      // Update the CSRF header with the new token
      const newCsrfToken = getCsrfTokenFromCookie();
      if (newCsrfToken) {
        originalRequest.headers[CSRF_HEADER_NAME] = newCsrfToken;
      }

      // Retry the original request
      return api(originalRequest);
    }

    // NOTE: 401 auth errors are handled by AuthContext's interceptor
    // which properly manages token refresh. Don't duplicate that logic here.

    return Promise.reject(error);
  }
);

export default api;
