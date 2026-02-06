import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import api from '../lib/api';

const AuthContext = createContext(null);

// Parse JWT to get expiration time
const parseJwt = (token) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (_error) {
    return null;
  }
};

// Get time until token expires (in milliseconds)
const getTokenExpirationTime = (token) => {
  const payload = parseJwt(token);
  if (!payload || !payload.exp) return 0;
  return payload.exp * 1000 - Date.now();
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(() => localStorage.getItem('accessToken'));
  const [refreshToken, setRefreshToken] = useState(() => localStorage.getItem('refreshToken'));
  const [loading, setLoading] = useState(true);
  const refreshTimeoutRef = useRef(null);
  const isRefreshingRef = useRef(false);
  const refreshQueueRef = useRef([]);
  const hasFetchedRef = useRef(false);

  // Clear all auth data
  const clearAuth = useCallback(() => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setAccessToken(null);
    setRefreshToken(null);
    setUser(null);
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
      refreshTimeoutRef.current = null;
    }
  }, []);

  // Refresh the access token
  // Uses a promise queue so concurrent callers wait for the in-flight refresh
  // instead of failing immediately when another refresh is already in progress.
  const refreshAccessToken = useCallback(async () => {
    if (!refreshToken) {
      return false;
    }

    if (isRefreshingRef.current) {
      return new Promise((resolve) => {
        refreshQueueRef.current.push(resolve);
      });
    }

    isRefreshingRef.current = true;

    try {
      const response = await api.post('/api/auth/refresh', { refreshToken });
      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = response.data;

      localStorage.setItem('accessToken', newAccessToken);
      localStorage.setItem('refreshToken', newRefreshToken);
      setAccessToken(newAccessToken);
      setRefreshToken(newRefreshToken);

      if (import.meta.env.DEV) console.log('Token refreshed successfully');

      refreshQueueRef.current.forEach((resolve) => resolve(true));
      refreshQueueRef.current = [];
      return true;
    } catch (error) {
      if (import.meta.env.DEV) console.error('Failed to refresh token:', error);
      // Refresh failed, clear auth and force re-login
      clearAuth();

      refreshQueueRef.current.forEach((resolve) => resolve(false));
      refreshQueueRef.current = [];
      return false;
    } finally {
      isRefreshingRef.current = false;
    }
  }, [refreshToken, clearAuth]);

  // Schedule token refresh before expiration
  const scheduleTokenRefresh = useCallback((token) => {
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current);
    }

    const expiresIn = getTokenExpirationTime(token);
    // Refresh 1 minute before expiration, or immediately if less than 1 minute left
    const refreshIn = Math.max(expiresIn - 60000, 0);

    if (refreshIn > 0) {
      if (import.meta.env.DEV) {
        console.log(`Token refresh scheduled in ${Math.round(refreshIn / 1000)} seconds`);
      }
      refreshTimeoutRef.current = setTimeout(() => {
        refreshAccessToken();
      }, refreshIn);
    } else if (expiresIn > 0) {
      // Token expires soon, refresh immediately
      refreshAccessToken();
    }
  }, [refreshAccessToken]);

  // Fetch user profile on initial mount only
  // login() and register() set user directly, so re-fetching on token change is unnecessary
  useEffect(() => {
    const fetchUser = async () => {
      if (hasFetchedRef.current) return;
      hasFetchedRef.current = true;

      if (!accessToken) {
        setLoading(false);
        return;
      }

      try {
        // If token is already expired, refresh before fetching user
        const expiresIn = getTokenExpirationTime(accessToken);
        if (expiresIn <= 0) {
          const refreshed = await refreshAccessToken();
          if (!refreshed) return;
          // Use refreshed token directly from localStorage
          const newToken = localStorage.getItem('accessToken');
          const response = await api.get('/api/auth/me', {
            headers: { Authorization: `Bearer ${newToken}` },
          });
          setUser(response.data.user);
          scheduleTokenRefresh(newToken);
          return;
        }

        const response = await api.get('/api/auth/me');
        setUser(response.data.user);
        scheduleTokenRefresh(accessToken);
      } catch (error) {
        if (import.meta.env.DEV) console.error('Failed to fetch user:', error);
        if (error.response?.status === 401) {
          const refreshed = await refreshAccessToken();
          if (refreshed) {
            try {
              const newToken = localStorage.getItem('accessToken');
              const retryResponse = await api.get('/api/auth/me', {
                headers: { Authorization: `Bearer ${newToken}` },
              });
              setUser(retryResponse.data.user);
            } catch (_retryError) {
              clearAuth();
            }
          }
        } else {
          clearAuth();
        }
      } finally {
        setLoading(false);
      }
    };

    fetchUser();

    // Cleanup timeout on unmount
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
    };
  }, [accessToken, refreshAccessToken, scheduleTokenRefresh, clearAuth]);

  // Update api interceptor to use current access token
  useEffect(() => {
    const interceptor = api.interceptors.request.use(
      (config) => {
        if (accessToken) {
          config.headers.Authorization = `Bearer ${accessToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    return () => {
      api.interceptors.request.eject(interceptor);
    };
  }, [accessToken]);

  // Response interceptor to handle 401 errors and attempt refresh
  useEffect(() => {
    const interceptor = api.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        // If 401 and not already retrying and not the refresh endpoint
        if (
          error.response?.status === 401 &&
          !originalRequest._retry &&
          !originalRequest.url.includes('/api/auth/refresh')
        ) {
          originalRequest._retry = true;

          const refreshed = await refreshAccessToken();
          if (refreshed) {
            // Retry the original request with new token
            const newToken = localStorage.getItem('accessToken');
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return api(originalRequest);
          }
        }

        return Promise.reject(error);
      }
    );

    return () => {
      api.interceptors.response.eject(interceptor);
    };
  }, [refreshAccessToken]);

  const login = useCallback(async (email, password) => {
    try {
      const response = await api.post('/api/auth/login', { email, password });
      const { accessToken: newAccessToken, refreshToken: newRefreshToken, user: userData } = response.data;

      localStorage.setItem('accessToken', newAccessToken);
      localStorage.setItem('refreshToken', newRefreshToken);
      setAccessToken(newAccessToken);
      setRefreshToken(newRefreshToken);
      setUser(userData);

      // Schedule token refresh
      scheduleTokenRefresh(newAccessToken);

      return { success: true };
    } catch (error) {
      const message = error.response?.data?.error || error.response?.data?.detail || 'Login failed. Please try again.';
      return { success: false, error: message };
    }
  }, [scheduleTokenRefresh]);

  const register = useCallback(async (name, email, password) => {
    try {
      const response = await api.post('/api/auth/register', { name, email, password });
      const { accessToken: newAccessToken, refreshToken: newRefreshToken, user: userData } = response.data;

      localStorage.setItem('accessToken', newAccessToken);
      localStorage.setItem('refreshToken', newRefreshToken);
      setAccessToken(newAccessToken);
      setRefreshToken(newRefreshToken);
      setUser(userData);

      // Schedule token refresh
      scheduleTokenRefresh(newAccessToken);

      return { success: true };
    } catch (error) {
      const message = error.response?.data?.error || error.response?.data?.detail || 'Registration failed. Please try again.';
      return { success: false, error: message };
    }
  }, [scheduleTokenRefresh]);

  const logout = useCallback(async () => {
    try {
      if (refreshToken) {
        await api.post('/api/auth/logout', { refreshToken });
      }
    } catch (error) {
      if (import.meta.env.DEV) console.error('Logout API error:', error);
    } finally {
      clearAuth();
    }
  }, [refreshToken, clearAuth]);

  const value = {
    user,
    token: accessToken, // Keep 'token' for backward compatibility
    accessToken,
    refreshToken,
    loading,
    isAuthenticated: !!accessToken && !!user,
    login,
    register,
    logout,
    refreshAccessToken,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
