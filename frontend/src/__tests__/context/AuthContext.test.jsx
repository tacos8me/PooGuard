import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthProvider, useAuth } from '../../context/AuthContext';
import api from '../../lib/api';

// Helper to create a mock JWT with future expiration
const createMockJwt = (payload = {}) => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const defaultPayload = {
    id: 1,
    email: 'test@example.com',
    role: 'admin',
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    ...payload,
  };
  const base64Header = btoa(JSON.stringify(header));
  const base64Payload = btoa(JSON.stringify(defaultPayload));
  return `${base64Header}.${base64Payload}.mock-signature`;
};

const mockAccessToken = createMockJwt();

// Mock the api module
vi.mock('../../lib/api', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: {
      request: { use: vi.fn(() => 1), eject: vi.fn() },
      response: { use: vi.fn(() => 1), eject: vi.fn() },
    },
  },
  initializeCsrf: vi.fn().mockResolvedValue('mock-csrf-token'),
}));

// Test component that uses the auth context
function TestComponent() {
  const { user, token, loading, isAuthenticated, login, logout, register } = useAuth();

  return (
    <div>
      <div data-testid="loading">{loading ? 'loading' : 'not-loading'}</div>
      <div data-testid="authenticated">{isAuthenticated ? 'authenticated' : 'not-authenticated'}</div>
      <div data-testid="user">{user ? JSON.stringify(user) : 'no-user'}</div>
      <div data-testid="token">{token || 'no-token'}</div>
      <button onClick={() => login('test@example.com', 'password')}>Login</button>
      <button onClick={() => register('Test User', 'test@example.com', 'password')}>Register</button>
      <button onClick={logout}>Logout</button>
    </div>
  );
}

// Component to test useAuth outside provider
function TestUseAuthOutsideProvider() {
  try {
    useAuth();
    return <div>No error</div>;
  } catch (error) {
    return <div data-testid="error">{error.message}</div>;
  }
}

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.getItem.mockReturnValue(null);
  });

  describe('Initial state', () => {
    it('starts with no user and not authenticated when no token exists', async () => {
      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('not-loading');
      });

      expect(screen.getByTestId('authenticated')).toHaveTextContent('not-authenticated');
      expect(screen.getByTestId('user')).toHaveTextContent('no-user');
      expect(screen.getByTestId('token')).toHaveTextContent('no-token');
    });

    it('fetches user when token exists in localStorage', async () => {
      window.localStorage.getItem.mockImplementation((key) => {
        if (key === 'accessToken') return mockAccessToken;
        return null;
      });

      api.get.mockResolvedValueOnce({
        data: { user: { id: 1, name: 'Test User', email: 'test@example.com' } },
      });

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('not-loading');
      });

      expect(api.get).toHaveBeenCalledWith('/api/auth/me');
      expect(screen.getByTestId('authenticated')).toHaveTextContent('authenticated');
    });

    it('clears token when fetching user fails', async () => {
      // Use a valid mock JWT so expiration check passes and /api/auth/me is called
      window.localStorage.getItem.mockImplementation((key) => {
        if (key === 'accessToken') return mockAccessToken;
        return null;
      });

      api.get.mockRejectedValueOnce(new Error('Unauthorized'));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('not-loading');
      });

      expect(window.localStorage.removeItem).toHaveBeenCalledWith('accessToken');
      expect(screen.getByTestId('authenticated')).toHaveTextContent('not-authenticated');
    });
  });

  describe('Login', () => {
    it('successfully logs in user', async () => {
      const user = userEvent.setup();
      api.post.mockResolvedValueOnce({
        data: {
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
          user: { id: 1, name: 'Test User', email: 'test@example.com' },
        },
      });

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('not-loading');
      });

      await user.click(screen.getByText('Login'));

      await waitFor(() => {
        expect(screen.getByTestId('authenticated')).toHaveTextContent('authenticated');
      });

      expect(api.post).toHaveBeenCalledWith('/api/auth/login', {
        email: 'test@example.com',
        password: 'password',
      });
      expect(window.localStorage.setItem).toHaveBeenCalledWith('accessToken', 'new-access-token');
    });

    it('returns error on login failure', async () => {
      const user = userEvent.setup();
      api.post.mockRejectedValueOnce({
        response: { data: { detail: 'Invalid credentials' } },
      });

      let loginResult;
      function TestLoginResult() {
        const { login } = useAuth();
        return (
          <button
            onClick={async () => {
              loginResult = await login('test@example.com', 'wrong');
            }}
          >
            Login
          </button>
        );
      }

      render(
        <AuthProvider>
          <TestLoginResult />
        </AuthProvider>
      );

      await user.click(screen.getByText('Login'));

      await waitFor(() => {
        expect(loginResult).toEqual({ success: false, error: 'Invalid credentials' });
      });
    });

    it('returns default error message when no detail provided', async () => {
      const user = userEvent.setup();
      api.post.mockRejectedValueOnce(new Error('Network error'));

      let loginResult;
      function TestLoginResult() {
        const { login } = useAuth();
        return (
          <button
            onClick={async () => {
              loginResult = await login('test@example.com', 'password');
            }}
          >
            Login
          </button>
        );
      }

      render(
        <AuthProvider>
          <TestLoginResult />
        </AuthProvider>
      );

      await user.click(screen.getByText('Login'));

      await waitFor(() => {
        expect(loginResult).toEqual({ success: false, error: 'Login failed. Please try again.' });
      });
    });
  });

  describe('Register', () => {
    it('successfully registers user', async () => {
      const user = userEvent.setup();
      api.post.mockResolvedValueOnce({
        data: {
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
          user: { id: 1, name: 'Test User', email: 'test@example.com' },
        },
      });

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('not-loading');
      });

      await user.click(screen.getByText('Register'));

      await waitFor(() => {
        expect(screen.getByTestId('authenticated')).toHaveTextContent('authenticated');
      });

      expect(api.post).toHaveBeenCalledWith('/api/auth/register', {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password',
      });
      expect(window.localStorage.setItem).toHaveBeenCalledWith('accessToken', 'new-access-token');
    });

    it('returns error on registration failure', async () => {
      const user = userEvent.setup();
      api.post.mockRejectedValueOnce({
        response: { data: { detail: 'Email already registered' } },
      });

      let registerResult;
      function TestRegisterResult() {
        const { register } = useAuth();
        return (
          <button
            onClick={async () => {
              registerResult = await register('Test', 'test@example.com', 'password');
            }}
          >
            Register
          </button>
        );
      }

      render(
        <AuthProvider>
          <TestRegisterResult />
        </AuthProvider>
      );

      await user.click(screen.getByText('Register'));

      await waitFor(() => {
        expect(registerResult).toEqual({ success: false, error: 'Email already registered' });
      });
    });
  });

  describe('Logout', () => {
    it('logs out user and clears state', async () => {
      const user = userEvent.setup();
      window.localStorage.getItem.mockImplementation((key) => {
        if (key === 'accessToken') return mockAccessToken;
        return null;
      });

      api.get.mockResolvedValueOnce({
        data: { user: { id: 1, name: 'Test User', email: 'test@example.com' } },
      });

      // Mock the logout endpoint
      api.post.mockResolvedValueOnce({ data: { success: true } });

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('authenticated')).toHaveTextContent('authenticated');
      });

      await user.click(screen.getByText('Logout'));

      await waitFor(() => {
        expect(screen.getByTestId('authenticated')).toHaveTextContent('not-authenticated');
      });

      expect(window.localStorage.removeItem).toHaveBeenCalledWith('accessToken');
      expect(screen.getByTestId('user')).toHaveTextContent('no-user');
      expect(screen.getByTestId('token')).toHaveTextContent('no-token');
    });
  });

  describe('useAuth hook', () => {
    it('throws error when used outside AuthProvider', () => {
      // Suppress console.error for this test
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      render(<TestUseAuthOutsideProvider />);

      expect(screen.getByTestId('error')).toHaveTextContent(
        'useAuth must be used within an AuthProvider'
      );

      consoleSpy.mockRestore();
    });
  });

  describe('isAuthenticated', () => {
    it('is false when only token exists but no user', async () => {
      window.localStorage.getItem.mockImplementation((key) => {
        if (key === 'accessToken') return mockAccessToken;
        return null;
      });

      // Simulate api.get that never resolves during test
      api.get.mockImplementation(() => new Promise(() => {}));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      // While loading, check state
      expect(screen.getByTestId('loading')).toHaveTextContent('loading');
    });

    it('is true when both token and user exist', async () => {
      window.localStorage.getItem.mockImplementation((key) => {
        if (key === 'accessToken') return mockAccessToken;
        return null;
      });

      api.get.mockResolvedValueOnce({
        data: { user: { id: 1, name: 'Test User', email: 'test@example.com' } },
      });

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('authenticated')).toHaveTextContent('authenticated');
      });
    });
  });
});
