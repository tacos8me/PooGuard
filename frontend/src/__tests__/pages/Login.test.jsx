import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import Login from '../../pages/Login';
import { AuthProvider } from '../../context/AuthContext';
import api from '../../lib/api';

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

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const renderLogin = () => {
  return render(
    <BrowserRouter>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('Login', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.getItem.mockReturnValue(null);
  });

  it('renders login form with all elements', () => {
    renderLogin();

    expect(screen.getByText('PooGuard')).toBeInTheDocument();
    expect(screen.getByLabelText(/email address/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('renders email and password inputs with correct types', () => {
    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);

    expect(emailInput).toHaveAttribute('type', 'email');
    expect(passwordInput).toHaveAttribute('type', 'password');
  });

  it('renders remember me checkbox', () => {
    renderLogin();

    expect(screen.getByText(/remember me/i)).toBeInTheDocument();
  });

  it('renders forgot password link', () => {
    renderLogin();

    expect(screen.getByText(/forgot password/i)).toBeInTheDocument();
  });

  it('renders link to register page', () => {
    renderLogin();

    const registerLink = screen.getByRole('link', { name: /create one/i });
    expect(registerLink).toHaveAttribute('href', '/register');
  });

  it('allows user to type in email field', async () => {
    const user = userEvent.setup();
    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    await user.type(emailInput, 'test@example.com');

    expect(emailInput).toHaveValue('test@example.com');
  });

  it('allows user to type in password field', async () => {
    const user = userEvent.setup();
    renderLogin();

    const passwordInput = screen.getByLabelText(/password/i);
    await user.type(passwordInput, 'secretpassword');

    expect(passwordInput).toHaveValue('secretpassword');
  });

  it('submits the form with correct credentials', async () => {
    const user = userEvent.setup();
    api.post.mockResolvedValueOnce({
      data: {
        accessToken: 'mock-token',
        refreshToken: 'mock-refresh-token',
        user: { id: 1, name: 'Test User', email: 'test@example.com' },
      },
    });

    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/auth/login', {
        email: 'test@example.com',
        password: 'password123',
      });
    });
  });

  it('navigates to dashboard on successful login', async () => {
    const user = userEvent.setup();
    api.post.mockResolvedValueOnce({
      data: {
        accessToken: 'mock-token',
        refreshToken: 'mock-refresh-token',
        user: { id: 1, name: 'Test User', email: 'test@example.com' },
      },
    });

    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard', { replace: true });
    });
  });

  it('stores token in localStorage on successful login', async () => {
    const user = userEvent.setup();
    api.post.mockResolvedValueOnce({
      data: {
        accessToken: 'mock-token-123',
        refreshToken: 'mock-refresh-token',
        user: { id: 1, name: 'Test User', email: 'test@example.com' },
      },
    });

    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    await waitFor(() => {
      expect(window.localStorage.setItem).toHaveBeenCalledWith('accessToken', 'mock-token-123');
    });
  });

  it('displays error message on failed login', async () => {
    const user = userEvent.setup();
    api.post.mockRejectedValueOnce({
      response: {
        data: {
          detail: 'Invalid email or password',
        },
      },
    });

    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'wrong@example.com');
    await user.type(passwordInput, 'wrongpassword');
    await user.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText('Invalid email or password')).toBeInTheDocument();
    });
  });

  it('shows loading state while submitting', async () => {
    const user = userEvent.setup();
    // Create a promise that won't resolve immediately
    let resolvePromise;
    api.post.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePromise = resolve;
        })
    );

    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    expect(screen.getByText(/signing in/i)).toBeInTheDocument();

    // Resolve the promise to clean up
    resolvePromise({
      data: {
        accessToken: 'mock-token',
        refreshToken: 'mock-refresh-token',
        user: { id: 1 },
      },
    });
  });

  it('disables submit button while loading', async () => {
    const user = userEvent.setup();
    let resolvePromise;
    api.post.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePromise = resolve;
        })
    );

    renderLogin();

    const emailInput = screen.getByLabelText(/email address/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password123');
    await user.click(submitButton);

    const loadingButton = screen.getByRole('button', { name: /signing in/i });
    expect(loadingButton).toBeDisabled();

    // Resolve the promise to clean up
    resolvePromise({
      data: {
        accessToken: 'mock-token',
        refreshToken: 'mock-refresh-token',
        user: { id: 1 },
      },
    });
  });
});
