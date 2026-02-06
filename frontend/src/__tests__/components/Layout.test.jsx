import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import Layout from '../../components/Layout';
import { AuthProvider } from '../../context/AuthContext';

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

// Mock SocketContext
vi.mock('../../context/SocketContext', () => ({
  useSocket: () => ({
    socket: null,
    connectionState: 'connected',
    isConnected: true,
    isReconnecting: false,
    reconnectAttempt: 0,
    reconnect: vi.fn(),
  }),
  SocketProvider: ({ children }) => children,
  CONNECTION_STATES: {
    CONNECTED: 'connected',
    DISCONNECTED: 'disconnected',
    RECONNECTING: 'reconnecting',
  },
}));

const renderWithProviders = (component) => {
  return render(
    <BrowserRouter>
      <AuthProvider>
        {component}
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('Layout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock localStorage to return a token so user is considered authenticated
    window.localStorage.getItem.mockImplementation((key) => {
      if (key === 'accessToken') return 'mock-token';
      if (key === 'refreshToken') return 'mock-refresh-token';
      return null;
    });
  });

  it('renders the sidebar with PooGuard branding', () => {
    renderWithProviders(<Layout />);

    expect(screen.getByText('Poo')).toBeInTheDocument();
    expect(screen.getByText('Guard')).toBeInTheDocument();
  });

  it('renders navigation links in the sidebar', () => {
    renderWithProviders(<Layout />);

    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Analytics')).toBeInTheDocument();
    expect(screen.getByText('Alerts')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('renders navigation with proper role attribute', () => {
    renderWithProviders(<Layout />);

    const nav = screen.getByRole('navigation', { name: /main navigation/i });
    expect(nav).toBeInTheDocument();
  });

  it('renders logout button', () => {
    renderWithProviders(<Layout />);

    const logoutButton = screen.getByRole('button', { name: /log out/i });
    expect(logoutButton).toBeInTheDocument();
  });

  it('calls logout and navigates to login when logout button is clicked', async () => {
    const user = userEvent.setup();
    renderWithProviders(<Layout />);

    const logoutButton = screen.getByRole('button', { name: /log out/i });
    await user.click(logoutButton);

    expect(window.localStorage.removeItem).toHaveBeenCalledWith('accessToken');
    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });

  it('renders navigation links with correct hrefs', () => {
    renderWithProviders(<Layout />);

    const dashboardLink = screen.getByRole('link', { name: /dashboard/i });
    const analyticsLink = screen.getByRole('link', { name: /analytics/i });
    const alertsLink = screen.getByRole('link', { name: /alerts/i });
    const settingsLink = screen.getByRole('link', { name: /settings/i });

    expect(dashboardLink).toHaveAttribute('href', '/dashboard');
    expect(analyticsLink).toHaveAttribute('href', '/analytics');
    expect(alertsLink).toHaveAttribute('href', '/alerts');
    expect(settingsLink).toHaveAttribute('href', '/settings');
  });
});
