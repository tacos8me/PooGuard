import { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import ConnectionStatus from './ConnectionStatus';

const navigation = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
        />
      </svg>
    ),
  },
  {
    name: 'Analytics',
    href: '/analytics',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
        />
      </svg>
    ),
  },
  {
    name: 'Alerts',
    href: '/alerts',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
        />
      </svg>
    ),
  },
  {
    name: 'Audit Log',
    href: '/audit',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        />
      </svg>
    ),
  },
  {
    name: 'Sessions',
    href: '/sessions',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
        />
      </svg>
    ),
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
        />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
        />
      </svg>
    ),
  },
];

function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);

  function handleLogout() {
    logout();
    navigate('/login');
  }

  useEffect(() => {
    setMenuOpen(false);
  }, [location]);

  useEffect(() => {
    function handleEscape(e) {
      if (e.key === 'Escape') {
        setMenuOpen(false);
      }
    }

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, []);

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col">
      {/* Skip link for accessibility */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-4 focus:z-[60] focus:px-4 focus:py-2 focus:bg-primary-600 focus:text-white focus:rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
      >
        Skip to main content
      </a>

      {/* Top navigation bar */}
      <header className="sticky top-0 z-50 bg-zinc-950 border-b border-zinc-800/60">
        <nav
          className="flex items-center justify-between h-11 px-4 sm:px-6"
          role="navigation"
          aria-label="Main navigation"
        >
          {/* Left: Logo */}
          <div className="flex items-center gap-6">
            <div className="flex items-baseline gap-1.5">
              <span className="font-mono text-sm tracking-tight">
                <span role="img" aria-label="poo">&#x1F4A9;</span>{' '}
                <span className="text-primary-500">Poo</span>
                <span className="text-zinc-100">Guard</span>
              </span>
              <span className="hidden sm:inline text-[10px] text-zinc-500 font-mono">
                Keeps the shit away
              </span>
            </div>

            {/* Desktop nav links */}
            <div className="hidden sm:flex items-center gap-0.5">
              {navigation.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.href}
                  className={({ isActive }) => {
                    const base =
                      'flex items-center gap-1.5 px-3 py-1 text-xs font-mono uppercase tracking-wider transition-colors duration-150 border-b-2 focus:outline-none focus:ring-1 focus:ring-primary-500/50 focus:rounded-sm';
                    if (isActive) {
                      return `${base} border-primary-500 text-primary-400 bg-primary-500/5`;
                    }
                    return `${base} border-transparent text-zinc-500 hover:text-zinc-300`;
                  }}
                >
                  {({ isActive }) => (
                    <>
                      <span className={isActive ? 'text-primary-400' : 'text-zinc-600'}>
                        {item.icon}
                      </span>
                      <span>{item.name}</span>
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>

          {/* Right: connection status, user, logout */}
          <div className="hidden sm:flex items-center gap-4">
            <ConnectionStatus />
            <div className="h-3 w-px bg-zinc-800/60" aria-hidden="true" />
            <span className="text-xs text-zinc-500 font-mono truncate max-w-[180px]">
              {user?.email || 'user@example.com'}
            </span>
            <button
              onClick={handleLogout}
              className="p-1 rounded text-zinc-600 hover:text-red-400 transition-colors duration-150 focus:outline-none focus:ring-1 focus:ring-primary-500/50"
              title="Sign out"
              aria-label="Log out"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                />
              </svg>
            </button>
          </div>

          {/* Mobile: hamburger button */}
          <button
            className="sm:hidden p-1.5 rounded text-zinc-500 hover:text-zinc-200 transition-colors duration-150 focus:outline-none focus:ring-1 focus:ring-primary-500/50"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-expanded={menuOpen}
            aria-controls="mobile-menu"
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          >
            {menuOpen ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            )}
          </button>
        </nav>

        {/* Mobile dropdown menu */}
        {menuOpen && (
          <>
            <div
              className="fixed inset-0 top-11 bg-black/60 backdrop-blur-sm z-40 sm:hidden"
              onClick={() => setMenuOpen(false)}
              aria-hidden="true"
            />
            <div
              id="mobile-menu"
              className="sm:hidden absolute left-0 right-0 z-50 bg-zinc-950 border-b border-zinc-800/60 animate-fade-in"
            >
              <div className="px-3 py-2 space-y-0.5">
                {navigation.map((item) => (
                  <NavLink
                    key={item.name}
                    to={item.href}
                    className={({ isActive }) => {
                      const base =
                        'flex items-center gap-3 px-3 py-2.5 text-xs font-mono uppercase tracking-wider rounded-md transition-colors duration-150 focus:outline-none focus:ring-1 focus:ring-primary-500/50';
                      if (isActive) {
                        return `${base} text-primary-400 bg-primary-500/5 border-l-2 border-primary-500`;
                      }
                      return `${base} text-zinc-500 hover:text-zinc-300 border-l-2 border-transparent`;
                    }}
                  >
                    {({ isActive }) => (
                      <>
                        <span className={isActive ? 'text-primary-400' : 'text-zinc-600'}>
                          {item.icon}
                        </span>
                        <span>{item.name}</span>
                      </>
                    )}
                  </NavLink>
                ))}
              </div>

              <div className="border-t border-zinc-800/60 px-4 py-3 space-y-3">
                <ConnectionStatus />
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-zinc-500 font-mono truncate">
                    {user?.email || 'user@example.com'}
                  </span>
                  <button
                    onClick={handleLogout}
                    className="shrink-0 p-1 rounded text-zinc-600 hover:text-red-400 transition-colors duration-150 focus:outline-none focus:ring-1 focus:ring-primary-500/50"
                    title="Sign out"
                    aria-label="Log out"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={1.5}
                        d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                      />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </header>

      {/* Page content — full width */}
      <main id="main-content" className="flex-1 p-6 overflow-auto" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}

export default Layout;
