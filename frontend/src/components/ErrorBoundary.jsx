import { Component } from 'react';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null, showStack: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });

    if (import.meta.env.DEV) {
      console.error('ErrorBoundary caught an error:', error, errorInfo);
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null, showStack: false });
  };

  toggleStack = () => {
    this.setState((prev) => ({ showStack: !prev.showStack }));
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const { error, errorInfo, showStack } = this.state;
    const stackTrace = errorInfo?.componentStack;

    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="max-w-lg w-full text-center">
          {/* Error icon - shield with X */}
          <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-6">
            <svg
              className="w-8 h-8 text-red-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M15 9l-6 6m0-6l6 6"
              />
            </svg>
          </div>

          <h1 className="text-xl font-bold text-zinc-100 mb-2">
            Something went wrong
          </h1>
          <p className="text-sm text-zinc-400 mb-6">
            An unexpected error occurred. Please try refreshing the page.
          </p>

          {/* Error message in monospace */}
          {import.meta.env.DEV && error && (
            <div className="mb-4 p-4 bg-zinc-950 border border-zinc-800 rounded-lg text-left">
              <p className="text-red-400 text-sm font-mono break-all leading-relaxed">
                {error.toString()}
              </p>
            </div>
          )}

          {/* Collapsible stack trace */}
          {import.meta.env.DEV && stackTrace && (
            <div className="mb-6 text-left">
              <button
                type="button"
                onClick={this.toggleStack}
                className="flex items-center gap-2 text-xs font-mono text-zinc-500 hover:text-zinc-400 transition-colors duration-150 mb-2"
              >
                <svg
                  className={`w-3 h-3 transition-transform duration-150 ${showStack ? 'rotate-90' : ''}`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
                Stack trace
              </button>
              {showStack && (
                <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-lg overflow-x-auto">
                  <pre className="text-xs font-mono text-red-400/80 whitespace-pre-wrap leading-relaxed">
                    {stackTrace}
                  </pre>
                </div>
              )}
            </div>
          )}

          <div className="flex gap-3 justify-center">
            <button
              type="button"
              onClick={this.handleReset}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-zinc-600 focus:ring-offset-2 focus:ring-offset-zinc-950"
            >
              Try Again
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="btn-primary"
            >
              Refresh Page
            </button>
          </div>
        </div>
      </div>
    );
  }
}

export default ErrorBoundary;
