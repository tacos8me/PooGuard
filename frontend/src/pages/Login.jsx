import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({});
  const [touched, setTouched] = useState({});

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  const validateField = (name, value) => {
    switch (name) {
      case 'email':
        if (!value) return 'Email is required';
        if (!value.includes('@')) return 'Invalid email format';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Invalid email format';
        return '';
      case 'password':
        if (!value) return 'Password is required';
        return '';
      default:
        return '';
    }
  };

  const handleBlur = (e) => {
    const { name, value } = e.target;
    setTouched((prev) => ({ ...prev, [name]: true }));
    setFieldErrors((prev) => ({ ...prev, [name]: validateField(name, value) }));
  };

  const handleFieldChange = (name, value) => {
    if (name === 'email') setEmail(value);
    if (name === 'password') setPassword(value);

    if (touched[name]) {
      setFieldErrors((prev) => ({ ...prev, [name]: validateField(name, value) }));
    }
  };

  const isFormValid = () => {
    const emailError = validateField('email', email);
    const passwordError = validateField('password', password);
    return !emailError && !passwordError && email && password;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = await login(email, password);

    if (result.success) {
      navigate(from, { replace: true });
    } else {
      setError(result.error);
    }

    setIsLoading(false);
  };

  function getFieldClasses(fieldName, fieldValue) {
    if (touched[fieldName] && fieldErrors[fieldName]) {
      return 'border-red-500/60 focus:border-red-500 focus:ring-red-500/20';
    }
    if (touched[fieldName] && !fieldErrors[fieldName] && fieldValue) {
      return 'border-primary-500/60 focus:border-primary-500 focus:ring-primary-500/20';
    }
    return '';
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-950 px-4 relative overflow-hidden">
      {/* Animated grid background */}
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(176, 125, 79, 0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(176, 125, 79, 0.3) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      <div className="w-full max-w-md relative z-10">
        {/* Brand */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-primary-500 font-mono tracking-tight">
            <span className="text-primary-600/70">💩 </span>
            PooGuard
          </h1>
          <p className="text-zinc-500 mt-2 text-sm tracking-wide uppercase">
            Keeps the shit away
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl shadow-lg shadow-black/40 p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
                <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {error}
              </div>
            )}

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-zinc-400 mb-1.5">
                Email address
              </label>
              <div className="relative">
                <input
                  id="email"
                  name="email"
                  type="email"
                  value={email}
                  onChange={(e) => handleFieldChange('email', e.target.value)}
                  onBlur={handleBlur}
                  className={`w-full px-4 py-2.5 bg-zinc-950 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-primary-500/30 focus:border-primary-500 transition-all duration-200 ${getFieldClasses('email', email)}`}
                  placeholder="you@example.com"
                  required
                  autoComplete="email"
                  aria-invalid={touched.email && fieldErrors.email ? 'true' : 'false'}
                  aria-describedby={fieldErrors.email ? 'email-error' : undefined}
                />
                {touched.email && !fieldErrors.email && email && (
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-primary-500">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                )}
              </div>
              {touched.email && fieldErrors.email && (
                <p id="email-error" className="mt-1 text-sm text-red-400" role="alert">
                  {fieldErrors.email}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-zinc-400 mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  name="password"
                  type="password"
                  value={password}
                  onChange={(e) => handleFieldChange('password', e.target.value)}
                  onBlur={handleBlur}
                  className={`w-full px-4 py-2.5 bg-zinc-950 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-primary-500/30 focus:border-primary-500 transition-all duration-200 ${getFieldClasses('password', password)}`}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                  aria-invalid={touched.password && fieldErrors.password ? 'true' : 'false'}
                  aria-describedby={fieldErrors.password ? 'password-error' : undefined}
                />
                {touched.password && !fieldErrors.password && password && (
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-primary-500">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                )}
              </div>
              {touched.password && fieldErrors.password && (
                <p id="password-error" className="mt-1 text-sm text-red-400" role="alert">
                  {fieldErrors.password}
                </p>
              )}
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="w-4 h-4 rounded border-zinc-700 bg-zinc-950 text-primary-600 focus:ring-primary-500 focus:ring-offset-zinc-900"
                />
                <span className="text-sm text-zinc-400">Remember me</span>
              </label>
              <span
                className="text-sm text-zinc-600 cursor-not-allowed"
                title="Coming soon"
              >
                Forgot password?
              </span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !isFormValid()}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg font-medium text-white bg-primary-600 hover:bg-primary-500 hover:shadow-[0_0_20px_rgba(176,125,79,0.15)] focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-zinc-900 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:shadow-none"
            >
              {isLoading ? (
                <>
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    />
                  </svg>
                  Signing in...
                </>
              ) : (
                'Sign in'
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-zinc-400 text-sm">
              Don&apos;t have an account?{' '}
              <Link to="/register" className="text-primary-500 hover:text-primary-400 font-medium transition-colors">
                Create one
              </Link>
            </p>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-zinc-600 text-xs mt-8 font-mono">
          Protected by PooGuard 💩
        </p>
      </div>
    </div>
  );
}

export default Login;
