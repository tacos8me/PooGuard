import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const PASSWORD_REQUIREMENTS = [
  { key: 'length', label: 'At least 8 characters', test: (pw) => pw.length >= 8 },
  { key: 'uppercase', label: 'One uppercase letter', test: (pw) => /[A-Z]/.test(pw) },
  { key: 'lowercase', label: 'One lowercase letter', test: (pw) => /[a-z]/.test(pw) },
  { key: 'number', label: 'One number', test: (pw) => /\d/.test(pw) },
];

function Register() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [termsAccepted, setTermsAccepted] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  const validateField = (fieldName, value, allValues = {}) => {
    switch (fieldName) {
      case 'name':
        if (!value) return 'Full name is required';
        if (value.length < 2) return 'Name must be at least 2 characters';
        return '';
      case 'email':
        if (!value) return 'Email is required';
        if (!value.includes('@')) return 'Invalid email format';
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Invalid email format';
        return '';
      case 'password':
        if (!value) return 'Password is required';
        if (value.length < 8) return 'Password must be at least 8 characters';
        return '';
      case 'confirmPassword':
        if (!value) return 'Please confirm your password';
        if (value !== allValues.password) return 'Passwords do not match';
        return '';
      default:
        return '';
    }
  };

  const handleBlur = (e) => {
    const { name: fieldName, value } = e.target;
    setTouched((prev) => ({ ...prev, [fieldName]: true }));
    setFieldErrors((prev) => ({
      ...prev,
      [fieldName]: validateField(fieldName, value, { password, confirmPassword }),
    }));
  };

  const handleFieldChange = (fieldName, value) => {
    if (fieldName === 'name') setName(value);
    if (fieldName === 'email') setEmail(value);
    if (fieldName === 'password') {
      setPassword(value);
      if (touched.confirmPassword) {
        setFieldErrors((prev) => ({
          ...prev,
          confirmPassword: validateField('confirmPassword', confirmPassword, { password: value }),
        }));
      }
    }
    if (fieldName === 'confirmPassword') setConfirmPassword(value);

    if (touched[fieldName]) {
      setFieldErrors((prev) => ({
        ...prev,
        [fieldName]: validateField(fieldName, value, { password: fieldName === 'password' ? value : password, confirmPassword }),
      }));
    }
  };

  const isFormValid = () => {
    const nameError = validateField('name', name);
    const emailError = validateField('email', email);
    const passwordError = validateField('password', password);
    const confirmPasswordError = validateField('confirmPassword', confirmPassword, { password });
    return !nameError && !emailError && !passwordError && !confirmPasswordError && termsAccepted;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    setIsLoading(true);

    const result = await register(name, email, password);

    if (result.success) {
      navigate('/dashboard', { replace: true });
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

  const inputBaseClasses =
    'w-full px-4 py-2.5 bg-zinc-950 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-primary-500/30 focus:border-primary-500 transition-all duration-200';

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-950 px-4 py-12 relative overflow-hidden">
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
            Create your account
          </p>
        </div>

        {/* Register Card */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl shadow-lg shadow-black/40 p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center gap-2">
                <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {error}
              </div>
            )}

            <div>
              <label htmlFor="name" className="block text-sm font-medium text-zinc-400 mb-1.5">
                Full name
              </label>
              <div className="relative">
                <input
                  id="name"
                  name="name"
                  type="text"
                  value={name}
                  onChange={(e) => handleFieldChange('name', e.target.value)}
                  onBlur={handleBlur}
                  className={`${inputBaseClasses} ${getFieldClasses('name', name)}`}
                  placeholder="John Doe"
                  required
                  autoComplete="name"
                  aria-invalid={touched.name && fieldErrors.name ? 'true' : 'false'}
                  aria-describedby={fieldErrors.name ? 'name-error' : undefined}
                />
                {touched.name && !fieldErrors.name && name && (
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-primary-500">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                )}
              </div>
              {touched.name && fieldErrors.name && (
                <p id="name-error" className="mt-1 text-sm text-red-400" role="alert">
                  {fieldErrors.name}
                </p>
              )}
            </div>

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
                  className={`${inputBaseClasses} ${getFieldClasses('email', email)}`}
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
                  className={`${inputBaseClasses} ${getFieldClasses('password', password)}`}
                  placeholder="At least 8 characters"
                  required
                  autoComplete="new-password"
                  aria-invalid={touched.password && fieldErrors.password ? 'true' : 'false'}
                  aria-describedby={fieldErrors.password ? 'password-error' : 'password-requirements'}
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

              {/* Password requirements checklist */}
              {password.length > 0 && (
                <ul id="password-requirements" className="mt-3 space-y-1.5">
                  {PASSWORD_REQUIREMENTS.map((req) => {
                    const met = req.test(password);
                    return (
                      <li key={req.key} className="flex items-center gap-2 text-xs">
                        {met ? (
                          <svg className="w-3.5 h-3.5 text-primary-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                          </svg>
                        ) : (
                          <svg className="w-3.5 h-3.5 text-zinc-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <circle cx="12" cy="12" r="9" strokeWidth={2} />
                          </svg>
                        )}
                        <span className={met ? 'text-primary-500' : 'text-zinc-500'}>
                          {req.label}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-zinc-400 mb-1.5">
                Confirm password
              </label>
              <div className="relative">
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => handleFieldChange('confirmPassword', e.target.value)}
                  onBlur={handleBlur}
                  className={`${inputBaseClasses} ${getFieldClasses('confirmPassword', confirmPassword)}`}
                  placeholder="Confirm your password"
                  required
                  autoComplete="new-password"
                  aria-invalid={touched.confirmPassword && fieldErrors.confirmPassword ? 'true' : 'false'}
                  aria-describedby={fieldErrors.confirmPassword ? 'confirmPassword-error' : undefined}
                />
                {touched.confirmPassword && !fieldErrors.confirmPassword && confirmPassword && (
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-primary-500">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                )}
              </div>
              {touched.confirmPassword && fieldErrors.confirmPassword && (
                <p id="confirmPassword-error" className="mt-1 text-sm text-red-400" role="alert">
                  {fieldErrors.confirmPassword}
                </p>
              )}
            </div>

            <div className="flex items-start gap-2">
              <input
                id="terms"
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                required
                className="w-4 h-4 mt-1 rounded border-zinc-700 bg-zinc-950 text-primary-600 focus:ring-primary-500 focus:ring-offset-zinc-900"
                aria-describedby="terms-description"
              />
              <label id="terms-description" htmlFor="terms" className="text-sm text-zinc-400 cursor-pointer">
                I agree to the{' '}
                <span
                  className="text-zinc-500 cursor-not-allowed"
                  title="Coming soon"
                >
                  Terms of Service
                </span>{' '}
                and{' '}
                <span
                  className="text-zinc-500 cursor-not-allowed"
                  title="Coming soon"
                >
                  Privacy Policy
                </span>
              </label>
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
                  Creating account...
                </>
              ) : (
                'Create account'
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-zinc-400 text-sm">
              Already have an account?{' '}
              <Link to="/login" className="text-primary-500 hover:text-primary-400 font-medium transition-colors">
                Sign in
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

export default Register;
