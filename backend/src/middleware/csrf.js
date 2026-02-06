const crypto = require('crypto');
const logger = require('../services/logger');
const config = require('../config');

// CSRF Token configuration
const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAME = 'x-csrf-token';
const TOKEN_LENGTH = 32;

// Routes that should skip CSRF validation (no session yet)
const SKIP_CSRF_ROUTES = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/refresh',
  '/api/csrf-token'
];

// HTTP methods that don't require CSRF protection
const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

/**
 * Generate a cryptographically secure random token
 */
const generateToken = () => {
  return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
};

/**
 * Middleware to set CSRF token cookie
 * Sets a new token if one doesn't exist
 */
const setCsrfCookie = (req, res, next) => {
  // Check if token already exists in cookies
  let token = req.cookies?.[CSRF_COOKIE_NAME];

  if (!token) {
    token = generateToken();

    // Set cookie options
    const cookieOptions = {
      httpOnly: false, // Must be false so JavaScript can read it
      secure: config.nodeEnv === 'production', // Only HTTPS in production
      sameSite: 'strict', // Strict same-site policy
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      path: '/'
    };

    res.cookie(CSRF_COOKIE_NAME, token, cookieOptions);
  }

  // Store token on request for easy access
  req.csrfToken = token;
  next();
};

/**
 * Middleware to verify CSRF token
 * Compares token from header with token from cookie
 */
const verifyCsrfToken = (req, res, next) => {
  // Skip for safe HTTP methods
  if (SAFE_METHODS.includes(req.method)) {
    return next();
  }

  // Skip for excluded routes
  const path = req.path;
  if (SKIP_CSRF_ROUTES.some(route => path === route || path.startsWith(route))) {
    return next();
  }

  // Get token from cookie
  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];

  // Get token from header
  const headerToken = req.headers[CSRF_HEADER_NAME];

  // Validate both tokens exist
  if (!cookieToken || !headerToken) {
    logger.warn('CSRF validation failed: missing token', {
      hasCookie: !!cookieToken,
      hasHeader: !!headerToken,
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    return res.status(403).json({
      error: 'CSRF validation failed',
      code: 'CSRF_TOKEN_MISSING'
    });
  }

  // Compare tokens using timing-safe comparison
  if (!timingSafeEqual(cookieToken, headerToken)) {
    logger.warn('CSRF validation failed: token mismatch', {
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    return res.status(403).json({
      error: 'CSRF validation failed',
      code: 'CSRF_TOKEN_MISMATCH'
    });
  }

  next();
};

/**
 * Timing-safe string comparison to prevent timing attacks
 */
const timingSafeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
};

/**
 * Route handler to get/refresh CSRF token
 */
const getCsrfTokenHandler = (req, res) => {
  // Generate a new token
  const token = generateToken();

  // Set cookie options
  const cookieOptions = {
    httpOnly: false,
    secure: config.nodeEnv === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  };

  res.cookie(CSRF_COOKIE_NAME, token, cookieOptions);

  // Also return token in response body for convenience
  res.json({ csrfToken: token });
};

/**
 * Combined middleware that sets and verifies CSRF tokens
 */
const csrfProtection = [setCsrfCookie, verifyCsrfToken];

module.exports = {
  setCsrfCookie,
  verifyCsrfToken,
  csrfProtection,
  getCsrfTokenHandler,
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  generateToken
};
