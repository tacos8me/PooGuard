const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis').default;
const { getClient } = require('../services/redis');
const logger = require('../services/logger');

// Store the Redis client once initialized
let redisClient = null;

/**
 * User tier rate limit configurations
 * Higher tiers get more generous limits
 */
const USER_TIER_LIMITS = {
  admin: {
    analyze: { windowMs: 60 * 1000, max: 100 },      // 100/min for admins
    batch: { windowMs: 60 * 1000, max: 30 },         // 30/min for batch
    general: { windowMs: 60 * 1000, max: 200 },      // 200/min general
  },
  viewer: {
    analyze: { windowMs: 60 * 1000, max: 30 },       // 30/min for viewers
    batch: { windowMs: 60 * 1000, max: 10 },         // 10/min for batch
    general: { windowMs: 60 * 1000, max: 100 },      // 100/min general
  },
  api_key: {
    analyze: { windowMs: 60 * 1000, max: 60 },       // 60/min for API key clients
    batch: { windowMs: 60 * 1000, max: 20 },         // 20/min for batch
    general: { windowMs: 60 * 1000, max: 150 },      // 150/min general
  },
  anonymous: {
    analyze: { windowMs: 60 * 1000, max: 15 },       // 15/min for anonymous
    batch: { windowMs: 60 * 1000, max: 5 },          // 5/min for batch
    general: { windowMs: 60 * 1000, max: 50 },       // 50/min general
  },
};

/**
 * Initialize Redis client for rate limiting
 * Must be called during server startup before handling requests
 */
const initRateLimiter = async () => {
  redisClient = await getClient();
  logger.info('Rate limiter Redis client initialized');
};

/**
 * Get the rate limit key for a request
 * Uses user ID for authenticated users, IP for anonymous
 * This ensures rate limits are tracked per user across all IPs
 *
 * @param {Object} req - Express request object
 * @returns {string} Rate limit key
 */
const getUserRateLimitKey = (req) => {
  if (req.user && req.user.id) {
    // Authenticated user - track by user ID (across all IPs)
    return `user:${req.user.id}`;
  }
  // Anonymous user - track by IP
  return `ip:${req.ip || req.connection?.remoteAddress || 'unknown'}`;
};

/**
 * Get the user's tier for rate limiting
 *
 * @param {Object} req - Express request object
 * @returns {string} User tier: 'admin', 'viewer', or 'anonymous'
 */
const getUserTier = (req) => {
  if (!req.user) {
    return 'anonymous';
  }
  if (req.apiKeyAuth) {
    return 'api_key';
  }
  return req.user.role === 'admin' ? 'admin' : 'viewer';
};

/**
 * Get rate limit configuration based on user tier
 *
 * @param {Object} req - Express request object
 * @param {string} limitType - Type of limit: 'analyze', 'batch', or 'general'
 * @returns {Object} Rate limit config { windowMs, max }
 */
const getTierLimits = (req, limitType) => {
  const tier = getUserTier(req);
  return USER_TIER_LIMITS[tier][limitType] || USER_TIER_LIMITS.anonymous[limitType];
};

/**
 * Create a rate limiter with Redis store for distributed limiting
 * If Redis is not initialized, uses in-memory store (not suitable for distributed setups)
 *
 * @param {Object} options - Rate limiter options
 * @param {number} options.windowMs - Time window in milliseconds
 * @param {number} options.max - Max requests per window
 * @param {string} options.message - Error message when limit exceeded
 * @param {string} options.keyPrefix - Redis key prefix for this limiter
 */
const createLimiter = (options) => {
  const { windowMs, max, message, keyPrefix } = options;

  const limiterConfig = {
    windowMs,
    max,
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false, // Disable `X-RateLimit-*` headers
    validate: false, // Limiter is lazily created (waiting for Redis), not per-request
    message: {
      error: 'Too many requests',
      message,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    handler: (req, res, next, options) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        path: req.path,
        keyPrefix
      });
      res.status(429).json(options.message);
    },
    keyGenerator: (req) => {
      // Use IP address as the key, falling back to a default
      return req.ip || req.connection?.remoteAddress || 'unknown';
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/health';
    }
  };

  // Create a middleware wrapper that lazily attaches the Redis store
  const middleware = (req, res, next) => {
    // Lazily create or update the rate limiter instance with Redis store
    if (!middleware._limiter) {
      if (redisClient) {
        // Redis is available - create limiter with Redis store
        limiterConfig.store = new RedisStore({
          sendCommand: (...args) => redisClient.sendCommand(args),
          prefix: `ratelimit:${keyPrefix}:`
        });
        logger.debug(`Rate limiter ${keyPrefix} using Redis store`);
      } else {
        // Redis not available - use default memory store
        logger.warn(`Rate limiter ${keyPrefix} using memory store (Redis not initialized)`);
      }
      middleware._limiter = rateLimit(limiterConfig);
    }

    return middleware._limiter(req, res, next);
  };

  return middleware;
};

/**
 * Create a user-aware rate limiter that applies different limits based on user tier
 * Authenticated users are tracked by user ID (across all IPs)
 * Anonymous users are tracked by IP
 *
 * @param {Object} options - Rate limiter options
 * @param {string} options.limitType - Type of limit: 'analyze', 'batch', or 'general'
 * @param {string} options.message - Error message when limit exceeded
 * @param {string} options.keyPrefix - Redis key prefix for this limiter
 */
const createUserBasedLimiter = (options) => {
  const { limitType, message, keyPrefix } = options;

  // Create limiters for each tier
  const tierLimiters = {};

  Object.keys(USER_TIER_LIMITS).forEach((tier) => {
    const tierConfig = USER_TIER_LIMITS[tier][limitType];

    const limiterConfig = {
      windowMs: tierConfig.windowMs,
      max: tierConfig.max,
      standardHeaders: true,
      legacyHeaders: false,
      validate: false, // Limiter is lazily created (waiting for Redis), not per-request
      message: {
        error: 'Too many requests',
        message,
        retryAfter: Math.ceil(tierConfig.windowMs / 1000),
      },
      handler: (req, res, next, opts) => {
        const userTier = getUserTier(req);
        const key = getUserRateLimitKey(req);
        logger.warn('Rate limit exceeded', {
          ip: req.ip,
          path: req.path,
          keyPrefix,
          userTier,
          rateLimitKey: key,
          userId: req.user?.id || null,
        });
        res.status(429).json(opts.message);
      },
      keyGenerator: getUserRateLimitKey,
      skip: (req) => {
        return req.path === '/health';
      },
    };

    tierLimiters[tier] = { config: limiterConfig, limiter: null };
  });

  // Middleware that selects the appropriate limiter based on user tier
  const middleware = (req, res, next) => {
    const tier = getUserTier(req);
    const tierData = tierLimiters[tier];

    // Lazily create the limiter instance
    if (!tierData.limiter) {
      if (redisClient) {
        tierData.config.store = new RedisStore({
          sendCommand: (...args) => redisClient.sendCommand(args),
          prefix: `ratelimit:${keyPrefix}:${tier}:`,
        });
        logger.debug(`User-based rate limiter ${keyPrefix}:${tier} using Redis store`);
      } else {
        logger.warn(
          `User-based rate limiter ${keyPrefix}:${tier} using memory store (Redis not initialized)`
        );
      }
      tierData.limiter = rateLimit(tierData.config);
    }

    return tierData.limiter(req, res, next);
  };

  // Expose tier limits for testing/inspection
  middleware.getTierLimits = () => {
    return Object.fromEntries(
      Object.entries(USER_TIER_LIMITS).map(([tier, limits]) => [tier, limits[limitType]])
    );
  };

  return middleware;
};

/**
 * Auth login limiter: 5 requests per minute
 * Strict limit to prevent brute force attacks
 */
const authLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: 'Too many login attempts. Please try again after 1 minute.',
  keyPrefix: 'auth-login'
});

/**
 * Registration limiter: 3 requests per minute
 * Very strict to prevent spam account creation
 */
const registerLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 3,
  message: 'Too many registration attempts. Please try again after 1 minute.',
  keyPrefix: 'auth-register'
});

/**
 * Analyze endpoint limiter: 30 requests per minute
 * Balanced limit for firewall analysis API
 */
const analyzeLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: 'Too many analysis requests. Please try again after 1 minute.',
  keyPrefix: 'firewall-analyze'
});

/**
 * Batch analyze endpoint limiter: 10 requests per minute
 * Lower limit than single analysis since each batch request processes multiple texts
 */
const batchAnalyzeLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: 'Too many batch analysis requests. Please try again after 1 minute.',
  keyPrefix: 'firewall-batch-analyze'
});

/**
 * General API limiter: 100 requests per minute
 * Applied to all other endpoints
 */
const generalLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: 'Too many requests. Please try again after 1 minute.',
  keyPrefix: 'general',
});

/**
 * User-based analyze limiter
 * Applies different limits based on user tier:
 * - Admin: 100/min
 * - Viewer: 30/min
 * - Anonymous: 15/min
 */
const userAnalyzeLimiter = createUserBasedLimiter({
  limitType: 'analyze',
  message: 'Too many analysis requests. Please try again after 1 minute.',
  keyPrefix: 'firewall-analyze-user',
});

/**
 * User-based batch analyze limiter
 * Applies different limits based on user tier:
 * - Admin: 30/min
 * - Viewer: 10/min
 * - Anonymous: 5/min
 */
const userBatchAnalyzeLimiter = createUserBasedLimiter({
  limitType: 'batch',
  message: 'Too many batch analysis requests. Please try again after 1 minute.',
  keyPrefix: 'firewall-batch-user',
});

/**
 * User-based general limiter
 * Applies different limits based on user tier:
 * - Admin: 200/min
 * - Viewer: 100/min
 * - Anonymous: 50/min
 */
const userGeneralLimiter = createUserBasedLimiter({
  limitType: 'general',
  message: 'Too many requests. Please try again after 1 minute.',
  keyPrefix: 'general-user',
});

module.exports = {
  initRateLimiter,
  authLimiter,
  registerLimiter,
  analyzeLimiter,
  batchAnalyzeLimiter,
  generalLimiter,
  // User-based rate limiters (tiered by role)
  userAnalyzeLimiter,
  userBatchAnalyzeLimiter,
  userGeneralLimiter,
  // Utilities for testing
  getUserRateLimitKey,
  getUserTier,
  getTierLimits,
  USER_TIER_LIMITS,
};
