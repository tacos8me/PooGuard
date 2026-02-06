const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const logger = require('../services/logger');
const { authLimiter, registerLimiter } = require('../middleware/rateLimiter');
const tokenService = require('../services/tokenService');
const { createAuditLog, ACTION_TYPES } = require('../middleware/auditLog');

const router = express.Router();

// Will be initialized with db after migrations are ready
let db = null;

const initDb = (knex) => {
  db = knex;
};

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.post('/register',
  registerLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  validateRequest,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const existing = await db('users').where({ email }).first();
      if (existing) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const [user] = await db('users')
        .insert({
          email,
          password_hash: passwordHash,
          role: 'viewer'
        })
        .returning(['id', 'email', 'role', 'created_at']);

      // Generate access and refresh tokens
      const accessToken = tokenService.generateAccessToken(user);
      const refreshToken = tokenService.generateRefreshToken(user);
      await tokenService.storeRefreshToken(user.id, refreshToken);

      logger.info('User registered', { email });

      res.status(201).json({
        user,
        accessToken,
        refreshToken
      });
    } catch (error) {
      logger.error('Registration error', { error: error.message });
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

router.post('/login',
  authLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  validateRequest,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await db('users').where({ email }).first();
      if (!user) {
        createAuditLog({
          userId: null,
          userEmail: email,
          action: ACTION_TYPES.AUTH_LOGIN_FAILURE,
          resource: 'auth',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          metadata: { reason: 'user_not_found' },
        }).catch(() => {});
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        createAuditLog({
          userId: user.id,
          userEmail: email,
          action: ACTION_TYPES.AUTH_LOGIN_FAILURE,
          resource: 'auth',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          metadata: { reason: 'invalid_password' },
        }).catch(() => {});
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate access and refresh tokens
      const accessToken = tokenService.generateAccessToken(user);
      const refreshToken = tokenService.generateRefreshToken(user);
      await tokenService.storeRefreshToken(user.id, refreshToken);

      logger.info('User logged in', { email });

      res.json({
        user: { id: user.id, email: user.email, role: user.role },
        accessToken,
        refreshToken
      });
    } catch (error) {
      logger.error('Login error', { error: error.message });
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

router.get('/me', require('../middleware/auth').authMiddleware, async (req, res) => {
  try {
    const user = await db('users')
      .where({ id: req.user.id })
      .select('id', 'email', 'role', 'created_at')
      .first();

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    logger.error('Get user error', { error: error.message });
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Refresh token endpoint
router.post('/refresh',
  body('refreshToken').notEmpty(),
  validateRequest,
  async (req, res) => {
    try {
      const { refreshToken } = req.body;

      // Validate refresh token exists in Redis
      const tokenData = await tokenService.validateRefreshToken(refreshToken);
      if (!tokenData) {
        return res.status(401).json({ error: 'Invalid or expired refresh token' });
      }

      // Get user from database
      const user = await db('users')
        .where({ id: tokenData.userId })
        .select('id', 'email', 'role')
        .first();

      if (!user) {
        await tokenService.revokeRefreshToken(refreshToken);
        return res.status(401).json({ error: 'User not found' });
      }

      // Generate new access token
      const accessToken = tokenService.generateAccessToken(user);

      // Rotate refresh token for enhanced security
      const newRefreshToken = await tokenService.rotateRefreshToken(refreshToken, user.id);

      logger.info('Token refreshed', { userId: user.id });

      res.json({
        accessToken,
        refreshToken: newRefreshToken
      });
    } catch (error) {
      logger.error('Token refresh error', { error: error.message });
      res.status(500).json({ error: 'Token refresh failed' });
    }
  }
);

// Logout endpoint
router.post('/logout',
  body('refreshToken').notEmpty(),
  validateRequest,
  async (req, res) => {
    try {
      const { refreshToken } = req.body;

      // Revoke the refresh token
      const revoked = await tokenService.revokeRefreshToken(refreshToken);

      if (!revoked) {
        logger.warn('Logout attempted with invalid refresh token');
      }

      logger.info('User logged out');

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      logger.error('Logout error', { error: error.message });
      res.status(500).json({ error: 'Logout failed' });
    }
  }
);

// Logout from all devices (optional)
router.post('/logout-all',
  require('../middleware/auth').authMiddleware,
  async (req, res) => {
    try {
      const deletedCount = await tokenService.revokeAllUserRefreshTokens(req.user.id);

      logger.info('User logged out from all devices', { userId: req.user.id, deletedCount });

      res.json({ message: 'Logged out from all devices', sessionsRevoked: deletedCount });
    } catch (error) {
      logger.error('Logout all error', { error: error.message });
      res.status(500).json({ error: 'Logout from all devices failed' });
    }
  }
);

module.exports = { router, initDb };
