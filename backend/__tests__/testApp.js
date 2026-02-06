/**
 * Test application factory
 * Creates an Express app instance for testing without starting the full server
 */
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const config = require('../src/config');
const { checkHealth: checkModelHealth, getCircuitState } = require('../src/services/modelService');
const { router: authRouter, initDb: initAuthDb } = require('../src/routes/auth');

// Mock tokenService to avoid Redis dependency in tests
jest.mock('../src/services/tokenService', () => {
  const jwt = require('jsonwebtoken');
  const crypto = require('crypto');
  const config = require('../src/config');

  return {
    generateAccessToken: (user) => {
      return jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        config.jwt.secret,
        { expiresIn: '15m' }
      );
    },
    generateRefreshToken: () => {
      return crypto.randomBytes(64).toString('hex');
    },
    storeRefreshToken: jest.fn().mockResolvedValue(undefined),
    validateRefreshToken: jest.fn().mockResolvedValue(null),
    revokeRefreshToken: jest.fn().mockResolvedValue(true),
    revokeAllUserRefreshTokens: jest.fn().mockResolvedValue(0),
    rotateRefreshToken: jest.fn().mockImplementation(async () => crypto.randomBytes(64).toString('hex')),
  };
});

// Mock rate limiter to avoid Redis dependency in tests
jest.mock('../src/middleware/rateLimiter', () => ({
  authLimiter: (req, res, next) => next(),
  registerLimiter: (req, res, next) => next(),
  analyzeLimiter: (req, res, next) => next(),
  batchLimiter: (req, res, next) => next(),
  generalLimiter: (req, res, next) => next(),
}));

/**
 * Creates a test Express application
 * @param {Object} db - Knex database instance (can be a mock)
 * @returns {Object} Express app instance
 */
const createTestApp = (db) => {
  const app = express();

  // Middleware
  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  // Health check endpoint — mirrors real health.js
  app.get('/health', async (req, res) => {
    const modelHealthy = await checkModelHealth();
    res.json({
      status: 'healthy',
      modelService: modelHealthy ? 'connected' : 'disconnected',
      modelServiceCircuit: getCircuitState(),
      timestamp: new Date().toISOString()
    });
  });

  // Initialize auth routes with database
  if (db) {
    initAuthDb(db);
  }

  // Routes
  app.use('/api/auth', authRouter);

  // Error handler
  app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
};

/**
 * Creates a mock database for testing
 * @returns {Object} Mock Knex instance
 */
const createMockDb = () => {
  const users = [];
  let idCounter = 1;

  const mockDb = jest.fn((tableName) => {
    if (tableName === 'users') {
      return {
        where: jest.fn((condition) => ({
          first: jest.fn().mockImplementation(() => {
            const user = users.find(u => {
              if (condition.email) return u.email === condition.email;
              if (condition.id) return u.id === condition.id;
              return false;
            });
            return Promise.resolve(user);
          }),
          select: jest.fn().mockReturnThis()
        })),
        insert: jest.fn((userData) => ({
          returning: jest.fn((fields) => {
            const newUser = {
              id: idCounter++,
              email: userData.email,
              password_hash: userData.password_hash,
              role: userData.role || 'viewer',
              created_at: new Date().toISOString()
            };
            users.push(newUser);

            // Return only requested fields
            const returnedUser = {};
            fields.forEach(field => {
              returnedUser[field] = newUser[field];
            });
            return Promise.resolve([returnedUser]);
          })
        }))
      };
    }
    return {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
      insert: jest.fn().mockReturnThis(),
      returning: jest.fn().mockResolvedValue([])
    };
  });

  // Add reset method for cleaning up between tests
  mockDb.reset = () => {
    users.length = 0;
    idCounter = 1;
  };

  // Add method to get users for testing
  mockDb.getUsers = () => users;

  return mockDb;
};

module.exports = { createTestApp, createMockDb };
