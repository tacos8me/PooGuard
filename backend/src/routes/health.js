const express = require('express');
const router = express.Router();
const { getCircuitState } = require('../services/modelService');
const { getCacheStats } = require('../services/redis');
const { authMiddleware } = require('../middleware/auth');

let db = null;
let redis = null;

const initDb = (knex, redisClient) => {
  db = knex;
  redis = redisClient;
};

// Public health endpoint - minimal info only
router.get('/health', async (req, res) => {
  let dbHealthy = false;
  let redisHealthy = false;

  try {
    await db.raw('SELECT 1');
    dbHealthy = true;
  } catch (_err) {
    // unhealthy
  }

  try {
    await redis.ping();
    redisHealthy = true;
  } catch (_err) {
    // unhealthy
  }

  const healthy = dbHealthy && redisHealthy;
  const statusCode = healthy ? 200 : 503;
  res.status(statusCode).json({ status: healthy ? 'ok' : 'unhealthy' });
});

// Detailed health - requires authentication
router.get('/health/detail', authMiddleware, async (req, res) => {
  const checks = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: { status: 'unknown' },
    redis: { status: 'unknown' },
    modelService: { circuitBreaker: getCircuitState() },
    cache: getCacheStats()
  };

  try {
    await db.raw('SELECT 1');
    checks.database.status = 'healthy';
  } catch (err) {
    checks.database.status = 'unhealthy';
    checks.database.error = err.message;
    checks.status = 'unhealthy';
  }

  try {
    await redis.ping();
    checks.redis.status = 'healthy';
  } catch (err) {
    checks.redis.status = 'unhealthy';
    checks.redis.error = err.message;
    checks.status = 'unhealthy';
  }

  const statusCode = checks.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(checks);
});

router.get('/ready', async (req, res) => {
  const circuitState = getCircuitState();
  const checks = {
    ready: true,
    timestamp: new Date().toISOString(),
    database: false,
    redis: false,
    modelServiceCircuit: circuitState
  };

  // If the circuit breaker is open, the service is not ready
  if (circuitState === 'open') {
    checks.ready = false;
  }

  try {
    await db.raw('SELECT 1');
    checks.database = true;
  } catch (_err) {
    checks.ready = false;
  }

  try {
    await redis.ping();
    checks.redis = true;
  } catch (_err) {
    checks.ready = false;
  }

  const statusCode = checks.ready ? 200 : 503;
  res.status(statusCode).json(checks);
});

router.get('/live', (req, res) => {
  // Liveness probe - returns 200 if process is running
  res.json({ status: 'alive' });
});

module.exports = { router, initDb };
