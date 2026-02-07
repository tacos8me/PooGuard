const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

// Validate configuration before loading anything else
const { validateConfig } = require('./config/validate');
validateConfig();

const { corsOptions, socketCorsOptions, proxyCorsOptions } = require('./config/cors');

const config = require('./config');
const logger = require('./services/logger');
const { getClient, getSubscriber, closeAll: closeRedis, CHANNELS } = require('./services/redis');

const { router: authRouter, initDb: initAuthDb } = require('./routes/auth');
const { router: firewallRouter, initDb: initFirewallDb } = require('./routes/firewall');
const { router: analyticsRouter, initDb: initAnalyticsDb } = require('./routes/analytics');
const { router: alertsRouter, initDb: initAlertsDb, evaluateAlerts } = require('./routes/alerts');
const { router: usersRouter, initDb: initUsersDb } = require('./routes/users');
const { router: healthRouter, initDb: initHealthDb } = require('./routes/health');
const { router: proxyRouter, initDb: initProxyDb } = require('./routes/proxy');
const { router: apikeysRouter, initDb: initApikeysDb } = require('./routes/apikeys');
const { initRateLimiter, generalLimiter } = require('./middleware/rateLimiter');
const { csrfProtection, getCsrfTokenHandler } = require('./middleware/csrf');
const egressMonitor = require('./middleware/egressMonitor');
const { initDb: initAuditLogDb } = require('./middleware/auditLog');
const dataRetention = require('./services/dataRetention');
const analysisQueue = require('./services/analysisQueue');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

// Socket.IO setup
const io = new Server(server, {
  cors: socketCorsOptions
});

// Middleware
app.use(helmet({
  frameguard: { action: 'deny' },
}));
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// CORS: /v1 proxy allows any origin (external chat clients), everything else uses strict config
const _proxyCors = cors(proxyCorsOptions);
const _standardCors = cors(corsOptions);
app.use((req, res, next) => {
  if (req.path.startsWith('/v1')) return _proxyCors(req, res, next);
  _standardCors(req, res, next);
});

app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.debug(`${req.method} ${req.path}`, {
      status: res.statusCode,
      duration: Date.now() - start
    });
  });
  next();
});

// Health check routes (no rate limiting)
app.use('/', healthRouter);

// OAI-compatible proxy — mounted before CSRF (external clients won't have CSRF tokens)
app.use('/v1', proxyRouter);

// Apply general rate limiter to all API routes (100 req/min)
// Specific routes have their own stricter limits applied at the route level
app.use('/api', generalLimiter);

// CSRF token endpoint - must be before CSRF protection middleware
app.get('/api/csrf-token', getCsrfTokenHandler);

// Apply CSRF protection to all API routes
// This validates CSRF token for POST/PUT/DELETE requests
app.use('/api', csrfProtection);

// Egress monitoring - monitors API responses for sensitive data
app.use(egressMonitor());

// Routes
app.use('/api/auth', authRouter);
app.use('/api/firewall', firewallRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/users', usersRouter);
app.use('/api/apikeys', apikeysRouter);

// Error handler
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// Socket.IO authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication required'));
  }

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    socket.user = decoded;
    next();
  } catch (_err) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  logger.info('Client connected', { userId: socket.user.id });

  socket.on('disconnect', () => {
    logger.info('Client disconnected', { userId: socket.user.id });
  });
});

// Initialize database and start server
const startServer = async () => {
  try {
    // Initialize rate limiter with Redis for distributed limiting
    await initRateLimiter();
    logger.info('Rate limiter initialized with Redis store');

    // Initialize database connection
    const knex = require('./models');

    // Initialize routes with db
    initAuthDb(knex);
    initFirewallDb(knex);
    initAnalyticsDb(knex);
    initAlertsDb(knex);
    initUsersDb(knex);
    initApikeysDb(knex);
    initProxyDb(knex);

    // Initialize egress monitor with db
    egressMonitor.initDb(knex);

    // Initialize audit log with db
    initAuditLogDb(knex);

    // Initialize data retention scheduler
    dataRetention.initDb(knex);
    dataRetention.startScheduler();

    // Start async analysis queue worker
    analysisQueue.startWorker(knex);

    // Initialize health check with db and redis
    const redisClient = await getClient();
    initHealthDb(knex, redisClient);

    // Subscribe to Redis events
    const subscriber = await getSubscriber();

    await subscriber.subscribe(CHANNELS.FIREWALL_EVENTS, (message) => {
      const event = JSON.parse(message);
      io.emit('firewall:event', event);
      evaluateAlerts(event);
    });

    await subscriber.subscribe(CHANNELS.ALERTS, (message) => {
      const alert = JSON.parse(message);
      io.emit('alert:triggered', alert);
    });

    logger.info('Redis subscriptions active');

    // Start server
    server.listen(config.port, () => {
      logger.info(`PooGuard API running on port ${config.port}`);
    });
  } catch (error) {
    logger.error('Failed to start server', { error: error.message });
    process.exit(1);
  }
};

// --- Graceful Shutdown ---
let shuttingDown = false;

const gracefulShutdown = async (signal) => {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info(`Received ${signal}, starting graceful shutdown`);

  // Stop data retention scheduler
  dataRetention.stopScheduler();

  // Stop analysis queue worker
  analysisQueue.stopWorker();

  // Stop accepting new connections
  server.close(() => {
    logger.info('HTTP server closed');
  });

  // Disconnect all WebSocket clients with a warning
  for (const socket of io.sockets.sockets.values()) {
    socket.emit('server:shutdown', { message: 'Server is shutting down' });
    socket.disconnect(true);
  }

  // Wait for in-flight requests to drain (up to 5s)
  await new Promise((resolve) => setTimeout(resolve, 5000));

  // Close Redis connections
  try {
    await closeRedis();
    logger.info('Redis connections closed');
  } catch (err) {
    logger.error('Error closing Redis', { error: err.message });
  }

  // Close database pool
  try {
    const knex = require('./models');
    await knex.destroy();
    logger.info('Database pool closed');
  } catch (err) {
    logger.error('Error closing database', { error: err.message });
  }

  logger.info('Graceful shutdown complete');
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();
