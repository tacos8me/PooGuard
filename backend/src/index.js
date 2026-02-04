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

const { corsOptions, socketCorsOptions } = require('./config/cors');

const config = require('./config');
const logger = require('./services/logger');
const { getClient, getSubscriber, CHANNELS } = require('./services/redis');

const { router: authRouter, initDb: initAuthDb } = require('./routes/auth');
const { router: firewallRouter, initDb: initFirewallDb } = require('./routes/firewall');
const { router: analyticsRouter, initDb: initAnalyticsDb } = require('./routes/analytics');
const { router: alertsRouter, initDb: initAlertsDb, evaluateAlerts } = require('./routes/alerts');
const { router: usersRouter, initDb: initUsersDb } = require('./routes/users');
const { router: healthRouter, initDb: initHealthDb } = require('./routes/health');
const { initRateLimiter, generalLimiter } = require('./middleware/rateLimiter');
const { csrfProtection, getCsrfTokenHandler } = require('./middleware/csrf');

const app = express();
const server = http.createServer(app);

// Socket.IO setup
const io = new Server(server, {
  cors: socketCorsOptions
});

// Middleware
app.use(helmet());
app.use(cors(corsOptions));
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

// Apply general rate limiter to all API routes (100 req/min)
// Specific routes have their own stricter limits applied at the route level
app.use('/api', generalLimiter);

// CSRF token endpoint - must be before CSRF protection middleware
app.get('/api/csrf-token', getCsrfTokenHandler);

// Apply CSRF protection to all API routes
// This validates CSRF token for POST/PUT/DELETE requests
app.use('/api', csrfProtection);

// Routes
app.use('/api/auth', authRouter);
app.use('/api/firewall', firewallRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/alerts', alertsRouter);
app.use('/api/users', usersRouter);

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
      logger.info(`ClawGuard API running on port ${config.port}`);
    });
  } catch (error) {
    logger.error('Failed to start server', { error: error.message });
    process.exit(1);
  }
};

startServer();
