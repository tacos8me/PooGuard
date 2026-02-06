const logger = require('../services/logger');

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000', 'http://localhost:5173'];

// Private/local network hostname pattern (development only)
// Matches: localhost, 127.0.0.1, ::1, 0.0.0.0, 192.168.x.x, 10.x.x.x, 172.16-31.x.x
const PRIVATE_NETWORK_RE = /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0$|localhost$|\[?::1\]?$)/;

// Only allow LAN/private network origins when explicitly in development
let corsOriginCheck;
if (process.env.NODE_ENV === 'development') {
  corsOriginCheck = (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    try {
      const { hostname } = new URL(origin);
      if (PRIVATE_NETWORK_RE.test(hostname)) {
        return callback(null, true);
      }
    } catch {}
    logger.warn('CORS rejected origin', { origin });
    callback(null, false);
  };
} else {
  // Strict allowlist only (production default)
  corsOriginCheck = (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    logger.warn('CORS rejected origin', { origin });
    callback(null, false);
  };
}

const corsOptions = {
  origin: corsOriginCheck,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  exposedHeaders: ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset']
};

const socketCorsOptions = {
  origin: corsOriginCheck,
  credentials: true,
  methods: ['GET', 'POST']
};

// Permissive CORS for /v1 proxy routes — external chat clients (SillyTavern,
// Open WebUI, Chatbox, Tauri apps, etc.) connect from arbitrary origins.
// API key authentication is the security barrier, not CORS.
const proxyCorsOptions = {
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

module.exports = {
  corsOptions,
  socketCorsOptions,
  proxyCorsOptions,
  allowedOrigins
};
