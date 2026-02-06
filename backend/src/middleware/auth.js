const jwt = require('jsonwebtoken');
const config = require('../config');
const { createAuditLog, ACTION_TYPES } = require('./auditLog');

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded;
    next();
  } catch (_err) {
    createAuditLog({
      userId: null,
      userEmail: null,
      action: ACTION_TYPES.AUTH_TOKEN_INVALID,
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { path: req.path, method: req.method },
    }).catch(() => {});
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const optionalAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      req.user = decoded;
    } catch (_err) {
      // Invalid token, but continue without user
    }
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    createAuditLog({
      userId: req.user?.id || null,
      userEmail: req.user?.email || null,
      action: ACTION_TYPES.AUTH_UNAUTHORIZED,
      resource: 'auth',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { path: req.path, method: req.method, requiredRole: 'admin', actualRole: req.user?.role || 'none' },
    }).catch(() => {});
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

module.exports = { authMiddleware, optionalAuth, requireAdmin };
