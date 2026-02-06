const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const logger = require('../services/logger');

let db = null;

const initDb = (knex) => {
  db = knex;
};

/**
 * Dual-path auth middleware for /v1 proxy routes.
 * Tries JWT verification first (dashboard users), then falls back to API key lookup
 * (external chat clients like Open WebUI, SillyTavern, etc.).
 */
const proxyAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: { message: 'No API key provided', type: 'authentication_error', code: 'missing_api_key' }
    });
  }

  const token = authHeader.substring(7);

  // Path 1: Try JWT verification
  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded;
    return next();
  } catch (_jwtErr) {
    // Not a valid JWT — try API key path
  }

  // Path 2: API key lookup
  if (!db) {
    logger.error('proxyAuth: database not initialized');
    return res.status(500).json({
      error: { message: 'Internal server error', type: 'server_error', code: 'db_not_ready' }
    });
  }

  try {
    const keyHash = crypto.createHash('sha256').update(token).digest('hex');

    const keyRow = await db('api_keys')
      .join('users', 'api_keys.user_id', 'users.id')
      .where('api_keys.key_hash', keyHash)
      .whereNull('api_keys.revoked_at')
      .where(function() {
        this.whereNull('api_keys.expires_at')
          .orWhere('api_keys.expires_at', '>', new Date());
      })
      .select(
        'users.id as user_id',
        'users.email as user_email',
        'users.role as user_role',
        'api_keys.id as api_key_id'
      )
      .first();

    if (!keyRow) {
      return res.status(401).json({
        error: { message: 'Invalid API key', type: 'authentication_error', code: 'invalid_api_key' }
      });
    }

    req.user = { id: keyRow.user_id, email: keyRow.user_email, role: keyRow.user_role };
    req.apiKeyAuth = true;
    req.apiKeyId = keyRow.api_key_id;

    // Async update last_used_at — don't block the request
    db('api_keys')
      .where('id', keyRow.api_key_id)
      .update({ last_used_at: new Date() })
      .catch((err) => logger.warn('Failed to update API key last_used_at', { error: err.message }));

    return next();
  } catch (err) {
    logger.error('proxyAuth: API key lookup failed', { error: err.message });
    return res.status(500).json({
      error: { message: 'Internal server error', type: 'server_error', code: 'auth_lookup_failed' }
    });
  }
};

module.exports = { proxyAuth, initDb };
