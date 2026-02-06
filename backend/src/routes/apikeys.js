const express = require('express');
const crypto = require('crypto');
const { body, param, query, validationResult } = require('express-validator');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const { createAuditLog, ACTION_TYPES } = require('../middleware/auditLog');
const logger = require('../services/logger');

const router = express.Router();

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

// All routes require admin auth
router.use(authMiddleware, requireAdmin);

/**
 * GET / — List API keys (paginated)
 * Never returns key_hash or full key.
 */
router.get('/',
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  validateRequest,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 20;
      const offset = (page - 1) * limit;

      const baseQuery = db('api_keys')
        .whereNull('revoked_at');

      const [{ count }] = await baseQuery.clone().count('* as count');
      const total = parseInt(count, 10);
      const totalPages = Math.ceil(total / limit);

      const keys = await baseQuery
        .clone()
        .join('users', 'api_keys.user_id', 'users.id')
        .select(
          'api_keys.id',
          'api_keys.name',
          'api_keys.key_prefix as prefix',
          'api_keys.last_used_at as lastUsedAt',
          'api_keys.expires_at as expiresAt',
          'api_keys.created_at as createdAt',
          'users.email as createdBy'
        )
        .orderBy('api_keys.created_at', 'desc')
        .limit(limit)
        .offset(offset);

      res.json({
        keys,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
        },
      });
    } catch (error) {
      logger.error('List API keys error', { error: error.message });
      res.status(500).json({ error: 'Failed to list API keys' });
    }
  }
);

/**
 * POST / — Create a new API key
 * Returns the full key ONCE in the response. It is never stored or retrievable again.
 */
router.post('/',
  body('name').isString().trim().isLength({ min: 1, max: 255 }).withMessage('Key name is required (1-255 chars)'),
  validateRequest,
  async (req, res) => {
    try {
      const { name } = req.body;

      // Generate key: sk-pg- + 32 random hex chars
      const rawKey = 'sk-pg-' + crypto.randomBytes(32).toString('hex');
      const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
      const keyPrefix = rawKey.substring(0, 10);

      const [created] = await db('api_keys')
        .insert({
          user_id: req.user.id,
          key_prefix: keyPrefix,
          key_hash: keyHash,
          name,
        })
        .returning(['id', 'name', 'key_prefix', 'created_at']);

      createAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: ACTION_TYPES.APIKEY_CREATE,
        resource: 'api_key',
        resourceId: created.id,
        newValue: { name, prefix: keyPrefix },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      }).catch(() => {});

      logger.info('API key created', { keyId: created.id, name, userId: req.user.id });

      res.status(201).json({
        key: {
          id: created.id,
          name: created.name,
          prefix: created.key_prefix,
          createdAt: created.created_at,
        },
        secret: rawKey,
      });
    } catch (error) {
      logger.error('Create API key error', { error: error.message });
      res.status(500).json({ error: 'Failed to create API key' });
    }
  }
);

/**
 * DELETE /:id — Revoke an API key (soft delete)
 * Sets revoked_at timestamp; key is never hard-deleted for audit trail.
 */
router.delete('/:id',
  param('id').isUUID().withMessage('Valid key ID required'),
  validateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;

      const existing = await db('api_keys')
        .where({ id })
        .whereNull('revoked_at')
        .first();

      if (!existing) {
        return res.status(404).json({ error: 'API key not found' });
      }

      await db('api_keys')
        .where({ id })
        .update({ revoked_at: new Date() });

      createAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: ACTION_TYPES.APIKEY_REVOKE,
        resource: 'api_key',
        resourceId: id,
        oldValue: { name: existing.name, prefix: existing.key_prefix },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      }).catch(() => {});

      logger.info('API key revoked', { keyId: id, userId: req.user.id });

      res.json({ success: true });
    } catch (error) {
      logger.error('Revoke API key error', { error: error.message });
      res.status(500).json({ error: 'Failed to revoke API key' });
    }
  }
);

module.exports = { router, initDb };
