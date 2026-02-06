const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const logger = require('../services/logger');
const { createAuditLog, ACTION_TYPES } = require('../middleware/auditLog');
const { getClient } = require('../services/redis');

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

// All routes require authentication and admin access
router.use(authMiddleware);
router.use(requireAdmin);

// GET /api/users - List users with pagination and search
router.get('/',
  query('page').optional().isInt({ min: 1 }).toInt().withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt().withMessage('Limit must be between 1 and 100'),
  query('search').optional().isString().trim().escape().withMessage('Search must be a string'),
  validateRequest,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 20;
      const search = req.query.search;
      const offset = (page - 1) * limit;

      let baseQuery = db('users');

      // Apply search filter if provided
      if (search) {
        baseQuery = baseQuery.where('email', 'ilike', `%${search}%`);
      }

      // Get total count for pagination
      const [{ count }] = await baseQuery.clone().count('* as count');
      const total = parseInt(count, 10);

      // Get paginated users (excluding password_hash)
      const users = await baseQuery
        .clone()
        .select('id', 'email', 'role', 'created_at', 'updated_at')
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset);

      const totalPages = Math.ceil(total / limit);

      logger.debug('Users listed', { page, limit, total, userId: req.user.id });

      res.json({
        users,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      });
    } catch (error) {
      logger.error('List users error', { error: error.message });
      res.status(500).json({ error: 'Failed to list users' });
    }
  }
);

// GET /api/users/:id - Get user by ID
router.get('/:id',
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
  validateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;

      const user = await db('users')
        .where({ id })
        .select('id', 'email', 'role', 'created_at', 'updated_at')
        .first();

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      logger.debug('User retrieved', { targetUserId: id, userId: req.user.id });

      res.json({ user });
    } catch (error) {
      logger.error('Get user error', { error: error.message });
      res.status(500).json({ error: 'Failed to get user' });
    }
  }
);

// PUT /api/users/:id/role - Update user role
router.put('/:id/role',
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
  body('role').isIn(['admin', 'analyst', 'viewer']).withMessage('Role must be admin, analyst, or viewer'),
  validateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;
      const targetUserId = parseInt(id, 10);

      // Prevent self-demotion
      if (targetUserId === req.user.id) {
        return res.status(400).json({ error: 'Cannot change your own role' });
      }

      // Check if user exists
      const existingUser = await db('users').where({ id: targetUserId }).first();
      if (!existingUser) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Update the user's role
      const [updatedUser] = await db('users')
        .where({ id: targetUserId })
        .update({
          role,
          updated_at: new Date()
        })
        .returning(['id', 'email', 'role', 'created_at', 'updated_at']);

      logger.info('User role updated', {
        targetUserId,
        oldRole: existingUser.role,
        newRole: role,
        updatedBy: req.user.id
      });

      res.json({ user: updatedUser });
    } catch (error) {
      logger.error('Update user role error', { error: error.message });
      res.status(500).json({ error: 'Failed to update user role' });
    }
  }
);

// DELETE /api/users/:id - Delete user (soft delete)
router.delete('/:id',
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
  validateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;
      const targetUserId = parseInt(id, 10);

      // Prevent self-deletion
      if (targetUserId === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
      }

      // Check if user exists
      const existingUser = await db('users')
        .where({ id: targetUserId })
        .first();

      if (!existingUser) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Hard delete the user
      // Note: In production, you may want to implement soft delete
      // by adding a 'deleted_at' column and filtering in queries
      await db('users').where({ id: targetUserId }).del();

      logger.info('User deleted', {
        targetUserId,
        targetEmail: existingUser.email,
        deletedBy: req.user.id
      });

      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      logger.error('Delete user error', { error: error.message });
      res.status(500).json({ error: 'Failed to delete user' });
    }
  }
);

// DELETE /api/users/:id/data - GDPR Right to Erasure
// Deletes all personal data for a user while preserving anonymized audit trail
router.delete('/:id/data',
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
  body('confirm').equals('true').withMessage('Must pass confirm: true to proceed'),
  validateRequest,
  async (req, res) => {
    try {
      const targetUserId = parseInt(req.params.id, 10);

      // Check if user exists
      const targetUser = await db('users')
        .where({ id: targetUserId })
        .select('id', 'email')
        .first();

      if (!targetUser) {
        return res.status(404).json({ error: 'User not found' });
      }

      const counts = {
        requestLogs: 0,
        egressLogs: 0,
        auditLogs: 0,
        sessionKeys: 0,
      };

      // Delete request_logs for this user
      counts.requestLogs = await db('request_logs')
        .where({ user_id: targetUserId })
        .del();

      // Delete egress_logs for this user
      counts.egressLogs = await db('egress_logs')
        .where({ user_id: targetUserId })
        .del();

      // Anonymize audit_logs — replace email but keep the log entries for compliance
      counts.auditLogs = await db('audit_logs')
        .where({ user_id: targetUserId })
        .update({
          user_email: `deleted-user-${targetUserId}`,
        });

      // Clear session tracking data from Redis
      try {
        const redis = await getClient();
        const sessionKey = `session:threat:user:${targetUserId}`;
        const historyKey = `session:history:user:${targetUserId}`;
        const deleted = await redis.del([sessionKey, historyKey]);
        counts.sessionKeys = deleted;
      } catch (redisError) {
        logger.warn('GDPR erasure: failed to clear Redis session data', {
          error: redisError.message,
          targetUserId,
        });
      }

      // Log the erasure action in audit_logs
      await createAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: ACTION_TYPES.SYSTEM_PURGE,
        resource: 'user_data',
        resourceId: String(targetUserId),
        oldValue: { email: targetUser.email },
        newValue: { erasedRecords: counts },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      logger.info('GDPR erasure completed', {
        targetUserId,
        performedBy: req.user.id,
        counts,
      });

      res.json({
        success: true,
        message: 'User data erased successfully',
        counts,
      });
    } catch (error) {
      logger.error('GDPR erasure error', { error: error.message });
      res.status(500).json({ error: 'Failed to erase user data' });
    }
  }
);

module.exports = { router, initDb };
