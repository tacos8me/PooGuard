/**
 * Admin Audit Logging Middleware
 *
 * Logs all admin actions to an immutable audit log including:
 * - Who performed the action
 * - What action was taken
 * - When it occurred
 * - Before/after values for changes
 *
 * The audit log table has no delete/update API to ensure immutability.
 */

const logger = require('../services/logger');

let db = null;

/**
 * Initialize the audit log middleware with database connection
 */
const initDb = (knex) => {
  db = knex;
};

/**
 * Action types for audit logging
 */
const ACTION_TYPES = {
  // Config changes
  CONFIG_VIEW: 'config.view',
  CONFIG_UPDATE: 'config.update',

  // User management
  USER_CREATE: 'user.create',
  USER_UPDATE: 'user.update',
  USER_DELETE: 'user.delete',
  USER_ROLE_CHANGE: 'user.role_change',

  // Alert management
  ALERT_CREATE: 'alert.create',
  ALERT_UPDATE: 'alert.update',
  ALERT_DELETE: 'alert.delete',
  ALERT_ACKNOWLEDGE: 'alert.acknowledge',

  // Session management
  SESSION_RESET: 'session.reset',
  SESSION_CLEAR: 'session.clear',

  // System actions
  SYSTEM_EXPORT: 'system.export',
  SYSTEM_PURGE: 'system.purge',

  // API key management
  APIKEY_CREATE: 'apikey.create',
  APIKEY_REVOKE: 'apikey.revoke',

  // Auth security events
  AUTH_LOGIN_FAILURE: 'auth.login_failure',
  AUTH_TOKEN_INVALID: 'auth.token_invalid',
  AUTH_RATE_LIMITED: 'auth.rate_limited',
  AUTH_UNAUTHORIZED: 'auth.unauthorized',
};

/**
 * Create an audit log entry
 */
const createAuditLog = async ({
  userId,
  userEmail,
  action,
  resource,
  resourceId,
  oldValue,
  newValue,
  ipAddress,
  userAgent,
  metadata = {},
}) => {
  if (!db) {
    logger.warn('Audit log: Database not initialized');
    return null;
  }

  try {
    const entry = {
      user_id: userId,
      user_email: userEmail,
      action,
      resource,
      resource_id: resourceId ? String(resourceId) : null,
      old_value: oldValue ? JSON.stringify(oldValue) : null,
      new_value: newValue ? JSON.stringify(newValue) : null,
      ip_address: ipAddress,
      user_agent: userAgent ? userAgent.substring(0, 500) : null,
      metadata: Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : null,
    };

    const [log] = await db('audit_logs').insert(entry).returning('*');

    logger.info('Audit log created', {
      id: log.id,
      action,
      resource,
      userId,
      userEmail,
    });

    return log;
  } catch (error) {
    logger.error('Failed to create audit log', {
      error: error.message,
      action,
      resource,
      userId,
    });
    // Don't throw - audit log failure shouldn't break the operation
    return null;
  }
};

/**
 * Middleware factory to automatically log admin actions
 *
 * @param {string} action - The action type (from ACTION_TYPES)
 * @param {string} resource - The resource being acted upon
 * @param {object} options - Additional options
 * @param {function} options.getResourceId - Function to extract resource ID from request
 * @param {function} options.getOldValue - Async function to fetch old value before change
 * @param {function} options.getNewValue - Function to extract new value from request
 * @param {function} options.getMetadata - Function to extract additional metadata
 */
const auditMiddleware = (action, resource, options = {}) => {
  const {
    getResourceId = () => null,
    getOldValue = async () => null,
    getNewValue = () => null,
    getMetadata = () => ({}),
  } = options;

  return async (req, res, next) => {
    // Store original json method to intercept response
    const originalJson = res.json.bind(res);
    let oldValue = null;

    try {
      // Fetch old value before the operation (for update/delete operations)
      if (getOldValue) {
        oldValue = await getOldValue(req);
      }
    } catch (error) {
      logger.warn('Failed to fetch old value for audit', { error: error.message, action });
    }

    // Intercept the response to log after successful completion
    res.json = async function (data) {
      // Only log on successful responses (2xx status)
      if (res.statusCode >= 200 && res.statusCode < 300) {
        try {
          await createAuditLog({
            userId: req.user?.id,
            userEmail: req.user?.email,
            action,
            resource,
            resourceId: getResourceId(req),
            oldValue,
            newValue: getNewValue(req),
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            metadata: getMetadata(req),
          });
        } catch (error) {
          logger.error('Audit middleware error', { error: error.message, action });
        }
      }

      return originalJson(data);
    };

    next();
  };
};

/**
 * Query audit logs with filtering and pagination
 */
const queryAuditLogs = async ({
  userId,
  action,
  resource,
  startDate,
  endDate,
  limit = 50,
  offset = 0,
}) => {
  if (!db) {
    return { logs: [], total: 0 };
  }

  try {
    let query = db('audit_logs');
    let countQuery = db('audit_logs');

    // Apply filters
    if (userId) {
      query = query.where('user_id', userId);
      countQuery = countQuery.where('user_id', userId);
    }
    if (action) {
      query = query.where('action', action);
      countQuery = countQuery.where('action', action);
    }
    if (resource) {
      query = query.where('resource', resource);
      countQuery = countQuery.where('resource', resource);
    }
    if (startDate) {
      query = query.where('created_at', '>=', startDate);
      countQuery = countQuery.where('created_at', '>=', startDate);
    }
    if (endDate) {
      query = query.where('created_at', '<=', endDate);
      countQuery = countQuery.where('created_at', '<=', endDate);
    }

    // Get total count
    const [{ count }] = await countQuery.count('id as count');

    // Get logs with pagination
    const logs = await query
      .orderBy('created_at', 'desc')
      .limit(limit)
      .offset(offset);

    // Parse JSON fields
    const parsedLogs = logs.map((log) => ({
      ...log,
      old_value: log.old_value ? JSON.parse(log.old_value) : null,
      new_value: log.new_value ? JSON.parse(log.new_value) : null,
      metadata: log.metadata ? JSON.parse(log.metadata) : null,
    }));

    return {
      logs: parsedLogs,
      total: parseInt(count, 10),
      limit,
      offset,
    };
  } catch (error) {
    logger.error('Failed to query audit logs', { error: error.message });
    return { logs: [], total: 0 };
  }
};

/**
 * Get audit log by ID
 */
const getAuditLogById = async (id) => {
  if (!db) return null;

  try {
    const log = await db('audit_logs').where('id', id).first();
    if (!log) return null;

    return {
      ...log,
      old_value: log.old_value ? JSON.parse(log.old_value) : null,
      new_value: log.new_value ? JSON.parse(log.new_value) : null,
      metadata: log.metadata ? JSON.parse(log.metadata) : null,
    };
  } catch (error) {
    logger.error('Failed to get audit log', { id, error: error.message });
    return null;
  }
};

module.exports = {
  initDb,
  ACTION_TYPES,
  createAuditLog,
  auditMiddleware,
  queryAuditLogs,
  getAuditLogById,
};
