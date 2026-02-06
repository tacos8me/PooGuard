const express = require('express');
const { body, param, validationResult } = require('express-validator');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const { publishEvent, CHANNELS } = require('../services/redis');
const logger = require('../services/logger');
const alertEvaluator = require('../services/alertEvaluator');

const router = express.Router();
let db = null;

// Valid alert types (including new enhanced types)
const VALID_ALERT_TYPES = [
  'rate',
  'threshold',
  'pattern',
  'session_threat',
  'access_pattern',
  'config_change',
  'repeat_block',
];

const initDb = (knex) => {
  db = knex;
  alertEvaluator.initDb(knex);
};

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.use(authMiddleware);

router.get('/', async (req, res) => {
  try {
    const alerts = await db('alerts')
      .orderBy('created_at', 'desc')
      .select('*');
    res.json({ alerts });
  } catch (error) {
    logger.error('Get alerts error', { error: error.message });
    res.status(500).json({ error: 'Failed to get alerts' });
  }
});

router.post('/',
  requireAdmin,
  body('name').isString().isLength({ min: 1, max: 100 }),
  body('type').isIn(VALID_ALERT_TYPES),
  body('config').isObject(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, type, config } = req.body;

      const [alert] = await db('alerts')
        .insert({ name, type, config, enabled: true })
        .returning('*');

      logger.info('Alert created', { alertId: alert.id, name });
      res.status(201).json({ alert });
    } catch (error) {
      logger.error('Create alert error', { error: error.message });
      res.status(500).json({ error: 'Failed to create alert' });
    }
  }
);

router.put('/:id',
  requireAdmin,
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
  body('name').optional().isString().isLength({ min: 1, max: 100 }).withMessage('Name must be 1-100 characters'),
  body('type').optional().isIn(VALID_ALERT_TYPES).withMessage(`Type must be one of: ${VALID_ALERT_TYPES.join(', ')}`),
  body('config').optional().isObject().withMessage('Config must be an object'),
  body('enabled').optional().isBoolean().withMessage('Enabled must be a boolean'),
  validateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, type, config, enabled } = req.body;

      const [alert] = await db('alerts')
        .where({ id })
        .update({ name, type, config, enabled })
        .returning('*');

      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      logger.info('Alert updated', { alertId: id });
      res.json({ alert });
    } catch (error) {
      logger.error('Update alert error', { error: error.message });
      res.status(500).json({ error: 'Failed to update alert' });
    }
  }
);

router.delete('/:id',
  requireAdmin,
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),
  validateRequest,
  async (req, res) => {
    try {
      const { id } = req.params;
      const deleted = await db('alerts').where({ id }).del();

      if (!deleted) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      logger.info('Alert deleted', { alertId: id });
      res.json({ success: true });
    } catch (error) {
      logger.error('Delete alert error', { error: error.message });
      res.status(500).json({ error: 'Failed to delete alert' });
    }
  }
);

router.get('/triggers', async (req, res) => {
  try {
    const { acknowledged } = req.query;
    let query = db('alert_triggers')
      .join('alerts', 'alert_triggers.alert_id', 'alerts.id')
      .orderBy('triggered_at', 'desc')
      .limit(100);

    if (acknowledged !== undefined) {
      query = query.where('acknowledged', acknowledged === 'true');
    }

    const triggers = await query.select(
      'alert_triggers.*',
      'alerts.name as alert_name',
      'alerts.type as alert_type'
    );

    res.json({ triggers });
  } catch (error) {
    logger.error('Get triggers error', { error: error.message });
    res.status(500).json({ error: 'Failed to get triggers' });
  }
});

router.post('/triggers/:id/acknowledge', async (req, res) => {
  try {
    const { id } = req.params;

    const [trigger] = await db('alert_triggers')
      .where({ id })
      .update({
        acknowledged: true,
        acknowledged_at: new Date()
      })
      .returning('*');

    if (!trigger) {
      return res.status(404).json({ error: 'Trigger not found' });
    }

    logger.info('Alert acknowledged', { triggerId: id, userId: req.user.id });
    res.json({ trigger });
  } catch (error) {
    logger.error('Acknowledge error', { error: error.message });
    res.status(500).json({ error: 'Failed to acknowledge' });
  }
});

/**
 * Alert evaluation function
 * Delegates to the enhanced alertEvaluator service which supports:
 * - threshold: Individual threat score thresholds
 * - rate: Blocked request rate limits
 * - session_threat: Cumulative session threat scores
 * - access_pattern: Unusual access patterns
 * - config_change: Configuration modifications
 * - repeat_block: Repeated blocks from same source
 *
 * @param {Object} event - Firewall event to evaluate
 * @param {Object} options - Additional options (e.g., configChange data)
 */
const evaluateAlerts = async (event, options = {}) => {
  return alertEvaluator.evaluateAlerts(event, options);
};

/**
 * Notify about config changes for config_change alert type
 */
const notifyConfigChange = async (changeData) => {
  return alertEvaluator.notifyConfigChange(changeData);
};

/**
 * Get alert statistics
 */
router.get('/stats', async (req, res) => {
  try {
    const stats = await alertEvaluator.getAlertStats();
    if (!stats) {
      return res.status(500).json({ error: 'Failed to get alert stats' });
    }
    res.json(stats);
  } catch (error) {
    logger.error('Get alert stats error', { error: error.message });
    res.status(500).json({ error: 'Failed to get alert stats' });
  }
});

/**
 * Get valid alert types
 */
router.get('/types', (req, res) => {
  res.json({
    types: VALID_ALERT_TYPES,
    descriptions: {
      rate: 'Alert when blocked request rate exceeds threshold',
      threshold: 'Alert when individual threat score exceeds threshold',
      pattern: 'Alert on specific attack patterns (legacy)',
      session_threat: 'Alert when cumulative session threat score exceeds threshold',
      access_pattern: 'Alert on unusual access patterns compared to baseline',
      config_change: 'Alert when firewall configuration is modified',
      repeat_block: 'Alert when same source is blocked repeatedly',
    },
  });
});

module.exports = {
  router,
  initDb,
  evaluateAlerts,
  notifyConfigChange,
  VALID_ALERT_TYPES,
};
