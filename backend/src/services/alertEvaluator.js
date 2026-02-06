/**
 * Enhanced Alert Evaluator Service
 *
 * Evaluates various alert conditions and triggers alerts when thresholds are exceeded.
 * Supports multiple alert types:
 * - threshold: Alert when individual threat scores exceed threshold
 * - rate: Alert when blocked request rate exceeds limit
 * - session_threat: Alert on cumulative session threat scores
 * - access_pattern: Alert on unusual access patterns
 * - config_change: Alert on firewall configuration changes
 * - repeat_block: Alert on repeated blocked attempts from same source
 */

const { getClient, publishEvent, CHANNELS } = require('./redis');
const logger = require('./logger');

// Alert type constants
const ALERT_TYPES = {
  THRESHOLD: 'threshold',
  RATE: 'rate',
  SESSION_THREAT: 'session_threat',
  ACCESS_PATTERN: 'access_pattern',
  CONFIG_CHANGE: 'config_change',
  REPEAT_BLOCK: 'repeat_block',
};

// Configuration defaults
const DEFAULTS = {
  SESSION_THREAT_THRESHOLD: 2.0,
  REPEAT_BLOCK_COUNT: 5,
  REPEAT_BLOCK_WINDOW_MINUTES: 10,
  ACCESS_PATTERN_WINDOW_MINUTES: 60,
  ACCESS_PATTERN_THRESHOLD_MULTIPLIER: 3,
  COOLDOWN_MINUTES: 5, // Prevent alert storms
};

let db = null;
let redis = null;

/**
 * Initialize database and Redis connections
 */
const initDb = async (knex) => {
  db = knex;
  try {
    redis = await getClient();
  } catch (error) {
    logger.warn('Alert evaluator: Redis not available', { error: error.message });
  }
};

/**
 * Check if an alert is in cooldown period
 *
 * @param {number} alertId - Alert ID
 * @returns {boolean} True if in cooldown
 */
const isAlertInCooldown = async (alertId) => {
  if (!redis) return false;

  try {
    const cooldownKey = `alert:cooldown:${alertId}`;
    const exists = await redis.exists(cooldownKey);
    return exists === 1;
  } catch (error) {
    return false;
  }
};

/**
 * Set alert cooldown
 *
 * @param {number} alertId - Alert ID
 * @param {number} minutes - Cooldown duration in minutes
 */
const setAlertCooldown = async (alertId, minutes = DEFAULTS.COOLDOWN_MINUTES) => {
  if (!redis) return;

  try {
    const cooldownKey = `alert:cooldown:${alertId}`;
    await redis.setEx(cooldownKey, minutes * 60, '1');
  } catch (error) {
    logger.warn('Failed to set alert cooldown', { alertId, error: error.message });
  }
};

/**
 * Create an alert trigger record and publish event
 *
 * @param {Object} alert - Alert configuration
 * @param {Object} triggerData - Data that triggered the alert
 */
const triggerAlert = async (alert, triggerData) => {
  // Check cooldown
  const inCooldown = await isAlertInCooldown(alert.id);
  if (inCooldown) {
    logger.debug('Alert in cooldown', { alertId: alert.id, alertName: alert.name });
    return null;
  }

  try {
    const [trigger] = await db('alert_triggers')
      .insert({
        alert_id: alert.id,
        data: triggerData,
      })
      .returning('*');

    await publishEvent(CHANNELS.ALERTS, {
      triggerId: trigger.id,
      alertId: alert.id,
      alertName: alert.name,
      alertType: alert.type,
      data: triggerData,
      triggeredAt: trigger.triggered_at,
    });

    // Set cooldown
    const cooldownMinutes = alert.config?.cooldownMinutes || DEFAULTS.COOLDOWN_MINUTES;
    await setAlertCooldown(alert.id, cooldownMinutes);

    logger.warn('Alert triggered', {
      alertId: alert.id,
      alertName: alert.name,
      alertType: alert.type,
      triggerData,
    });

    return trigger;
  } catch (error) {
    logger.error('Failed to trigger alert', { alertId: alert.id, error: error.message });
    return null;
  }
};

/**
 * Evaluate threshold-based alert
 * Triggers when a specific threat score exceeds threshold
 */
const evaluateThresholdAlert = async (alert, event) => {
  if (event.action !== 'blocked') return false;

  const threatType = alert.config.threatType;
  const threshold = alert.config.threshold;

  if (!threatType || !threshold) return false;

  const score = event.threatScores?.[threatType] || 0;
  if (score >= threshold) {
    await triggerAlert(alert, {
      type: 'threshold_exceeded',
      threatType,
      score,
      threshold,
      requestId: event.id,
    });
    return true;
  }
  return false;
};

/**
 * Evaluate rate-based alert
 * Triggers when blocked request count exceeds threshold in time window
 */
const evaluateRateAlert = async (alert) => {
  const windowMinutes = alert.config.windowMinutes || 5;
  const maxCount = alert.config.maxCount || 10;
  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);

  const { count } = await db('request_logs')
    .where('timestamp', '>=', windowStart)
    .where('action', 'blocked')
    .count('* as count')
    .first();

  const blockedCount = parseInt(count);
  if (blockedCount >= maxCount) {
    await triggerAlert(alert, {
      type: 'rate_exceeded',
      count: blockedCount,
      maxCount,
      windowMinutes,
    });
    return true;
  }
  return false;
};

/**
 * Evaluate session threat alert
 * Triggers when a session's cumulative threat score exceeds threshold
 */
const evaluateSessionThreatAlert = async (alert, event) => {
  if (!event.sessionThreatAlert) return false;

  const threshold = alert.config.threshold || DEFAULTS.SESSION_THREAT_THRESHOLD;
  const sessionInfo = event.sessionThreatAlert;

  if (sessionInfo.cumulativeScore >= threshold) {
    await triggerAlert(alert, {
      type: 'session_threat_exceeded',
      sessionId: sessionInfo.sessionId,
      cumulativeScore: sessionInfo.cumulativeScore,
      threshold,
      alertTriggered: sessionInfo.alertTriggered,
    });
    return true;
  }
  return false;
};

/**
 * Evaluate access pattern alert
 * Triggers when access patterns deviate significantly from baseline
 */
const evaluateAccessPatternAlert = async (alert, event) => {
  const windowMinutes = alert.config.windowMinutes || DEFAULTS.ACCESS_PATTERN_WINDOW_MINUTES;
  const multiplier = alert.config.thresholdMultiplier || DEFAULTS.ACCESS_PATTERN_THRESHOLD_MULTIPLIER;
  const now = Date.now();
  const windowStart = new Date(now - windowMinutes * 60 * 1000);
  const baselineStart = new Date(now - windowMinutes * 2 * 60 * 1000);

  // Get current period stats
  const currentStats = await db('request_logs')
    .where('timestamp', '>=', windowStart)
    .select(
      db.raw('COUNT(*) as total'),
      db.raw("COUNT(*) FILTER (WHERE action = 'blocked') as blocked")
    )
    .first();

  // Get baseline stats (previous period)
  const baselineStats = await db('request_logs')
    .where('timestamp', '>=', baselineStart)
    .where('timestamp', '<', windowStart)
    .select(
      db.raw('COUNT(*) as total'),
      db.raw("COUNT(*) FILTER (WHERE action = 'blocked') as blocked")
    )
    .first();

  const currentBlocked = parseInt(currentStats.blocked) || 0;
  const baselineBlocked = parseInt(baselineStats.blocked) || 1; // Avoid division by zero

  // Check if current blocked rate is significantly higher than baseline
  if (currentBlocked >= baselineBlocked * multiplier && currentBlocked >= 5) {
    await triggerAlert(alert, {
      type: 'access_pattern_anomaly',
      currentBlocked,
      baselineBlocked,
      multiplier,
      windowMinutes,
      percentageIncrease: ((currentBlocked - baselineBlocked) / baselineBlocked * 100).toFixed(1),
    });
    return true;
  }
  return false;
};

/**
 * Evaluate config change alert
 * Triggers when firewall configuration is modified
 *
 * @param {Object} alert - Alert configuration
 * @param {Object} configChange - Config change event data
 */
const evaluateConfigChangeAlert = async (alert, configChange) => {
  if (!configChange || configChange.type !== 'config_update') return false;

  await triggerAlert(alert, {
    type: 'config_changed',
    userId: configChange.userId,
    userEmail: configChange.userEmail,
    resource: configChange.resource,
    oldValue: configChange.oldValue,
    newValue: configChange.newValue,
    changedAt: configChange.timestamp || new Date().toISOString(),
  });
  return true;
};

/**
 * Evaluate repeat block alert
 * Triggers when same source is blocked multiple times in short window
 */
const evaluateRepeatBlockAlert = async (alert, event) => {
  if (event.action !== 'blocked') return false;

  const windowMinutes = alert.config.windowMinutes || DEFAULTS.REPEAT_BLOCK_WINDOW_MINUTES;
  const maxBlocks = alert.config.maxBlocks || DEFAULTS.REPEAT_BLOCK_COUNT;
  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);

  // Check by client IP
  const clientIp = event.clientIp || event.ip;
  if (!clientIp) return false;

  const { count } = await db('request_logs')
    .where('timestamp', '>=', windowStart)
    .where('action', 'blocked')
    .where('client_ip', clientIp)
    .count('* as count')
    .first();

  const blockedCount = parseInt(count);
  if (blockedCount >= maxBlocks) {
    await triggerAlert(alert, {
      type: 'repeat_block_detected',
      clientIp,
      blockedCount,
      maxBlocks,
      windowMinutes,
    });
    return true;
  }
  return false;
};

/**
 * Main alert evaluation function
 * Evaluates all enabled alerts against an event
 *
 * @param {Object} event - Firewall event to evaluate
 * @param {Object} options - Additional options
 * @param {Object} options.configChange - Config change data (for config_change alerts)
 * @returns {Array} List of triggered alerts
 */
const evaluateAlerts = async (event, options = {}) => {
  if (!db) {
    logger.warn('Alert evaluator: Database not initialized');
    return [];
  }

  const triggeredAlerts = [];

  try {
    const alerts = await db('alerts').where({ enabled: true });

    for (const alert of alerts) {
      let triggered = false;

      switch (alert.type) {
        case ALERT_TYPES.THRESHOLD:
          triggered = await evaluateThresholdAlert(alert, event);
          break;

        case ALERT_TYPES.RATE:
          triggered = await evaluateRateAlert(alert);
          break;

        case ALERT_TYPES.SESSION_THREAT:
          triggered = await evaluateSessionThreatAlert(alert, event);
          break;

        case ALERT_TYPES.ACCESS_PATTERN:
          triggered = await evaluateAccessPatternAlert(alert, event);
          break;

        case ALERT_TYPES.CONFIG_CHANGE:
          if (options.configChange) {
            triggered = await evaluateConfigChangeAlert(alert, options.configChange);
          }
          break;

        case ALERT_TYPES.REPEAT_BLOCK:
          triggered = await evaluateRepeatBlockAlert(alert, event);
          break;

        default:
          logger.debug('Unknown alert type', { alertType: alert.type });
      }

      if (triggered) {
        triggeredAlerts.push({
          alertId: alert.id,
          alertName: alert.name,
          alertType: alert.type,
        });
      }
    }
  } catch (error) {
    logger.error('Alert evaluation error', { error: error.message });
  }

  return triggeredAlerts;
};

/**
 * Notify about config changes (called from firewall routes)
 *
 * @param {Object} changeData - Config change data
 */
const notifyConfigChange = async (changeData) => {
  await evaluateAlerts({}, { configChange: { ...changeData, type: 'config_update' } });
};

/**
 * Get alert statistics
 */
const getAlertStats = async () => {
  if (!db) return null;

  try {
    const now = new Date();
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);

    const [totalAlerts, enabledAlerts, dayStats] = await Promise.all([
      db('alerts').count('* as count').first(),
      db('alerts').where({ enabled: true }).count('* as count').first(),
      db('alert_triggers')
        .where('triggered_at', '>=', oneDayAgo)
        .select(
          db.raw('COUNT(*) as total'),
          db.raw("COUNT(*) FILTER (WHERE acknowledged = true) as acknowledged")
        )
        .first(),
    ]);

    return {
      totalAlerts: parseInt(totalAlerts.count),
      enabledAlerts: parseInt(enabledAlerts.count),
      triggersLast24h: parseInt(dayStats.total) || 0,
      acknowledgedLast24h: parseInt(dayStats.acknowledged) || 0,
    };
  } catch (error) {
    logger.error('Get alert stats error', { error: error.message });
    return null;
  }
};

module.exports = {
  initDb,
  evaluateAlerts,
  notifyConfigChange,
  getAlertStats,
  triggerAlert,
  ALERT_TYPES,
  DEFAULTS,
  // Export individual evaluators for testing
  evaluateThresholdAlert,
  evaluateRateAlert,
  evaluateSessionThreatAlert,
  evaluateAccessPatternAlert,
  evaluateConfigChangeAlert,
  evaluateRepeatBlockAlert,
  isAlertInCooldown,
  setAlertCooldown,
};
