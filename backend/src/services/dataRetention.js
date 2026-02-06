/**
 * Data Retention Service
 *
 * Periodically cleans up old request_logs and egress_logs based on the
 * configured retention period. Audit logs are kept permanently for
 * compliance requirements.
 */

const logger = require('./logger');

let db = null;
let intervalHandle = null;

// Default: run cleanup every 24 hours
const CLEANUP_INTERVAL_MS = parseInt(
  process.env.DATA_RETENTION_INTERVAL_MS || String(24 * 60 * 60 * 1000),
  10
);

/**
 * Initialize the data retention service with the database connection.
 */
const initDb = (knex) => {
  db = knex;
};

/**
 * Read the current retention period from firewall_config.
 * Returns 0 if retention is disabled (keep forever).
 */
const getRetentionDays = async () => {
  if (!db) return 0;
  try {
    const row = await db('firewall_config').select('data_retention_days').first();
    return row?.data_retention_days ?? 90;
  } catch (error) {
    logger.error('Failed to read data retention config', { error: error.message });
    return 0; // fail-safe: don't delete anything if we can't read config
  }
};

/**
 * Run the cleanup job: delete request_logs and egress_logs older than
 * the configured retention period. Audit logs are never deleted.
 *
 * Returns an object with counts of deleted rows.
 */
const runCleanup = async () => {
  if (!db) {
    logger.warn('Data retention: database not initialized, skipping cleanup');
    return { requestLogs: 0, egressLogs: 0 };
  }

  const retentionDays = await getRetentionDays();
  if (retentionDays <= 0) {
    logger.debug('Data retention disabled (retention_days=0), skipping cleanup');
    return { requestLogs: 0, egressLogs: 0 };
  }

  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

  let requestLogsDeleted = 0;
  let egressLogsDeleted = 0;

  try {
    requestLogsDeleted = await db('request_logs')
      .where('timestamp', '<', cutoffDate)
      .del();
  } catch (error) {
    logger.error('Data retention: failed to clean request_logs', { error: error.message });
  }

  try {
    egressLogsDeleted = await db('egress_logs')
      .where('timestamp', '<', cutoffDate)
      .del();
  } catch (error) {
    logger.error('Data retention: failed to clean egress_logs', { error: error.message });
  }

  logger.info('Data retention cleanup completed', {
    retentionDays,
    cutoffDate: cutoffDate.toISOString(),
    requestLogsDeleted,
    egressLogsDeleted,
  });

  return { requestLogs: requestLogsDeleted, egressLogs: egressLogsDeleted };
};

/**
 * Start the periodic cleanup scheduler.
 */
const startScheduler = () => {
  if (intervalHandle) {
    logger.warn('Data retention scheduler already running');
    return;
  }

  logger.info('Data retention scheduler started', {
    intervalMs: CLEANUP_INTERVAL_MS,
  });

  // Run once at startup (after a short delay to let migrations complete)
  setTimeout(() => {
    runCleanup().catch((err) =>
      logger.error('Data retention initial cleanup error', { error: err.message })
    );
  }, 5000);

  intervalHandle = setInterval(() => {
    runCleanup().catch((err) =>
      logger.error('Data retention scheduled cleanup error', { error: err.message })
    );
  }, CLEANUP_INTERVAL_MS);
};

/**
 * Stop the periodic cleanup scheduler.
 */
const stopScheduler = () => {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
    logger.info('Data retention scheduler stopped');
  }
};

module.exports = {
  initDb,
  getRetentionDays,
  runCleanup,
  startScheduler,
  stopScheduler,
};
