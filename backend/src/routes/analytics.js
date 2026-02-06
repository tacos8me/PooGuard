const express = require('express');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const logger = require('../services/logger');
const secretMasker = require('../utils/secretMasker');
const sessionTracker = require('../services/sessionTracker');
const { queryAuditLogs, getAuditLogById, initDb: initAuditDb } = require('../middleware/auditLog');

const router = express.Router();
let db = null;

// Whitelist of allowed intervals and their corresponding date formats
const ALLOWED_INTERVALS = {
  'hour': 'YYYY-MM-DD HH24:00',
  'day': 'YYYY-MM-DD'
};

// Whitelist of allowed period values
const ALLOWED_PERIODS = ['1h', '24h', '7d', '30d'];

const initDb = (knex) => {
  db = knex;
  initAuditDb(knex);
};

router.use(authMiddleware);

router.get('/summary', async (req, res) => {
  try {
    const now = new Date();
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);
    const oneHourAgo = new Date(now - 60 * 60 * 1000);

    const [dayStats, hourStats, recentEvents] = await Promise.all([
      db('request_logs')
        .where('timestamp', '>=', oneDayAgo)
        .select(
          db.raw('COUNT(*) as total'),
          db.raw("COUNT(*) FILTER (WHERE action = 'blocked') as blocked"),
          db.raw("COUNT(*) FILTER (WHERE action = 'flagged') as flagged"),
          db.raw('AVG(latency_ms) as avg_latency')
        )
        .first(),
      db('request_logs')
        .where('timestamp', '>=', oneHourAgo)
        .select(db.raw('COUNT(*) as total'))
        .first(),
      db('request_logs')
        .orderBy('timestamp', 'desc')
        .limit(20)
        .select('id', 'timestamp', 'input_text', 'threat_scores', 'action', 'latency_ms')
    ]);

    const total24h = parseInt(dayStats.total) || 0;
    const blocked24h = parseInt(dayStats.blocked) || 0;
    const flagged24h = parseInt(dayStats.flagged) || 0;
    const activeThreats = blocked24h + flagged24h;
    const blockRate = total24h > 0
      ? parseFloat(((blocked24h / total24h) * 100).toFixed(1))
      : 0;
    const avgLatencyMs = Math.round(dayStats.avg_latency) || 0;
    const hourTotal = parseInt(hourStats.total) || 0;
    const requestsPerMinute = parseFloat((hourTotal / 60).toFixed(2));

    // Compute threat level based on block rate and active threats
    let threatLevel = 'low';
    if (blockRate > 50 || activeThreats > 100) threatLevel = 'critical';
    else if (blockRate > 30 || activeThreats > 50) threatLevel = 'high';
    else if (blockRate > 10 || activeThreats > 10) threatLevel = 'medium';

    // Mask secrets in recent events
    const maskedRecentEvents = recentEvents.map(evt => ({
      ...evt,
      input_text: secretMasker.mask(evt.input_text || '').masked
    }));

    res.json({
      last24Hours: {
        total: total24h,
        blocked: blocked24h,
        flagged: flagged24h,
        avgLatencyMs,
        blockRate
      },
      lastHour: {
        total: hourTotal,
        requestsPerMinute
      },
      recentBlocks: maskedRecentEvents.filter(e => e.action === 'blocked').slice(0, 5),
      // Flat fields for dashboard consumption
      requests_per_minute: requestsPerMinute,
      block_rate: blockRate,
      active_threats_today: activeThreats,
      avg_latency_ms: avgLatencyMs,
      threat_level: threatLevel,
      recent_events: maskedRecentEvents
    });
  } catch (error) {
    logger.error('Summary error', { error: error.message });
    res.status(500).json({ error: 'Failed to get summary' });
  }
});

router.get('/timeline', async (req, res) => {
  try {
    const { period = '24h', interval = 'hour' } = req.query;

    // Validate period parameter against whitelist
    if (!ALLOWED_PERIODS.includes(period)) {
      return res.status(400).json({
        error: 'Invalid period parameter',
        allowed: ALLOWED_PERIODS
      });
    }

    // Validate interval parameter against whitelist
    if (!Object.hasOwn(ALLOWED_INTERVALS, interval)) {
      return res.status(400).json({
        error: 'Invalid interval parameter',
        allowed: Object.keys(ALLOWED_INTERVALS)
      });
    }

    // Map period to hours
    const periodMap = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };
    const periodHours = periodMap[period];
    const startTime = new Date(Date.now() - periodHours * 60 * 60 * 1000);

    // Use whitelisted date format (safe from injection)
    const dateFormat = ALLOWED_INTERVALS[interval];

    const timeline = await db('request_logs')
      .where('timestamp', '>=', startTime)
      .select(
        db.raw(`TO_CHAR(timestamp, '${dateFormat}') as time_bucket`),
        db.raw('COUNT(*) as total'),
        db.raw("COUNT(*) FILTER (WHERE action = 'blocked') as blocked"),
        db.raw("COUNT(*) FILTER (WHERE action = 'flagged') as flagged")
      )
      .groupByRaw(`TO_CHAR(timestamp, '${dateFormat}')`)
      .orderBy('time_bucket');

    // Parse COUNT bigints to numbers (pg driver returns strings)
    const parsed = timeline.map(row => ({
      time_bucket: row.time_bucket,
      total: parseInt(row.total) || 0,
      blocked: parseInt(row.blocked) || 0,
      flagged: parseInt(row.flagged) || 0,
    }));

    res.json({ timeline: parsed });
  } catch (error) {
    logger.error('Timeline error', { error: error.message });
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

router.get('/threats', async (req, res) => {
  try {
    const { period = '24h' } = req.query;

    // Validate period parameter against whitelist
    if (!ALLOWED_PERIODS.includes(period)) {
      return res.status(400).json({
        error: 'Invalid period parameter',
        allowed: ALLOWED_PERIODS
      });
    }

    const periodMap = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };
    const periodHours = periodMap[period];
    const startTime = new Date(Date.now() - periodHours * 60 * 60 * 1000);

    const result = await db('request_logs')
      .where('timestamp', '>=', startTime)
      .whereNot('action', 'allowed')
      .select(
        db.raw("COUNT(*) FILTER (WHERE (threat_scores->>'prompt_injection')::float >= 0.7) as prompt_injection"),
        db.raw("COUNT(*) FILTER (WHERE (threat_scores->>'jailbreak')::float >= 0.7) as jailbreak"),
        db.raw("COUNT(*) FILTER (WHERE (threat_scores->>'pii')::float >= 0.5) as pii"),
        db.raw('COUNT(*) as total')
      )
      .first();

    res.json({
      breakdown: [
        { type: 'Prompt Injection', count: parseInt(result.prompt_injection) || 0 },
        { type: 'Jailbreak', count: parseInt(result.jailbreak) || 0 },
        { type: 'PII Detection', count: parseInt(result.pii) || 0 }
      ],
      total: parseInt(result.total) || 0
    });
  } catch (error) {
    logger.error('Threats error', { error: error.message });
    res.status(500).json({ error: 'Failed to get threats' });
  }
});

router.get('/logs', async (req, res) => {
  try {
    const { page = 1, limit = 50, action } = req.query;
    const offset = (page - 1) * limit;

    let query = db('request_logs');

    if (action) {
      query = query.where('action', action);
    }

    const [logs, countResult] = await Promise.all([
      query.clone().orderBy('timestamp', 'desc').limit(limit).offset(offset)
        .select('id', 'timestamp', 'input_text', 'threat_scores', 'action', 'latency_ms'),
      query.clone().count('* as count').first()
    ]);

    // Mask any secrets in the input_text field before returning
    const maskedLogs = logs.map(log => ({
      ...log,
      input_text: secretMasker.mask(log.input_text || '').masked
    }));

    res.json({
      logs: maskedLogs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(countResult.count),
        pages: Math.ceil(countResult.count / limit)
      }
    });
  } catch (error) {
    logger.error('Logs error', { error: error.message });
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// Egress statistics endpoint
router.get('/egress', async (req, res) => {
  try {
    const { period = '24h' } = req.query;

    // Validate period parameter against whitelist
    if (!ALLOWED_PERIODS.includes(period)) {
      return res.status(400).json({
        error: 'Invalid period parameter',
        allowed: ALLOWED_PERIODS
      });
    }

    // Map period to hours
    const periodMap = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };
    const periodHours = periodMap[period];
    const startTime = new Date(Date.now() - periodHours * 60 * 60 * 1000);

    // Get egress statistics
    const stats = await db('egress_logs')
      .select(
        db.raw('COUNT(*) as total_events'),
        db.raw('COALESCE(SUM(secrets_detected), 0) as total_secrets'),
        db.raw('COALESCE(SUM(pii_detected), 0) as total_pii')
      )
      .where('timestamp', '>=', startTime)
      .first();

    // Get breakdown by detected type
    const typeBreakdown = await db('egress_logs')
      .select('detected_types')
      .where('timestamp', '>=', startTime)
      .whereRaw("detected_types != '[]'::jsonb");

    // Count occurrences of each type
    const typeCounts = {};
    typeBreakdown.forEach(row => {
      const types = row.detected_types || [];
      types.forEach(type => {
        typeCounts[type] = (typeCounts[type] || 0) + 1;
      });
    });

    // Get top paths with sensitive data egress
    const topPaths = await db('egress_logs')
      .select('path')
      .count('* as count')
      .sum('secrets_detected as secrets')
      .sum('pii_detected as pii')
      .where('timestamp', '>=', startTime)
      .whereRaw('(secrets_detected > 0 OR pii_detected > 0)')
      .groupBy('path')
      .orderBy('count', 'desc')
      .limit(10);

    res.json({
      period,
      summary: {
        totalEvents: parseInt(stats.total_events) || 0,
        totalSecrets: parseInt(stats.total_secrets) || 0,
        totalPii: parseInt(stats.total_pii) || 0,
      },
      typeBreakdown: typeCounts,
      topPaths: topPaths.map(p => ({
        path: p.path,
        count: parseInt(p.count) || 0,
        secrets: parseInt(p.secrets) || 0,
        pii: parseInt(p.pii) || 0,
      })),
    });
  } catch (error) {
    logger.error('Egress stats error', { error: error.message });
    res.status(500).json({ error: 'Failed to get egress statistics' });
  }
});

// Recent egress events with sensitive data
router.get('/egress/recent', async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const parsedLimit = Math.min(parseInt(limit) || 50, 100);

    const events = await db('egress_logs')
      .whereRaw('(secrets_detected > 0 OR pii_detected > 0)')
      .orderBy('timestamp', 'desc')
      .limit(parsedLimit)
      .select(
        'id',
        'timestamp',
        'path',
        'method',
        'user_id',
        'client_ip',
        'status_code',
        'response_size',
        'secrets_detected',
        'pii_detected',
        'detected_types'
      );

    res.json({ events });
  } catch (error) {
    logger.error('Recent egress events error', { error: error.message });
    res.status(500).json({ error: 'Failed to get recent egress events' });
  }
});

// ============================================================
// Session Threat Tracking Endpoints
// ============================================================

/**
 * Get sessions with elevated threat scores
 * Returns sessions sorted by cumulative threat score (descending)
 */
router.get('/sessions/elevated', async (req, res) => {
  try {
    const { minScore = 0.5 } = req.query;
    const parsedMinScore = Math.max(0, Math.min(parseFloat(minScore) || 0.5, 10));

    const sessions = await sessionTracker.getElevatedSessions(parsedMinScore);

    res.json({
      sessions,
      count: sessions.length,
      threshold: sessionTracker.CUMULATIVE_THRESHOLD,
      minScoreFilter: parsedMinScore,
    });
  } catch (error) {
    logger.error('Elevated sessions error', { error: error.message });
    res.status(500).json({ error: 'Failed to get elevated sessions' });
  }
});

/**
 * Get detailed info for a specific session
 */
router.get('/sessions/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const info = await sessionTracker.getSessionInfo(sessionId);

    if (!info) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json(info);
  } catch (error) {
    logger.error('Session info error', { error: error.message, sessionId: req.params.sessionId });
    res.status(500).json({ error: 'Failed to get session info' });
  }
});

/**
 * Reset alert status for a session (admin only)
 */
router.post('/sessions/:sessionId/reset-alert', requireAdmin, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const success = await sessionTracker.resetSessionAlert(sessionId);

    if (!success) {
      return res.status(500).json({ error: 'Failed to reset alert' });
    }

    logger.info('Session alert reset by admin', {
      sessionId,
      adminId: req.user.id,
      adminEmail: req.user.email,
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    logger.error('Session reset error', { error: error.message, sessionId: req.params.sessionId });
    res.status(500).json({ error: 'Failed to reset session alert' });
  }
});

/**
 * Clear session threat data (admin only)
 */
router.delete('/sessions/:sessionId', requireAdmin, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const success = await sessionTracker.clearSession(sessionId);

    if (!success) {
      return res.status(500).json({ error: 'Failed to clear session' });
    }

    logger.info('Session cleared by admin', {
      sessionId,
      adminId: req.user.id,
      adminEmail: req.user.email,
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    logger.error('Session clear error', { error: error.message, sessionId: req.params.sessionId });
    res.status(500).json({ error: 'Failed to clear session' });
  }
});

// ============================================================
// Audit Log Endpoints
// ============================================================

/**
 * Query audit logs (admin only)
 * Supports filtering by user, action, resource, and date range
 */
router.get('/audit', requireAdmin, async (req, res) => {
  try {
    const {
      userId,
      action,
      resource,
      startDate,
      endDate,
      limit = 50,
      offset = 0,
    } = req.query;

    const result = await queryAuditLogs({
      userId: userId ? parseInt(userId) : undefined,
      action,
      resource,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: Math.min(parseInt(limit) || 50, 100),
      offset: parseInt(offset) || 0,
    });

    res.json(result);
  } catch (error) {
    logger.error('Audit logs query error', { error: error.message });
    res.status(500).json({ error: 'Failed to query audit logs' });
  }
});

/**
 * Get a specific audit log entry (admin only)
 */
router.get('/audit/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const log = await getAuditLogById(parseInt(id));

    if (!log) {
      return res.status(404).json({ error: 'Audit log not found' });
    }

    res.json(log);
  } catch (error) {
    logger.error('Audit log get error', { error: error.message, id: req.params.id });
    res.status(500).json({ error: 'Failed to get audit log' });
  }
});

module.exports = { router, initDb };
