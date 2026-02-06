/**
 * Session-Level Threat Tracking Service
 *
 * Tracks threat scores per session/user across requests with:
 * - Cumulative threat scoring
 * - Time-based score decay (30-minute half-life)
 * - Alert triggering when thresholds exceeded
 * - Session identification via JWT user ID or IP+UA fingerprint
 */

const { getClient, publishEvent, CHANNELS } = require('./redis');
const logger = require('./logger');
const crypto = require('crypto');

// Configuration
const SESSION_THREAT_PREFIX = 'session:threat:';
const SESSION_HISTORY_PREFIX = 'session:history:';
const CUMULATIVE_THRESHOLD = parseFloat(process.env.SESSION_THREAT_THRESHOLD || '2.0');
const DECAY_HALF_LIFE_MS = parseInt(process.env.SESSION_DECAY_HALF_LIFE_MS || String(30 * 60 * 1000)); // 30 minutes
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS || String(24 * 60 * 60)); // 24 hours
const ALERT_COOLDOWN_MS = parseInt(process.env.SESSION_ALERT_COOLDOWN_MS || String(15 * 60 * 1000)); // 15 minutes
const MAX_HISTORY_ITEMS = 100;

/**
 * Generate session ID from request
 * Uses user ID if authenticated, otherwise IP + User-Agent fingerprint
 */
const getSessionId = (req) => {
  if (req.user && req.user.id) {
    return `user:${req.user.id}`;
  }

  // Create fingerprint from IP + User-Agent
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const fingerprint = crypto
    .createHash('sha256')
    .update(`${ip}:${userAgent}`)
    .digest('hex')
    .substring(0, 16);

  return `anon:${fingerprint}`;
};

/**
 * Calculate decayed score based on time elapsed
 * Uses exponential decay with configurable half-life
 */
const calculateDecayedScore = (score, lastUpdateTime) => {
  if (!lastUpdateTime || score === 0) return score;

  const now = Date.now();
  const elapsed = now - lastUpdateTime;

  // Exponential decay: score * e^(-lambda * t)
  // where lambda = ln(2) / halfLife
  const lambda = Math.LN2 / DECAY_HALF_LIFE_MS;
  const decayFactor = Math.exp(-lambda * elapsed);

  return score * decayFactor;
};

/**
 * Get current session threat data from Redis
 */
const getSessionThreatData = async (sessionId) => {
  try {
    const redis = await getClient();
    const key = `${SESSION_THREAT_PREFIX}${sessionId}`;
    const data = await redis.get(key);

    if (!data) {
      return {
        cumulativeScore: 0,
        lastUpdateTime: null,
        requestCount: 0,
        threatCount: 0,
        alertTriggeredAt: null,
        alertCount: 0,
      };
    }

    const parsed = JSON.parse(data);
    // Backward compat: migrate boolean alertTriggered to alertTriggeredAt
    if (parsed.alertTriggered === true && !parsed.alertTriggeredAt) {
      parsed.alertTriggeredAt = parsed.lastUpdateTime || Date.now();
      parsed.alertCount = parsed.alertCount || 1;
    } else if (!parsed.alertTriggeredAt) {
      parsed.alertTriggeredAt = null;
      parsed.alertCount = parsed.alertCount || 0;
    }
    return parsed;
  } catch (error) {
    logger.error('Failed to get session threat data', { sessionId, error: error.message });
    return {
      cumulativeScore: 0,
      lastUpdateTime: null,
      requestCount: 0,
      threatCount: 0,
      alertTriggeredAt: null,
      alertCount: 0,
    };
  }
};

/**
 * Update session threat score with new request data
 */
const updateSessionThreat = async (req, threatScores, action, detectedThreats) => {
  try {
    const redis = await getClient();
    const sessionId = getSessionId(req);
    const key = `${SESSION_THREAT_PREFIX}${sessionId}`;
    const historyKey = `${SESSION_HISTORY_PREFIX}${sessionId}`;

    // Get current session data
    const currentData = await getSessionThreatData(sessionId);

    // Calculate decayed score from previous value
    const decayedScore = calculateDecayedScore(
      currentData.cumulativeScore,
      currentData.lastUpdateTime
    );

    // Calculate threat score for this request
    // Higher weight for blocked actions, lower for flagged
    let requestThreatScore = 0;
    if (action === 'blocked') {
      requestThreatScore =
        (threatScores.prompt_injection || 0) * 1.5 +
        (threatScores.jailbreak || 0) * 1.5 +
        (threatScores.pii || 0) * 1.0;
    } else if (action === 'flagged') {
      requestThreatScore =
        (threatScores.prompt_injection || 0) * 0.5 +
        (threatScores.jailbreak || 0) * 0.5 +
        (threatScores.pii || 0) * 0.3;
    }
    // Allowed requests don't add to threat score

    // Add semantic similarity if present
    if (threatScores.semantic_similarity && threatScores.semantic_similarity > 0.5) {
      requestThreatScore += threatScores.semantic_similarity * 0.5;
    }

    // Update cumulative score
    const newCumulativeScore = decayedScore + requestThreatScore;
    const now = Date.now();

    // Determine if we should re-trigger alert using time-windowed approach
    const previousDecayedScore = decayedScore; // score before this request's contribution
    const wasAboveThreshold = previousDecayedScore >= CUMULATIVE_THRESHOLD;
    const isAboveThreshold = newCumulativeScore >= CUMULATIVE_THRESHOLD;
    const lastAlertTime = currentData.alertTriggeredAt || 0;
    const cooldownExpired = lastAlertTime > 0 && (now - lastAlertTime) > ALERT_COOLDOWN_MS;

    // Alert triggers when:
    // 1. First time crossing threshold (never alerted)
    // 2. Score re-escalated after dropping below threshold
    // 3. Sustained threat and cooldown period expired
    const shouldAlert = isAboveThreshold && (
      !currentData.alertTriggeredAt ||
      (!wasAboveThreshold) ||
      (cooldownExpired)
    );

    const newData = {
      cumulativeScore: newCumulativeScore,
      lastUpdateTime: now,
      requestCount: currentData.requestCount + 1,
      threatCount: currentData.threatCount + (detectedThreats.length > 0 ? 1 : 0),
      alertTriggeredAt: currentData.alertTriggeredAt,
      alertCount: currentData.alertCount || 0,
      sessionId,
      isAuthenticated: !!req.user,
      userId: req.user?.id || null,
    };

    let alertTriggeredNow = false;
    if (shouldAlert) {
      newData.alertTriggeredAt = now;
      newData.alertCount = (currentData.alertCount || 0) + 1;
      alertTriggeredNow = true;

      // Publish alert event
      const alertEvent = {
        type: 'session_threat_threshold',
        sessionId,
        cumulativeScore: newCumulativeScore,
        threshold: CUMULATIVE_THRESHOLD,
        requestCount: newData.requestCount,
        threatCount: newData.threatCount,
        alertCount: newData.alertCount,
        isAuthenticated: newData.isAuthenticated,
        userId: newData.userId,
        timestamp: new Date().toISOString(),
        severity: newCumulativeScore >= CUMULATIVE_THRESHOLD * 1.5 ? 'critical' : 'high',
        reEscalation: wasAboveThreshold === false && currentData.alertTriggeredAt != null,
      };

      await publishEvent(CHANNELS.ALERTS, alertEvent);
      logger.warn('Session threat threshold exceeded', alertEvent);
    }

    // Store updated data
    await redis.setEx(key, SESSION_TTL_SECONDS, JSON.stringify(newData));

    // Add to history
    const historyEntry = {
      timestamp: now,
      threatScores,
      action,
      detectedThreats,
      requestThreatScore,
      cumulativeScore: newCumulativeScore,
    };
    await redis.lPush(historyKey, JSON.stringify(historyEntry));
    await redis.lTrim(historyKey, 0, MAX_HISTORY_ITEMS - 1);
    await redis.expire(historyKey, SESSION_TTL_SECONDS);

    return {
      sessionId,
      cumulativeScore: newCumulativeScore,
      requestThreatScore,
      alertTriggered: alertTriggeredNow,
      thresholdExceeded: newCumulativeScore >= CUMULATIVE_THRESHOLD,
    };
  } catch (error) {
    logger.error('Failed to update session threat', { error: error.message });
    // Return safe defaults on error
    return {
      sessionId: getSessionId(req),
      cumulativeScore: 0,
      requestThreatScore: 0,
      alertTriggered: false,
      thresholdExceeded: false,
    };
  }
};

/**
 * Get session threat info for a specific session
 */
const getSessionInfo = async (sessionId) => {
  try {
    const redis = await getClient();
    const data = await getSessionThreatData(sessionId);

    // Calculate current decayed score
    const currentScore = calculateDecayedScore(data.cumulativeScore, data.lastUpdateTime);

    // Get recent history
    const historyKey = `${SESSION_HISTORY_PREFIX}${sessionId}`;
    const historyRaw = await redis.lRange(historyKey, 0, 9);
    const history = historyRaw.map((h) => JSON.parse(h));

    return {
      sessionId,
      cumulativeScore: currentScore,
      rawScore: data.cumulativeScore,
      requestCount: data.requestCount,
      threatCount: data.threatCount,
      alertTriggered: !!data.alertTriggeredAt,
      alertTriggeredAt: data.alertTriggeredAt,
      alertCount: data.alertCount || 0,
      thresholdExceeded: currentScore >= CUMULATIVE_THRESHOLD,
      threshold: CUMULATIVE_THRESHOLD,
      lastUpdateTime: data.lastUpdateTime,
      isAuthenticated: data.isAuthenticated,
      userId: data.userId,
      recentHistory: history,
    };
  } catch (error) {
    logger.error('Failed to get session info', { sessionId, error: error.message });
    return null;
  }
};

/**
 * Get all active sessions with elevated threat scores
 */
const getElevatedSessions = async (minScore = 0.5) => {
  try {
    const redis = await getClient();

    // Scan for all session keys
    const keys = [];
    let cursor = 0;
    do {
      const result = await redis.scan(cursor, {
        MATCH: `${SESSION_THREAT_PREFIX}*`,
        COUNT: 100,
      });
      cursor = result.cursor;
      keys.push(...result.keys);
    } while (cursor !== 0);

    // Get data for each session and filter by score
    const sessions = [];
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const parsed = JSON.parse(data);
        const currentScore = calculateDecayedScore(parsed.cumulativeScore, parsed.lastUpdateTime);
        if (currentScore >= minScore) {
          sessions.push({
            sessionId: parsed.sessionId || key.replace(SESSION_THREAT_PREFIX, ''),
            cumulativeScore: currentScore,
            requestCount: parsed.requestCount,
            threatCount: parsed.threatCount,
            alertTriggered: !!parsed.alertTriggeredAt,
            alertTriggeredAt: parsed.alertTriggeredAt,
            alertCount: parsed.alertCount || 0,
            isAuthenticated: parsed.isAuthenticated,
            userId: parsed.userId,
            lastUpdateTime: parsed.lastUpdateTime,
          });
        }
      }
    }

    // Sort by score descending
    sessions.sort((a, b) => b.cumulativeScore - a.cumulativeScore);

    return sessions;
  } catch (error) {
    logger.error('Failed to get elevated sessions', { error: error.message });
    return [];
  }
};

/**
 * Reset alert status for a session (after manual review)
 */
const resetSessionAlert = async (sessionId) => {
  try {
    const redis = await getClient();
    const key = `${SESSION_THREAT_PREFIX}${sessionId}`;
    const data = await getSessionThreatData(sessionId);

    data.alertTriggeredAt = null;
    data.alertCount = 0;
    await redis.setEx(key, SESSION_TTL_SECONDS, JSON.stringify(data));

    logger.info('Session alert reset', { sessionId });
    return true;
  } catch (error) {
    logger.error('Failed to reset session alert', { sessionId, error: error.message });
    return false;
  }
};

/**
 * Clear session threat data (for testing or manual reset)
 */
const clearSession = async (sessionId) => {
  try {
    const redis = await getClient();
    const key = `${SESSION_THREAT_PREFIX}${sessionId}`;
    const historyKey = `${SESSION_HISTORY_PREFIX}${sessionId}`;

    await redis.del(key);
    await redis.del(historyKey);

    logger.info('Session cleared', { sessionId });
    return true;
  } catch (error) {
    logger.error('Failed to clear session', { sessionId, error: error.message });
    return false;
  }
};

module.exports = {
  getSessionId,
  getSessionThreatData,
  updateSessionThreat,
  getSessionInfo,
  getElevatedSessions,
  resetSessionAlert,
  clearSession,
  CUMULATIVE_THRESHOLD,
  ALERT_COOLDOWN_MS,
};
