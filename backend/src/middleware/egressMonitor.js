/**
 * Egress Monitoring Middleware
 * Monitors API responses for sensitive data before they leave the system
 */

const secretMasker = require('../utils/secretMasker');
const { publishEvent, CHANNELS } = require('../services/redis');
const logger = require('../services/logger');

// Database instance - will be initialized later
let db = null;

/**
 * Initialize database connection for egress monitoring
 * @param {object} knex - Knex database instance
 */
const initDb = (knex) => {
  db = knex;
};

/**
 * Configuration for egress monitoring
 */
const EGRESS_CONFIG = {
  // Paths to monitor (regex patterns)
  monitoredPaths: [/^\/api\//],

  // Paths to exclude from monitoring
  // Auth endpoints intentionally return JWT tokens - not a data leak
  // Firewall analyze endpoints return threat scores/metadata, not user data
  excludedPaths: [
    /^\/api\/health/,
    /^\/api\/csrf-token/,
    /^\/api\/auth\/(login|register|refresh|me)$/,
    /^\/api\/firewall\/analyze/,
  ],

  // Minimum response size to analyze (bytes)
  minResponseSize: 10,

  // Maximum response size to analyze (bytes) - skip very large responses
  maxResponseSize: 1000000,

  // Alert threshold - number of sensitive items to trigger alert
  alertThreshold: 1,
};

/**
 * PII detection patterns
 */
const PII_PATTERNS = [
  { name: 'ssn', pattern: /\d{3}-\d{2}-\d{4}/ },
  { name: 'credit_card', pattern: /\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}/ },
  { name: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
];

/**
 * Check if response contains sensitive data
 * @param {string|object} body - Response body to analyze
 * @returns {{ secrets: Array, pii: Array, hasSensitiveData: boolean }}
 */
function analyzeResponse(body) {
  if (typeof body !== 'string') {
    body = JSON.stringify(body);
  }

  // Use secretMasker to detect secrets (includes encoded secret detection)
  const secretResult = secretMasker.mask(body);

  // Also check for PII patterns
  const piiDetected = [];
  for (const { name, pattern } of PII_PATTERNS) {
    if (pattern.test(body)) {
      piiDetected.push({ type: name });
    }
  }

  return {
    secrets: secretResult.detected,
    pii: piiDetected,
    hasSensitiveData: secretResult.detected.length > 0 || piiDetected.length > 0,
    maskedBody: secretResult.masked,
  };
}

/**
 * Redact PII patterns from response text
 * @param {string} text - Response body string
 * @returns {string} Text with PII patterns redacted
 */
function redactPII(text) {
  let redacted = text;
  const piiReplacements = [
    { pattern: /\d{3}-\d{2}-\d{4}/g, replacement: '[SSN REDACTED]' },
    { pattern: /\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}/g, replacement: '[CC REDACTED]' },
  ];
  for (const { pattern, replacement } of piiReplacements) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

/**
 * Log egress event to database
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {object} analysis - Analysis result from analyzeResponse
 * @param {string} responseBody - Response body string
 */
async function logEgressEvent(req, res, analysis, responseBody) {
  if (!db) {
    logger.warn('Egress logging skipped: database not initialized');
    return;
  }

  try {
    await db('egress_logs').insert({
      timestamp: new Date(),
      path: req.path,
      method: req.method,
      user_id: req.user?.id || null,
      client_ip: req.ip,
      status_code: res.statusCode,
      response_size: responseBody.length,
      secrets_detected: analysis.secrets.length,
      pii_detected: analysis.pii.length,
      detected_types: JSON.stringify([
        ...analysis.secrets.map(s => s.type),
        ...analysis.pii.map(p => p.type)
      ]),
    });
  } catch (err) {
    logger.error('Failed to log egress event', { error: err.message });
  }
}

/**
 * Publish alert for sensitive data egress
 * @param {object} req - Express request object
 * @param {object} analysis - Analysis result from analyzeResponse
 */
async function publishEgressAlert(req, analysis) {
  try {
    await publishEvent(CHANNELS.ALERTS, {
      type: 'egress_sensitive_data',
      timestamp: new Date().toISOString(),
      path: req.path,
      method: req.method,
      user_id: req.user?.id || null,
      client_ip: req.ip,
      detected: [
        ...analysis.secrets.map(s => s.type),
        ...analysis.pii.map(p => p.type)
      ],
    });
    logger.warn('Egress alert triggered', {
      path: req.path,
      detected: analysis.secrets.length + analysis.pii.length
    });
  } catch (err) {
    logger.error('Failed to publish egress alert', { error: err.message });
  }
}

/**
 * Egress monitoring middleware factory
 * @param {object} options - Configuration options to override defaults
 * @returns {function} Express middleware function
 */
function egressMonitor(options = {}) {
  const config = { ...EGRESS_CONFIG, ...options };

  return (req, res, next) => {
    // Check if path should be monitored
    const shouldMonitor = config.monitoredPaths.some(p => p.test(req.path)) &&
                          !config.excludedPaths.some(p => p.test(req.path));

    if (!shouldMonitor) {
      return next();
    }

    // Store original json method
    const originalJson = res.json.bind(res);

    // Override json method to intercept and redact sensitive data BEFORE sending
    res.json = function(body) {
      const bodyStr = JSON.stringify(body);

      // Skip if response too small or too large
      if (bodyStr.length < config.minResponseSize || bodyStr.length > config.maxResponseSize) {
        return originalJson(body);
      }

      try {
        // Analyze response SYNCHRONOUSLY before sending
        const analysis = analyzeResponse(bodyStr);

        if (analysis.hasSensitiveData) {
          // Redact sensitive data: secrets (via maskedBody) + PII
          let redactedStr = redactPII(analysis.maskedBody);
          let redactedBody;
          try {
            redactedBody = JSON.parse(redactedStr);
          } catch (parseErr) {
            logger.error('Egress redaction created invalid JSON, blocking response', {
              path: req.path,
              error: parseErr.message
            });
            redactedBody = {
              error: 'Response blocked',
              message: 'Sensitive content detected and could not be safely redacted'
            };
          }

          // Log and alert asynchronously (don't delay the redacted response)
          logEgressEvent(req, res, analysis, bodyStr).catch(err =>
            logger.error('Egress log failed', { error: err.message })
          );

          const totalDetected = analysis.secrets.length + analysis.pii.length;
          if (totalDetected >= config.alertThreshold) {
            publishEgressAlert(req, analysis).catch(err =>
              logger.error('Egress alert failed', { error: err.message })
            );
          }

          // Send REDACTED response
          return originalJson(redactedBody);
        }
      } catch (err) {
        logger.error('Egress analysis failed', { error: err.message });
      }

      // No sensitive data or analysis failed - send original
      return originalJson(body);
    };

    next();
  };
}

module.exports = egressMonitor;
module.exports.analyzeResponse = analyzeResponse;
module.exports.redactPII = redactPII;
module.exports.logEgressEvent = logEgressEvent;
module.exports.publishEgressAlert = publishEgressAlert;
module.exports.EGRESS_CONFIG = EGRESS_CONFIG;
module.exports.PII_PATTERNS = PII_PATTERNS;
module.exports.initDb = initDb;
