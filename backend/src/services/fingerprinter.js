/**
 * Request Fingerprinting Service
 *
 * Generates fingerprints from IP + UA + timing patterns to:
 * - Detect distributed attacks from the same actor
 * - Link requests across IP changes
 * - Identify suspicious request patterns
 */

const crypto = require('crypto');
const { getClient, publishEvent, CHANNELS } = require('./redis');
const logger = require('./logger');

// Configuration
const FINGERPRINT_TTL = 24 * 60 * 60; // 24 hours
const TIMING_WINDOW_SIZE = 10; // Track last 10 request times
const TIMING_SIMILARITY_THRESHOLD = 0.8; // 80% timing pattern similarity
const MIN_REQUESTS_FOR_PATTERN = 5; // Minimum requests to establish pattern

/**
 * Extract browser fingerprint components from request
 *
 * @param {Object} req - Express request object
 * @returns {Object} Fingerprint components
 */
const extractFingerprintComponents = (req) => {
  const headers = req.headers || {};

  return {
    // Core identifiers
    ip: req.ip || req.connection?.remoteAddress || 'unknown',
    userAgent: headers['user-agent'] || 'unknown',

    // Browser hints (if available)
    acceptLanguage: headers['accept-language'] || '',
    acceptEncoding: headers['accept-encoding'] || '',

    // Security headers that may reveal client
    secChUa: headers['sec-ch-ua'] || '', // Chrome User-Agent Client Hints
    secChUaPlatform: headers['sec-ch-ua-platform'] || '',
    secChUaMobile: headers['sec-ch-ua-mobile'] || '',

    // Connection characteristics
    connection: headers['connection'] || '',
    upgradeInsecureRequests: headers['upgrade-insecure-requests'] || '',

    // Forwarded headers (for reverse proxy setups)
    xForwardedFor: headers['x-forwarded-for'] || '',
    xRealIp: headers['x-real-ip'] || '',
  };
};

/**
 * Generate a stable fingerprint hash from components
 * This creates a consistent ID for similar requests
 *
 * @param {Object} components - Fingerprint components
 * @returns {string} SHA-256 hash (first 16 chars)
 */
const generateFingerprintHash = (components) => {
  // Use only stable components for core fingerprint
  const stableData = [
    components.userAgent,
    components.acceptLanguage,
    components.acceptEncoding,
    components.secChUa,
    components.secChUaPlatform,
  ].join('|');

  return crypto.createHash('sha256').update(stableData).digest('hex').substring(0, 16);
};

/**
 * Generate an IP-aware fingerprint that includes network info
 *
 * @param {Object} components - Fingerprint components
 * @returns {string} SHA-256 hash (first 16 chars)
 */
const generateIpAwareFingerprint = (components) => {
  const ipData = [
    components.ip,
    components.userAgent,
    components.acceptLanguage,
  ].join('|');

  return crypto.createHash('sha256').update(ipData).digest('hex').substring(0, 16);
};

/**
 * Calculate timing pattern similarity between two sets of intervals
 * Uses normalized cross-correlation
 *
 * @param {number[]} pattern1 - First timing pattern (intervals in ms)
 * @param {number[]} pattern2 - Second timing pattern (intervals in ms)
 * @returns {number} Similarity score 0-1
 */
const calculateTimingSimilarity = (pattern1, pattern2) => {
  if (!pattern1.length || !pattern2.length) {
    return 0;
  }

  // Normalize patterns to 0-1 range
  const normalize = (arr) => {
    const max = Math.max(...arr);
    const min = Math.min(...arr);
    if (max === min) return arr.map(() => 0.5);
    return arr.map((v) => (v - min) / (max - min));
  };

  // Use the shorter pattern length
  const len = Math.min(pattern1.length, pattern2.length);
  const norm1 = normalize(pattern1.slice(0, len));
  const norm2 = normalize(pattern2.slice(0, len));

  // Calculate correlation coefficient
  let sumProduct = 0;
  let sumSq1 = 0;
  let sumSq2 = 0;

  for (let i = 0; i < len; i++) {
    sumProduct += norm1[i] * norm2[i];
    sumSq1 += norm1[i] * norm1[i];
    sumSq2 += norm2[i] * norm2[i];
  }

  const denominator = Math.sqrt(sumSq1 * sumSq2);
  if (denominator === 0) return 0;

  return sumProduct / denominator;
};

/**
 * Convert request times to intervals between requests
 *
 * @param {number[]} times - Array of timestamps
 * @returns {number[]} Array of intervals in ms
 */
const timesToIntervals = (times) => {
  if (times.length < 2) return [];
  const intervals = [];
  for (let i = 1; i < times.length; i++) {
    intervals.push(times[i] - times[i - 1]);
  }
  return intervals;
};

/**
 * Request Fingerprinter class
 * Tracks and analyzes request fingerprints
 */
class RequestFingerprinter {
  constructor() {
    this.redis = null;
  }

  /**
   * Initialize Redis connection
   */
  async init() {
    this.redis = await getClient();
    logger.info('Request fingerprinter initialized');
  }

  /**
   * Generate full fingerprint analysis for a request
   *
   * @param {Object} req - Express request object
   * @returns {Object} Fingerprint analysis result
   */
  async fingerprint(req) {
    const components = extractFingerprintComponents(req);
    const browserFingerprint = generateFingerprintHash(components);
    const ipFingerprint = generateIpAwareFingerprint(components);
    const timestamp = Date.now();

    const result = {
      browserFingerprint,
      ipFingerprint,
      components: {
        ip: components.ip,
        userAgent: components.userAgent.substring(0, 100),
        acceptLanguage: components.acceptLanguage.substring(0, 50),
      },
      timestamp,
      linkedFingerprints: [],
      suspiciousPatterns: [],
      riskScore: 0,
    };

    if (!this.redis) {
      return result;
    }

    try {
      // Store/update fingerprint data
      await this._updateFingerprintData(browserFingerprint, components, timestamp);

      // Check for linked fingerprints (same browser, different IPs)
      result.linkedFingerprints = await this._findLinkedFingerprints(browserFingerprint);

      // Analyze timing patterns
      const timingAnalysis = await this._analyzeTimingPatterns(browserFingerprint, timestamp);
      result.timingPattern = timingAnalysis;

      // Calculate risk score
      result.riskScore = this._calculateRiskScore(result);

      // Detect suspicious patterns
      result.suspiciousPatterns = this._detectSuspiciousPatterns(result);

      // Publish event if high risk
      if (result.riskScore > 0.7) {
        await publishEvent(CHANNELS.FIREWALL_EVENTS, {
          type: 'suspicious_fingerprint',
          browserFingerprint,
          ipFingerprint,
          riskScore: result.riskScore,
          suspiciousPatterns: result.suspiciousPatterns,
          ip: components.ip,
          timestamp,
        });
      }
    } catch (error) {
      logger.error('Fingerprint analysis error', { error: error.message });
    }

    return result;
  }

  /**
   * Update stored fingerprint data
   */
  async _updateFingerprintData(fingerprint, components, timestamp) {
    const key = `fingerprint:${fingerprint}`;
    const ipKey = `fingerprint:${fingerprint}:ips`;
    const timesKey = `fingerprint:${fingerprint}:times`;

    // Store/update main fingerprint data
    const data = JSON.stringify({
      lastSeen: timestamp,
      userAgent: components.userAgent,
      acceptLanguage: components.acceptLanguage,
    });
    await this.redis.setEx(key, FINGERPRINT_TTL, data);

    // Track IPs used by this fingerprint
    await this.redis.sAdd(ipKey, components.ip);
    await this.redis.expire(ipKey, FINGERPRINT_TTL);

    // Track request times for timing pattern analysis
    await this.redis.lPush(timesKey, timestamp.toString());
    await this.redis.lTrim(timesKey, 0, TIMING_WINDOW_SIZE - 1);
    await this.redis.expire(timesKey, FINGERPRINT_TTL);
  }

  /**
   * Find fingerprints that share the same browser profile but different IPs
   */
  async _findLinkedFingerprints(fingerprint) {
    const ipKey = `fingerprint:${fingerprint}:ips`;
    const ips = await this.redis.sMembers(ipKey);

    return ips.map((ip) => ({
      ip,
      fingerprint: generateIpAwareFingerprint({ ip, userAgent: '', acceptLanguage: '' }),
    }));
  }

  /**
   * Analyze timing patterns for this fingerprint
   */
  async _analyzeTimingPatterns(fingerprint, currentTime) {
    const timesKey = `fingerprint:${fingerprint}:times`;
    const times = await this.redis.lRange(timesKey, 0, -1);

    const timestamps = times.map((t) => parseInt(t, 10)).sort((a, b) => a - b);
    const intervals = timesToIntervals(timestamps);

    const result = {
      requestCount: timestamps.length,
      intervals: intervals.slice(-5), // Last 5 intervals
      avgInterval: intervals.length > 0 ? intervals.reduce((a, b) => a + b, 0) / intervals.length : 0,
      isBot: false,
      patternScore: 0,
    };

    // Check for bot-like patterns (very consistent timing)
    if (intervals.length >= MIN_REQUESTS_FOR_PATTERN) {
      const variance = this._calculateVariance(intervals);
      const mean = result.avgInterval;

      // Low coefficient of variation suggests bot behavior
      const cv = mean > 0 ? Math.sqrt(variance) / mean : 0;
      result.coefficientOfVariation = cv;
      result.isBot = cv < 0.1 && mean < 1000; // Very consistent and fast
      result.patternScore = result.isBot ? 0.9 : Math.max(0, 1 - cv);
    }

    return result;
  }

  /**
   * Calculate variance of an array of numbers
   */
  _calculateVariance(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / (arr.length - 1);
  }

  /**
   * Calculate overall risk score based on fingerprint analysis
   */
  _calculateRiskScore(analysis) {
    let score = 0;

    // Multiple IPs for same browser fingerprint
    if (analysis.linkedFingerprints.length > 3) {
      score += 0.3;
    } else if (analysis.linkedFingerprints.length > 1) {
      score += 0.1;
    }

    // Bot-like timing patterns
    if (analysis.timingPattern?.isBot) {
      score += 0.4;
    } else if (analysis.timingPattern?.patternScore > 0.8) {
      score += 0.2;
    }

    // High request frequency
    if (analysis.timingPattern?.avgInterval < 500 && analysis.timingPattern?.requestCount > 5) {
      score += 0.2;
    }

    return Math.min(1, score);
  }

  /**
   * Detect specific suspicious patterns
   */
  _detectSuspiciousPatterns(analysis) {
    const patterns = [];

    if (analysis.linkedFingerprints.length > 5) {
      patterns.push({
        type: 'ip_rotation',
        description: 'Same browser fingerprint across many IPs',
        severity: 'high',
        count: analysis.linkedFingerprints.length,
      });
    }

    if (analysis.timingPattern?.isBot) {
      patterns.push({
        type: 'bot_timing',
        description: 'Request timing patterns consistent with automated access',
        severity: 'high',
        cv: analysis.timingPattern.coefficientOfVariation,
      });
    }

    if (analysis.timingPattern?.avgInterval < 200 && analysis.timingPattern?.requestCount > 10) {
      patterns.push({
        type: 'rapid_fire',
        description: 'Very high request frequency detected',
        severity: 'medium',
        avgInterval: analysis.timingPattern.avgInterval,
      });
    }

    return patterns;
  }

  /**
   * Find similar fingerprints based on timing patterns
   * Used to link distributed attacks
   *
   * @param {string} fingerprint - Fingerprint to compare
   * @returns {Array} List of similar fingerprints
   */
  async findSimilarByTiming(fingerprint) {
    if (!this.redis) return [];

    const timesKey = `fingerprint:${fingerprint}:times`;
    const baseTimes = await this.redis.lRange(timesKey, 0, -1);
    const baseIntervals = timesToIntervals(
      baseTimes.map((t) => parseInt(t, 10)).sort((a, b) => a - b)
    );

    if (baseIntervals.length < MIN_REQUESTS_FOR_PATTERN) {
      return [];
    }

    // Scan for other fingerprints (limited scan for performance)
    const similar = [];
    let cursor = 0;

    do {
      const result = await this.redis.scan(cursor, {
        MATCH: 'fingerprint:*:times',
        COUNT: 100,
      });
      cursor = result.cursor;

      for (const key of result.keys) {
        const otherFingerprint = key.split(':')[1];
        if (otherFingerprint === fingerprint) continue;

        const otherTimes = await this.redis.lRange(key, 0, -1);
        const otherIntervals = timesToIntervals(
          otherTimes.map((t) => parseInt(t, 10)).sort((a, b) => a - b)
        );

        if (otherIntervals.length < MIN_REQUESTS_FOR_PATTERN) continue;

        const similarity = calculateTimingSimilarity(baseIntervals, otherIntervals);
        if (similarity >= TIMING_SIMILARITY_THRESHOLD) {
          similar.push({
            fingerprint: otherFingerprint,
            similarity,
          });
        }
      }
    } while (cursor !== 0 && similar.length < 10);

    return similar;
  }

  /**
   * Get fingerprint statistics for analytics
   */
  async getStats() {
    if (!this.redis) {
      return { active: 0, suspicious: 0 };
    }

    try {
      let cursor = 0;
      let activeCount = 0;
      let suspiciousCount = 0;

      do {
        const result = await this.redis.scan(cursor, {
          MATCH: 'fingerprint:*:ips',
          COUNT: 100,
        });
        cursor = result.cursor;

        for (const key of result.keys) {
          activeCount++;
          const ips = await this.redis.sCard(key);
          if (ips > 3) {
            suspiciousCount++;
          }
        }
      } while (cursor !== 0);

      return {
        active: activeCount,
        suspicious: suspiciousCount,
      };
    } catch (error) {
      logger.error('Fingerprint stats error', { error: error.message });
      return { active: 0, suspicious: 0 };
    }
  }
}

// Singleton instance
const fingerprinter = new RequestFingerprinter();

module.exports = {
  fingerprinter,
  // Export utilities for testing
  extractFingerprintComponents,
  generateFingerprintHash,
  generateIpAwareFingerprint,
  calculateTimingSimilarity,
  timesToIntervals,
  FINGERPRINT_TTL,
  TIMING_WINDOW_SIZE,
  TIMING_SIMILARITY_THRESHOLD,
  MIN_REQUESTS_FOR_PATTERN,
};
