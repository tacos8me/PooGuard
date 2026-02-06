const axios = require('axios');
const crypto = require('crypto');
const config = require('../config');
const logger = require('./logger');
const { cacheGet, cacheSet } = require('./redis');

// --- Circuit Breaker ---
const CIRCUIT_STATES = { CLOSED: 'closed', OPEN: 'open', HALF_OPEN: 'half-open' };

const circuitBreaker = {
  state: CIRCUIT_STATES.CLOSED,
  failureCount: 0,
  failureThreshold: 5,
  resetTimeoutMs: 30000,
  lastFailureTime: null,

  recordSuccess() {
    this.failureCount = 0;
    if (this.state !== CIRCUIT_STATES.CLOSED) {
      logger.info('Circuit breaker closed after successful request');
    }
    this.state = CIRCUIT_STATES.CLOSED;
  },

  recordFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.failureThreshold && this.state === CIRCUIT_STATES.CLOSED) {
      this.state = CIRCUIT_STATES.OPEN;
      logger.warn('Circuit breaker opened', { failureCount: this.failureCount });
    }
  },

  canRequest() {
    if (this.state === CIRCUIT_STATES.CLOSED) return true;
    if (this.state === CIRCUIT_STATES.OPEN) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeoutMs) {
        this.state = CIRCUIT_STATES.HALF_OPEN;
        logger.info('Circuit breaker half-open, allowing test request');
        return true;
      }
      return false;
    }
    // HALF_OPEN: allow one request through
    return true;
  },

  getState() {
    // Check if open circuit should transition to half-open
    if (this.state === CIRCUIT_STATES.OPEN && this.lastFailureTime) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeoutMs) {
        return CIRCUIT_STATES.HALF_OPEN;
      }
    }
    return this.state;
  },

  reset() {
    this.state = CIRCUIT_STATES.CLOSED;
    this.failureCount = 0;
    this.lastFailureTime = null;
  }
};

const modelClient = axios.create({
  baseURL: config.modelService.url,
  timeout: 30000,
  headers: config.modelService.apiKey
    ? { 'X-API-Key': config.modelService.apiKey }
    : {}
});

const executeWithCircuitBreaker = async (fn) => {
  if (!circuitBreaker.canRequest()) {
    throw new Error('Model service circuit breaker is open');
  }

  try {
    const result = await fn();
    circuitBreaker.recordSuccess();
    return result;
  } catch (error) {
    // Auth failures indicate config issues, not service outages — don't trip the breaker
    if (error.response?.status === 401 || error.response?.status === 403) {
      throw error;
    }
    circuitBreaker.recordFailure();
    throw error;
  }
};

const analyzeText = async (text) => {
  const startTime = Date.now();

  return executeWithCircuitBreaker(async () => {
    try {
      const response = await modelClient.post('/analyze', { text });
      const latencyMs = Date.now() - startTime;

      logger.debug('Model analysis completed', { latencyMs });

      return {
        ...response.data,
        latencyMs
      };
    } catch (error) {
      logger.error('Model service error', { error: error.message });

      if (error.code === 'ECONNREFUSED') {
        throw new Error('Model service unavailable');
      }

      throw error;
    }
  });
};

/**
 * Build a cache key from the input text and model variant.
 * @param {string} text - Input text
 * @param {string} modelVariant - Model variant (e.g. '20b', '120b')
 * @returns {string} Redis cache key
 */
const buildCacheKey = (text, modelVariant) => {
  const hash = crypto.createHash('sha256').update(text).digest('hex');
  return `cache:analyze:${modelVariant}:${hash}`;
};

/**
 * Analyze text with optional Redis caching.
 * When caching is enabled and a cached result exists for the same text + model variant,
 * returns the cached result immediately without calling the model service.
 *
 * @param {string} text - Input text to analyze
 * @param {Object} options - Cache options
 * @param {boolean} options.cacheEnabled - Whether caching is enabled
 * @param {number} options.cacheTtlSeconds - Cache TTL in seconds
 * @param {string} options.modelVariant - Model variant for cache key scoping
 * @param {boolean} options.noCache - Bypass cache for this request
 * @returns {Promise<Object>} Analysis result (with cache_hit flag)
 */
const analyzeTextCached = async (text, { cacheEnabled = true, cacheTtlSeconds = 300, modelVariant = '20b', noCache = false } = {}) => {
  const useCache = cacheEnabled && !noCache;
  const cacheKey = buildCacheKey(text, modelVariant);

  if (useCache) {
    try {
      const cached = await cacheGet(cacheKey);
      if (cached) {
        logger.debug('Cache hit for analyze request', { modelVariant });
        return { ...cached, cache_hit: true, latencyMs: 0 };
      }
    } catch (err) {
      logger.warn('Cache read error, falling through to model', { error: err.message });
    }
  }

  const result = await analyzeText(text);

  if (useCache) {
    try {
      // Cache the scores only (not latencyMs which is per-request)
      const toCache = {
        prompt_injection_score: result.prompt_injection_score,
        jailbreak_score: result.jailbreak_score,
        pii_score: result.pii_score,
        semantic_similarity_score: result.semantic_similarity_score,
      };
      await cacheSet(cacheKey, toCache, cacheTtlSeconds);
    } catch (err) {
      logger.warn('Cache write error', { error: err.message });
    }
  }

  return { ...result, cache_hit: false };
};

/**
 * Analyze multiple texts in a single batch request
 * @param {string[]} texts - Array of texts to analyze
 * @param {number} maxBatchSize - Maximum batch size (default 10)
 * @returns {Promise<Object>} Batch analysis results
 */
const analyzeBatch = async (texts, maxBatchSize = 10) => {
  const startTime = Date.now();

  return executeWithCircuitBreaker(async () => {
    try {
      const response = await modelClient.post('/analyze/batch', {
        texts,
        max_batch_size: maxBatchSize
      }, {
        timeout: 60000
      });
      const latencyMs = Date.now() - startTime;

      logger.debug('Model batch analysis completed', {
        latencyMs,
        totalCount: response.data.total_count,
        successCount: response.data.success_count
      });

      return {
        ...response.data,
        latencyMs
      };
    } catch (error) {
      logger.error('Model service batch error', { error: error.message });

      if (error.code === 'ECONNREFUSED') {
        throw new Error('Model service unavailable');
      }

      if (error.response) {
        const { status, data } = error.response;
        if (status === 400) {
          throw new Error(data.detail || 'Invalid batch request');
        }
        if (status === 503) {
          throw new Error('Model service not available');
        }
      }

      throw error;
    }
  });
};

const analyzeOutput = async (text) => {
  const startTime = Date.now();

  return executeWithCircuitBreaker(async () => {
    try {
      const response = await modelClient.post('/analyze-output', { text });
      const latencyMs = Date.now() - startTime;

      logger.debug('Output analysis completed', { latencyMs });

      return {
        ...response.data,
        latencyMs
      };
    } catch (error) {
      logger.error('Output filter service error', { error: error.message });

      if (error.code === 'ECONNREFUSED') {
        throw new Error('Model service unavailable');
      }

      if (error.response) {
        const { status, data } = error.response;
        if (status === 400) {
          throw new Error(data.detail || 'Invalid output analysis request');
        }
        if (status === 503) {
          throw new Error('Model service not available');
        }
      }

      throw error;
    }
  });
};

const checkHealth = async () => {
  try {
    const response = await modelClient.get('/health');
    return response.data.status === 'healthy';
  } catch {
    return false;
  }
};

const getCircuitState = () => circuitBreaker.getState();

const resetCircuitBreaker = () => circuitBreaker.reset();

module.exports = { analyzeText, analyzeTextCached, buildCacheKey, analyzeBatch, analyzeOutput, checkHealth, getCircuitState, resetCircuitBreaker };
