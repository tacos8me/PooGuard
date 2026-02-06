const crypto = require('crypto');
const { getClient, createDedicatedClient, publishEvent, CHANNELS } = require('./redis');
const { analyzeTextCached } = require('./modelService');
const logger = require('./logger');

const QUEUE_KEY = 'queue:analysis';
const RESULT_PREFIX = 'result:';
const RESULT_TTL_SECONDS = 3600; // 1 hour

let workerRunning = false;
let workerStopping = false;

/**
 * Enqueue a text for async analysis.
 * Returns a request ID that can be used to poll for results.
 */
const enqueue = async (text, { userId, clientIp, isAuthenticated, cacheOptions }) => {
  const requestId = crypto.randomUUID();
  const job = {
    requestId,
    text,
    userId: userId || null,
    clientIp,
    isAuthenticated,
    cacheOptions,
    enqueuedAt: Date.now(),
  };

  const redis = await getClient();
  await redis.lPush(QUEUE_KEY, JSON.stringify(job));

  logger.debug('Analysis job enqueued', { requestId });
  return requestId;
};

/**
 * Get the result for an async analysis request.
 * Returns null if not yet available.
 */
const getResult = async (requestId) => {
  const redis = await getClient();
  const raw = await redis.get(`${RESULT_PREFIX}${requestId}`);
  if (!raw) return null;
  return JSON.parse(raw);
};

/**
 * Process a single job from the queue.
 * Called by the worker loop.
 */
const processJob = async (job, db) => {
  const { requestId, text, userId, clientIp, isAuthenticated, cacheOptions } = job;
  const startTime = Date.now();

  try {
    const analysisResult = await analyzeTextCached(text, cacheOptions || {});
    const latencyMs = Date.now() - startTime;

    const result = {
      requestId,
      status: 'completed',
      threatScores: {
        prompt_injection: analysisResult.prompt_injection_score,
        jailbreak: analysisResult.jailbreak_score,
        pii: analysisResult.pii_score,
        semantic_similarity: analysisResult.semantic_similarity_score || 0,
      },
      cache_hit: !!analysisResult.cache_hit,
      latencyMs,
      completedAt: Date.now(),
    };

    // Store result in Redis
    const redis = await getClient();
    await redis.set(
      `${RESULT_PREFIX}${requestId}`,
      JSON.stringify(result),
      { EX: RESULT_TTL_SECONDS }
    );

    // Publish firewall event so dashboard gets real-time updates
    const event = {
      id: requestId,
      timestamp: new Date().toISOString(),
      action: 'async_completed',
      threatScores: result.threatScores,
      latencyMs,
      isAuthenticated,
      source: 'async_worker',
    };
    await publishEvent(CHANNELS.FIREWALL_EVENTS, event);

    // Log to database if available
    if (db) {
      try {
        const secretMasker = require('../utils/secretMasker');
        const maskedInput = secretMasker.mask(text);
        await db('request_logs').insert({
          input_text: maskedInput.masked.substring(0, 1000),
          threat_scores: result.threatScores,
          action: 'async_completed',
          latency_ms: latencyMs,
          user_id: userId || null,
          is_authenticated: isAuthenticated,
          client_ip: clientIp,
        });
      } catch (dbErr) {
        logger.warn('Failed to log async result to DB', { error: dbErr.message });
      }
    }

    logger.debug('Async analysis completed', { requestId, latencyMs });
  } catch (err) {
    logger.error('Async analysis failed', { requestId, error: err.message });

    // Store error result so callers know it failed
    try {
      const redis = await getClient();
      await redis.set(
        `${RESULT_PREFIX}${requestId}`,
        JSON.stringify({ requestId, status: 'error', error: err.message, completedAt: Date.now() }),
        { EX: RESULT_TTL_SECONDS }
      );
    } catch (storeErr) {
      logger.error('Failed to store error result', { error: storeErr.message });
    }
  }
};

/**
 * Start the background worker that processes the analysis queue.
 * Uses BRPOP for efficient blocking reads.
 */
const startWorker = async (db) => {
  if (workerRunning) return;
  workerRunning = true;
  workerStopping = false;

  logger.info('Analysis queue worker started');

  // Use a DEDICATED Redis client for BRPOP so the blocking call
  // doesn't starve the shared client used by rate limiter, token storage, etc.
  let workerRedis;
  try {
    workerRedis = await createDedicatedClient('queue-worker');
  } catch (err) {
    logger.error('Failed to create dedicated Redis client for queue worker', { error: err.message });
    workerRunning = false;
    return;
  }

  while (!workerStopping) {
    try {
      // BRPOP with 5s timeout so we can check workerStopping periodically
      const item = await workerRedis.brPop(QUEUE_KEY, 5);
      if (!item) continue; // timeout, loop again

      const job = JSON.parse(item.element);
      await processJob(job, db);
    } catch (err) {
      if (workerStopping) break;
      logger.error('Analysis queue worker error', { error: err.message });
      // Brief pause to avoid tight error loop
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  // Clean up dedicated connection
  try { await workerRedis.quit(); } catch (_) { /* ignore */ }
  workerRunning = false;
  logger.info('Analysis queue worker stopped');
};

/**
 * Stop the background worker gracefully.
 */
const stopWorker = () => {
  workerStopping = true;
};

const isWorkerRunning = () => workerRunning;

module.exports = { enqueue, getResult, startWorker, stopWorker, isWorkerRunning, processJob };
