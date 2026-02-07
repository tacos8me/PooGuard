/**
 * OAI-Compatible Proxy Route
 *
 * Accepts standard OpenAI API requests, analyzes input for threats via
 * model-service, then forwards safe requests to the configured upstream LLM.
 * Supports both streaming (SSE) and non-streaming responses.
 *
 * Clients point at PooGuard as their OpenAI base URL:
 *   OPENAI_BASE_URL=http://pooguard:3001/v1
 *   OPENAI_API_KEY=<pooguard-jwt-or-api-key>
 */
const express = require('express');
const axios = require('axios');
const http = require('http');
const https = require('https');
const { analyzeTextCached } = require('../services/modelService');

const upstreamHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 20 });
const upstreamHttpsAgent = new https.Agent({ keepAlive: true, maxSockets: 20 });
const { getFirewallConfig, getModelConfig, determineAction } = require('./firewall');
const { publishEvent, CHANNELS } = require('../services/redis');
const logger = require('../services/logger');
const { proxyAuth, initDb: initProxyAuthDb } = require('../middleware/proxyAuth');
const { userAnalyzeLimiter } = require('../middleware/rateLimiter');
const secretMasker = require('../utils/secretMasker');
const analysisQueue = require('../services/analysisQueue');
const { getCircuitState } = require('../services/modelService');

const router = express.Router();
let db = null;

const initDb = (knex) => {
  db = knex;
  initProxyAuthDb(knex);
};

/**
 * Extract the user message text from an OAI messages array.
 * Concatenates all user role messages for threat analysis.
 */
function extractUserText(messages) {
  if (!Array.isArray(messages)) return '';
  return messages
    .filter(m => m.role === 'user')
    .map(m => {
      if (typeof m.content === 'string') return m.content;
      // Handle content arrays (vision messages, etc.)
      if (Array.isArray(m.content)) {
        return m.content
          .filter(part => part.type === 'text')
          .map(part => part.text)
          .join(' ');
      }
      return '';
    })
    .join('\n');
}

/**
 * Log a proxy request to the database and publish event.
 */
async function logProxyRequest({ userText, scores, action, detectedThreats, latencyMs, userId, clientIp }) {
  const maskedInput = secretMasker.mask(userText);

  const logEntry = {
    input_text: maskedInput.masked.substring(0, 1000),
    threat_scores: {
      prompt_injection: scores.prompt_injection_score || 0,
      jailbreak: scores.jailbreak_score || 0,
      pii: scores.pii_score || 0,
    },
    action,
    latency_ms: latencyMs,
    user_id: userId || null,
    is_authenticated: !!userId,
    client_ip: clientIp,
  };

  try {
    const [log] = await db('request_logs').insert(logEntry).returning('*');

    const event = {
      id: log.id,
      timestamp: log.timestamp,
      action,
      threatScores: logEntry.threat_scores,
      detectedThreats,
      latencyMs,
      isAuthenticated: !!userId,
      input_text: maskedInput.masked.substring(0, 100),
      source: 'proxy',
    };

    publishEvent(CHANNELS.FIREWALL_EVENTS, event).catch(err => logger.error('Failed to publish proxy event', { error: err.message }));
    return log;
  } catch (err) {
    logger.error('Failed to log proxy request', { error: err.message });
    return null;
  }
}

/**
 * POST /v1/chat/completions
 * OAI-compatible chat completions proxy with threat analysis.
 */
router.post('/chat/completions',
  proxyAuth,
  userAnalyzeLimiter,
  async (req, res) => {
    const startTime = Date.now();
    const requestBody = req.body;

    // Validate basic structure
    if (!requestBody.messages || !Array.isArray(requestBody.messages) || requestBody.messages.length === 0) {
      return res.status(400).json({
        error: {
          message: 'messages is required and must be a non-empty array',
          type: 'invalid_request_error',
          code: 'invalid_messages',
        }
      });
    }

    const isStreaming = requestBody.stream === true;
    const userText = extractUserText(requestBody.messages);

    // Load firewall config first to determine analysis mode
    let firewallConfig;
    try {
      firewallConfig = await getFirewallConfig();
    } catch (err) {
      logger.error('Failed to read firewall config in proxy', { error: err.message });
      return res.status(503).json({
        error: { message: 'Failed to read firewall configuration', type: 'server_error', code: 'config_error' }
      });
    }

    // --- ASYNC MODE: forward immediately, analyze in background ---
    if (firewallConfig.analysisMode === 'async') {
      // Fail-closed check: reject if model service is down and fail mode is closed
      if (firewallConfig.failMode === 'closed' && getCircuitState() !== 'closed') {
        logger.warn('Fail-closed: blocking async proxy request due to model service circuit breaker open', {
          circuitState: getCircuitState(),
          userId: req.user?.id,
        });
        return res.status(503).json({
          error: {
            message: 'Request blocked by PooGuard: fail-closed mode active — model service unavailable',
            type: 'content_filter',
            code: 'fail_closed',
          }
        });
      }

      // Enqueue analysis (fire-and-forget)
      analysisQueue.enqueue(userText, {
        userId: req.user?.id,
        clientIp: req.ip,
        isAuthenticated: true,
        cacheOptions: {
          cacheEnabled: firewallConfig.cacheEnabled,
          cacheTtlSeconds: firewallConfig.cacheTtlSeconds,
          modelVariant: firewallConfig.safeguardModel,
        },
      }).catch(err => {
        logger.error('Failed to enqueue async proxy analysis', { error: err.message });
      });

      // Get upstream config and forward immediately
      let modelCfg;
      try {
        modelCfg = await getModelConfig();
      } catch (err) {
        logger.error('Failed to read model config', { error: err.message });
        return res.status(503).json({
          error: { message: 'Failed to read model configuration', type: 'server_error', code: 'config_error' }
        });
      }

      if (!modelCfg || !modelCfg.endpointUrl) {
        return res.status(503).json({
          error: {
            message: 'No upstream model configured. Set up a model endpoint in Settings.',
            type: 'server_error',
            code: 'no_upstream',
          }
        });
      }

      const upstreamUrl = `${modelCfg.endpointUrl.replace(/\/$/, '')}/chat/completions`;
      const upstreamHeaders = { 'Content-Type': 'application/json' };
      if (modelCfg.apiKey) {
        upstreamHeaders['Authorization'] = `Bearer ${modelCfg.apiKey}`;
      }

      const upstreamBody = { ...requestBody };
      if (modelCfg.modelName) {
        upstreamBody.model = modelCfg.modelName;
      }

      const dummyScores = { prompt_injection_score: 0, jailbreak_score: 0, pii_score: 0 };
      if (isStreaming) {
        return await handleStreaming(req, res, upstreamUrl, upstreamHeaders, upstreamBody, {
          startTime, userText, scores: dummyScores, action: 'async_pending', detectedThreats: [],
        });
      } else {
        return await handleNonStreaming(req, res, upstreamUrl, upstreamHeaders, upstreamBody, {
          startTime, userText, scores: dummyScores, action: 'async_pending', detectedThreats: [],
        });
      }
    }

    // --- SYNC MODE (default): analyze before forwarding ---
    let scores;
    try {
      scores = await analyzeTextCached(userText, {
        cacheEnabled: firewallConfig.cacheEnabled,
        cacheTtlSeconds: firewallConfig.cacheTtlSeconds,
        modelVariant: firewallConfig.safeguardModel,
      });
    } catch (err) {
      logger.error('Proxy threat analysis failed', { error: err.message });

      // In fail-closed mode, block the proxy request when model is down
      if (firewallConfig.failMode === 'closed') {
        logger.warn('Fail-closed: blocking proxy request due to model unavailability', {
          userId: req.user?.id,
        });
        return res.status(503).json({
          error: {
            message: 'Request blocked by PooGuard: fail-closed mode active — model service unavailable',
            type: 'content_filter',
            code: 'fail_closed',
          }
        });
      }

      return res.status(503).json({
        error: {
          message: 'Threat analysis service unavailable',
          type: 'server_error',
          code: 'analysis_unavailable',
        }
      });
    }

    const { action, detectedThreats } = determineAction(scores, firewallConfig);

    // Step 2: Block if threats detected
    if (action === 'blocked') {
      const latencyMs = Date.now() - startTime;
      await logProxyRequest({
        userText, scores, action, detectedThreats, latencyMs,
        userId: req.user?.id, clientIp: req.ip,
      });

      logger.warn('Proxy request blocked', {
        threats: detectedThreats.map(t => t.type),
        userId: req.user?.id,
      });

      return res.status(400).json({
        error: {
          message: 'Request blocked by PooGuard: content policy violation detected',
          type: 'content_filter',
          code: 'content_blocked',
          details: detectedThreats.map(t => ({ type: t.type, score: t.score })),
        }
      });
    }

    // Step 3: Get upstream config
    let modelCfg;
    try {
      modelCfg = await getModelConfig();
    } catch (err) {
      logger.error('Failed to read model config', { error: err.message });
      return res.status(503).json({
        error: { message: 'Failed to read model configuration', type: 'server_error', code: 'config_error' }
      });
    }

    if (!modelCfg || !modelCfg.endpointUrl) {
      return res.status(503).json({
        error: {
          message: 'No upstream model configured. Set up a model endpoint in Settings.',
          type: 'server_error',
          code: 'no_upstream',
        }
      });
    }

    // Build upstream request
    const upstreamUrl = `${modelCfg.endpointUrl.replace(/\/$/, '')}/chat/completions`;
    const upstreamHeaders = { 'Content-Type': 'application/json' };
    if (modelCfg.apiKey) {
      upstreamHeaders['Authorization'] = `Bearer ${modelCfg.apiKey}`;
    }

    // Override model name if configured
    const upstreamBody = { ...requestBody };
    if (modelCfg.modelName) {
      upstreamBody.model = modelCfg.modelName;
    }

    // Log flagged requests but still allow through
    if (action === 'flagged') {
      logger.warn('Proxy request flagged (allowing through)', {
        threats: detectedThreats.map(t => t.type),
        userId: req.user?.id,
      });
    }

    // Step 4: Forward to upstream
    if (isStreaming) {
      await handleStreaming(req, res, upstreamUrl, upstreamHeaders, upstreamBody, {
        startTime, userText, scores, action, detectedThreats,
      });
    } else {
      await handleNonStreaming(req, res, upstreamUrl, upstreamHeaders, upstreamBody, {
        startTime, userText, scores, action, detectedThreats,
      });
    }
  }
);

/**
 * Handle non-streaming proxy request.
 */
async function handleNonStreaming(req, res, upstreamUrl, headers, body, ctx) {
  try {
    const response = await axios.post(upstreamUrl, body, {
      headers,
      timeout: 120000,
      httpAgent: upstreamHttpAgent,
      httpsAgent: upstreamHttpsAgent,
    });

    const latencyMs = Date.now() - ctx.startTime;

    // Log the request
    await logProxyRequest({
      userText: ctx.userText,
      scores: ctx.scores,
      action: ctx.action,
      detectedThreats: ctx.detectedThreats,
      latencyMs,
      userId: req.user?.id,
      clientIp: req.ip,
    });

    logger.info('Proxy request completed', {
      action: ctx.action,
      latencyMs,
      model: response.data?.model,
      userId: req.user?.id,
    });

    res.json(response.data);
  } catch (error) {
    const latencyMs = Date.now() - ctx.startTime;
    await logProxyRequest({
      userText: ctx.userText,
      scores: ctx.scores,
      action: 'error',
      detectedThreats: ctx.detectedThreats,
      latencyMs,
      userId: req.user?.id,
      clientIp: req.ip,
    });

    const status = error.response?.status || 502;
    const rawMessage = error.response?.data?.error?.message
      || (error.code === 'ECONNREFUSED' ? 'Upstream model service unavailable' : 'Upstream request failed');
    const message = secretMasker.mask(rawMessage).masked;

    logger.error('Proxy upstream error', { error: message, status, userId: req.user?.id });

    res.status(status).json({
      error: {
        message: `Upstream error: ${message}`,
        type: 'upstream_error',
        code: error.code || 'upstream_failed',
      }
    });
  }
}

// How often (in accumulated characters) to run mid-stream egress checks
const STREAM_EGRESS_CHECK_INTERVAL = 2000;

/**
 * Handle streaming (SSE) proxy request.
 * Uses a rolling window for egress checks to avoid O(n²) memory growth.
 * If sensitive data is detected mid-stream, injects a warning event and
 * terminates the stream to prevent further leakage.
 */
async function handleStreaming(req, res, upstreamUrl, headers, body, ctx) {
  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  let totalContentLength = 0;
  let recentContent = '';       // Rolling window for egress checks (last ~4000 chars)
  let lastCheckedLength = 0;
  let streamTerminated = false;

  try {
    const response = await axios.post(upstreamUrl, body, {
      headers,
      timeout: 120000,
      responseType: 'stream',
      httpAgent: upstreamHttpAgent,
      httpsAgent: upstreamHttpsAgent,
    });

    response.data.on('data', (chunk) => {
      if (streamTerminated) return;

      const text = chunk.toString();
      // Write chunk to client immediately
      res.write(text);

      // Parse SSE data lines to accumulate content deltas
      const lines = text.split('\n');
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        try {
          const parsed = JSON.parse(data);
          const delta = parsed.choices?.[0]?.delta?.content;
          if (delta) {
            totalContentLength += delta.length;
            recentContent += delta;
            // Keep rolling window to ~4000 chars to bound memory
            if (recentContent.length > 6000) {
              recentContent = recentContent.slice(-4000);
            }
          }
        } catch {
          // Not valid JSON, skip
        }
      }

      // Periodic mid-stream egress check on rolling window
      if (totalContentLength - lastCheckedLength >= STREAM_EGRESS_CHECK_INTERVAL) {
        lastCheckedLength = totalContentLength;
        const midCheck = secretMasker.mask(recentContent);
        if (midCheck.detected.length > 0) {
          streamTerminated = true;
          logger.warn('Proxy stream egress: sensitive data detected mid-stream, terminating', {
            detectedCount: midCheck.detected.length,
            detectedTypes: midCheck.detected.map(d => d.type),
            userId: req.user?.id,
          });

          // Inject warning SSE event and terminate
          try {
            const warning = {
              id: `pooguard-egress-${Date.now()}`,
              object: 'chat.completion.chunk',
              choices: [{
                index: 0,
                delta: { content: '\n\n[PooGuard: Response terminated — sensitive data detected in output]' },
                finish_reason: 'content_filter',
              }],
            };
            res.write(`data: ${JSON.stringify(warning)}\n\n`);
            res.write('data: [DONE]\n\n');
          } catch { /* response may already be closed */ }

          // Kill upstream — clean up listeners first to prevent leaks
          recentContent = '';
          if (!response.data.destroyed) {
            response.data.removeAllListeners();
            response.data.destroy();
          }
          res.end();

          // Publish alert
          publishEvent(CHANNELS.ALERTS, {
            type: 'egress_stream',
            message: 'Sensitive data detected in streaming response — stream terminated',
            detectedCount: midCheck.detected.length,
            userId: req.user?.id,
            timestamp: new Date().toISOString(),
          }).catch(() => {});
        }
      }
    });

    response.data.on('end', async () => {
      if (streamTerminated) return;
      res.end();

      const latencyMs = Date.now() - ctx.startTime;

      // Log the completed stream
      await logProxyRequest({
        userText: ctx.userText,
        scores: ctx.scores,
        action: ctx.action,
        detectedThreats: ctx.detectedThreats,
        latencyMs,
        userId: req.user?.id,
        clientIp: req.ip,
      });

      // Final post-stream egress analysis on recent content window
      if (recentContent.length > 0) {
        const masked = secretMasker.mask(recentContent);
        if (masked.detected.length > 0) {
          logger.warn('Proxy stream egress: sensitive data detected in completed response', {
            detectedCount: masked.detected.length,
            detectedTypes: masked.detected.map(d => d.type),
            userId: req.user?.id,
          });

          publishEvent(CHANNELS.ALERTS, {
            type: 'egress_stream',
            message: 'Sensitive data detected in completed streaming response',
            detectedCount: masked.detected.length,
            userId: req.user?.id,
            timestamp: new Date().toISOString(),
          }).catch(() => {});
        }
      }

      // Release references for GC
      recentContent = '';

      logger.info('Proxy stream completed', {
        action: ctx.action,
        latencyMs,
        responseChars: totalContentLength,
        userId: req.user?.id,
      });
    });

    response.data.on('error', (err) => {
      if (streamTerminated) return;
      logger.error('Proxy stream error from upstream', { error: err.message });
      // Try to send an error event before closing
      try {
        res.write(`data: ${JSON.stringify({ error: { message: 'Upstream stream error', type: 'upstream_error' } })}\n\n`);
      } catch { /* response may already be closed */ }
      res.end();
    });

    // Handle client disconnect — clean up to prevent memory leaks
    req.on('close', () => {
      recentContent = '';
      if (!response.data.destroyed) {
        response.data.removeAllListeners();
        response.data.destroy();
      }
    });

  } catch (error) {
    const rawMessage = error.code === 'ECONNREFUSED'
      ? 'Upstream model service unavailable'
      : error.response?.data ? 'Upstream error' : 'Upstream request failed';
    const message = secretMasker.mask(rawMessage).masked;

    logger.error('Proxy stream connection failed', { error: message, userId: req.user?.id });

    // If headers already sent, write SSE error
    if (res.headersSent) {
      try {
        res.write(`data: ${JSON.stringify({ error: { message, type: 'upstream_error' } })}\n\n`);
      } catch { /* ignore */ }
      res.end();
    } else {
      res.status(502).json({
        error: { message: `Upstream error: ${message}`, type: 'upstream_error', code: 'upstream_failed' }
      });
    }
  }
}

/**
 * GET /v1/models
 * Proxy the model list from the configured upstream endpoint.
 */
router.get('/models',
  proxyAuth,
  async (req, res) => {
    try {
      const modelCfg = await getModelConfig();

      if (!modelCfg || !modelCfg.endpointUrl) {
        return res.json({
          object: 'list',
          data: [],
        });
      }

      const headers = {};
      if (modelCfg.apiKey) {
        headers['Authorization'] = `Bearer ${modelCfg.apiKey}`;
      }

      const response = await axios.get(
        `${modelCfg.endpointUrl.replace(/\/$/, '')}/models`,
        { headers, timeout: 5000 }
      );

      res.json(response.data);
    } catch (error) {
      logger.error('Proxy model list error', { error: error.message });
      res.json({ object: 'list', data: [] });
    }
  }
);

module.exports = { router, initDb };
