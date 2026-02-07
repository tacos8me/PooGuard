const express = require('express');
const axios = require('axios');
const { body, validationResult } = require('express-validator');
const { analyzeTextCached, analyzeBatch } = require('../services/modelService');
const { analyzeOutput, shouldBlockOutput } = require('../services/outputFilter');
const { publishEvent, CHANNELS } = require('../services/redis');
const logger = require('../services/logger');
const config = require('../config');
const { authMiddleware, optionalAuth } = require('../middleware/auth');
const { userAnalyzeLimiter, userBatchAnalyzeLimiter } = require('../middleware/rateLimiter');
const secretMasker = require('../utils/secretMasker');
const sessionTracker = require('../services/sessionTracker');
const { auditMiddleware, ACTION_TYPES, createAuditLog } = require('../middleware/auditLog');
const { encrypt, decrypt } = require('../utils/encryption');
const analysisQueue = require('../services/analysisQueue');
const { getCircuitState } = require('../services/modelService');

const router = express.Router();
let db = null;

const { initDb: initAuditDb } = require('../middleware/auditLog');

const initDb = (knex) => {
  db = knex;
  initAuditDb(knex);
};

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Valid actions for firewall configuration
const VALID_ACTIONS = ['block', 'flag', 'allow'];

const VALID_PROVIDER_TYPES = ['none', 'openai_compatible'];

let _configCache = null;
let _configCacheTime = 0;
const CONFIG_CACHE_TTL = 10000;

const clearConfigCache = () => {
  _configCache = null;
  _configCacheTime = 0;
};

const getFirewallConfig = async () => {
  if (_configCache && (Date.now() - _configCacheTime) < CONFIG_CACHE_TTL) {
    return _configCache;
  }

  const configRow = await db('firewall_config').first();
  let result;
  if (configRow) {
    result = {
      thresholds: {
        promptInjection: parseFloat(configRow.threshold_prompt_injection),
        jailbreak: parseFloat(configRow.threshold_jailbreak),
        pii: parseFloat(configRow.threshold_pii)
      },
      actions: {
        promptInjection: configRow.action_prompt_injection,
        jailbreak: configRow.action_jailbreak,
        pii: configRow.action_pii
      },
      modelConfig: {
        providerType: configRow.model_provider_type || 'none',
        endpointUrl: configRow.model_endpoint_url || '',
        hasApiKey: !!configRow.model_api_key_encrypted,
        modelName: configRow.model_name || '',
      },
      safeguardModel: configRow.safeguard_model || '20b',
      dataRetentionDays: configRow.data_retention_days ?? 90,
      failMode: configRow.fail_mode || 'open',
      cacheEnabled: configRow.cache_enabled ?? true,
      cacheTtlSeconds: configRow.cache_ttl_seconds ?? 300,
      analysisMode: configRow.analysis_mode || 'sync',
      _raw: configRow,
    };
  } else {
    result = {
      thresholds: config.firewall.defaultThresholds,
      actions: {
        promptInjection: 'block',
        jailbreak: 'block',
        pii: 'flag'
      },
      modelConfig: {
        providerType: 'none',
        endpointUrl: '',
        hasApiKey: false,
        modelName: '',
      },
      safeguardModel: '20b',
      dataRetentionDays: 90,
      failMode: 'open',
      cacheEnabled: true,
      cacheTtlSeconds: 300,
      analysisMode: 'sync',
      _raw: null,
    };
  }

  _configCache = result;
  _configCacheTime = Date.now();
  return result;
};

/**
 * Get the raw model config with decrypted API key (for internal use by proxy).
 * Never expose this to the frontend — use getFirewallConfig() for that.
 */
const getModelConfig = async () => {
  const cachedConfig = await getFirewallConfig();
  const configRow = cachedConfig._raw;
  if (!configRow || configRow.model_provider_type === 'none') {
    return null;
  }
  return {
    providerType: configRow.model_provider_type,
    endpointUrl: configRow.model_endpoint_url,
    apiKey: decrypt(configRow.model_api_key_encrypted),
    modelName: configRow.model_name,
  };
};

const determineAction = (scores, firewallConfig) => {
  const { thresholds, actions } = firewallConfig;
  const detectedThreats = [];

  if (scores.prompt_injection_score >= thresholds.promptInjection) {
    detectedThreats.push({ type: 'prompt_injection', score: scores.prompt_injection_score, action: actions.promptInjection });
  }
  if (scores.jailbreak_score >= thresholds.jailbreak) {
    detectedThreats.push({ type: 'jailbreak', score: scores.jailbreak_score, action: actions.jailbreak });
  }
  if (scores.pii_score >= thresholds.pii) {
    detectedThreats.push({ type: 'pii', score: scores.pii_score, action: actions.pii });
  }

  if (detectedThreats.some(t => t.action === 'block')) {
    return { action: 'blocked', detectedThreats };
  }
  if (detectedThreats.some(t => t.action === 'flag')) {
    return { action: 'flagged', detectedThreats };
  }
  return { action: 'allowed', detectedThreats };
};

router.post('/analyze',
  optionalAuth,              // Sets req.user if valid token provided, allows anonymous
  userAnalyzeLimiter,        // Tiered rate limiter: admin 100/min, viewer 30/min, anon 15/min
  body('text').isString().isLength({ min: 1, max: 50000 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { text } = req.body;
    const startTime = Date.now();
    const isAuthenticated = !!req.user;
    const isAdmin = req.user?.role === 'admin';
    const noCache = isAdmin && req.query.nocache === 'true';

    try {
      const firewallConfig = await getFirewallConfig();

      // Async mode: enqueue and return immediately
      if (firewallConfig.analysisMode === 'async') {
        // Fail-closed check: reject if model service is down and fail mode is closed
        if (firewallConfig.failMode === 'closed' && getCircuitState() !== 'closed') {
          logger.warn('Fail-closed: blocking async request due to model service circuit breaker open', {
            circuitState: getCircuitState(),
            userId: req.user?.id || null,
            clientIp: req.ip,
          });
          return res.status(503).json({
            action: 'blocked',
            detectedThreats: ['model_unavailable'],
            reason: 'Fail-closed mode: requests blocked while model service is unavailable',
          });
        }

        const requestId = await analysisQueue.enqueue(text, {
          userId: req.user?.id,
          clientIp: req.ip,
          isAuthenticated,
          cacheOptions: {
            cacheEnabled: firewallConfig.cacheEnabled,
            cacheTtlSeconds: firewallConfig.cacheTtlSeconds,
            modelVariant: firewallConfig.safeguardModel,
            noCache,
          },
        });

        logger.info('Firewall analysis enqueued (async mode)', {
          requestId,
          isAuthenticated,
          userId: req.user?.id || null,
        });

        return res.status(202).json({
          status: 'pending',
          requestId,
          message: 'Analysis queued. Poll GET /api/firewall/result/:requestId for results.',
        });
      }

      const analysisResult = await analyzeTextCached(text, {
        cacheEnabled: firewallConfig.cacheEnabled,
        cacheTtlSeconds: firewallConfig.cacheTtlSeconds,
        modelVariant: firewallConfig.safeguardModel,
        noCache,
      });

      const { action, detectedThreats } = determineAction(analysisResult, firewallConfig);
      const latencyMs = Date.now() - startTime;

      // Mask any secrets in the input text before logging
      const maskedInput = secretMasker.mask(text);

      const logEntry = {
        input_text: maskedInput.masked.substring(0, 1000),
        threat_scores: {
          prompt_injection: analysisResult.prompt_injection_score,
          jailbreak: analysisResult.jailbreak_score,
          pii: analysisResult.pii_score
        },
        action,
        latency_ms: latencyMs,
        user_id: req.user?.id || null,
        is_authenticated: isAuthenticated,
        client_ip: req.ip
      };

      const [log] = await db('request_logs').insert(logEntry).returning('*');

      const event = {
        id: log.id,
        timestamp: log.timestamp,
        action,
        threatScores: logEntry.threat_scores,
        detectedThreats,
        latencyMs,
        isAuthenticated,
        input_text: maskedInput.masked.substring(0, 100), // Short preview only
        secrets_detected: maskedInput.detected.length > 0
      };

      await publishEvent(CHANNELS.FIREWALL_EVENTS, event);

      // Update session threat tracking
      let sessionInfo = null;
      try {
        sessionInfo = await sessionTracker.updateSessionThreat(
          req,
          logEntry.threat_scores,
          action,
          detectedThreats
        );

        // Add session info to event if threshold exceeded
        if (sessionInfo.thresholdExceeded) {
          event.sessionThreatAlert = {
            sessionId: sessionInfo.sessionId,
            cumulativeScore: sessionInfo.cumulativeScore,
            alertTriggered: sessionInfo.alertTriggered,
          };
        }
      } catch (sessionError) {
        logger.warn('Session tracking failed', { error: sessionError.message });
      }

      // Log differently based on authentication status
      if (isAuthenticated) {
        logger.info('Firewall analysis (authenticated)', {
          action,
          latencyMs,
          threatsDetected: detectedThreats.length,
          userId: req.user.id,
          userEmail: req.user.email
        });
      } else {
        logger.info('Firewall analysis (anonymous)', {
          action,
          latencyMs,
          threatsDetected: detectedThreats.length,
          clientIp: req.ip
        });
      }

      // Build response — strip numeric scores for anonymous callers to
      // prevent attackers calibrating bypass payloads against the scoring oracle.
      const response = { id: log.id, action, latencyMs, cache_hit: !!analysisResult.cache_hit };

      if (isAuthenticated) {
        response.threatScores = logEntry.threat_scores;
        response.detectedThreats = detectedThreats;

        if (sessionInfo) {
          response.sessionThreat = {
            sessionId: sessionInfo.sessionId,
            cumulativeScore: sessionInfo.cumulativeScore,
            requestThreatScore: sessionInfo.requestThreatScore,
            thresholdExceeded: sessionInfo.thresholdExceeded,
          };
        }
      } else {
        // Anonymous: only reveal threat type names, not scores
        response.detectedThreats = detectedThreats.map(t => ({ type: t.type }));
      }

      res.json(response);
    } catch (error) {
      logger.error('Firewall analysis error', {
        error: error.message,
        isAuthenticated,
        userId: req.user?.id || null,
        clientIp: req.ip
      });

      // Check fail mode: if closed, block the request instead of returning 500
      const isModelUnavailable = error.message === 'Model service unavailable'
        || error.message === 'Model service not available';

      if (isModelUnavailable) {
        try {
          const fwConfig = await getFirewallConfig();
          if (fwConfig.failMode === 'closed') {
            logger.warn('Fail-closed: blocking request due to model unavailability', {
              userId: req.user?.id || null,
              clientIp: req.ip,
            });
            return res.status(503).json({
              action: 'blocked',
              detectedThreats: ['model_unavailable'],
              reason: 'Fail-closed mode: requests blocked while model service is unavailable',
            });
          }
        } catch (configError) {
          logger.error('Failed to read fail mode config', { error: configError.message });
        }
      }

      res.status(500).json({ error: 'Analysis failed' });
    }
  }
);

/**
 * Get result of an async analysis request.
 * Returns 200 with result if complete, 202 if still pending, 404 if not found.
 */
router.get('/result/:requestId',
  optionalAuth,
  async (req, res) => {
    const { requestId } = req.params;

    // Basic UUID format validation
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(requestId)) {
      return res.status(400).json({ error: 'Invalid request ID format' });
    }

    try {
      const result = await analysisQueue.getResult(requestId);

      if (!result) {
        return res.status(202).json({
          status: 'pending',
          requestId,
          message: 'Analysis is still in progress or has not been queued.',
        });
      }

      if (result.status === 'error') {
        return res.status(500).json({
          status: 'error',
          requestId,
          error: result.error,
        });
      }

      res.json(result);
    } catch (error) {
      logger.error('Get async result error', { error: error.message, requestId });
      res.status(500).json({ error: 'Failed to retrieve result' });
    }
  }
);

/**
 * Batch analysis endpoint
 * Analyzes multiple texts in a single request for improved efficiency
 */
router.post('/analyze/batch',
  optionalAuth,              // Sets req.user if valid token provided, allows anonymous
  userBatchAnalyzeLimiter,   // Tiered batch rate limiter: admin 100/min, viewer 30/min, anon 15/min
  body('texts')
    .isArray({ min: 1, max: 20 })
    .withMessage('texts must be an array with 1-20 items'),
  body('texts.*')
    .isString()
    .isLength({ min: 1, max: 50000 })
    .withMessage('Each text must be a string between 1 and 50000 characters'),
  body('maxBatchSize')
    .optional()
    .isInt({ min: 1, max: 20 })
    .withMessage('maxBatchSize must be between 1 and 20'),
  validateRequest,
  async (req, res) => {
    const { texts, maxBatchSize = 10 } = req.body;
    const startTime = Date.now();
    const isAuthenticated = !!req.user;

    try {
      const [firewallConfig, batchResult] = await Promise.all([
        getFirewallConfig(),
        analyzeBatch(texts, maxBatchSize)
      ]);

      const latencyMs = Date.now() - startTime;

      // Process each result with firewall config to determine actions.
      // Strip numeric scores for anonymous callers (same as /analyze).
      const processedResults = batchResult.results.map((item) => {
        if (!item.success || !item.result) {
          return {
            index: item.index,
            success: false,
            error: item.error || 'Analysis failed'
          };
        }

        const { action, detectedThreats } = determineAction(item.result, firewallConfig);

        const result = {
          index: item.index,
          success: true,
          action,
          detectedThreats: isAuthenticated
            ? detectedThreats
            : detectedThreats.map(t => ({ type: t.type })),
          processingTimeMs: item.result.processing_time_ms
        };

        if (isAuthenticated) {
          result.threatScores = {
            prompt_injection: item.result.prompt_injection_score,
            jailbreak: item.result.jailbreak_score,
            pii: item.result.pii_score
          };
        }

        return result;
      });

      // Log batch request (don't log individual texts for privacy)
      const batchLogEntry = {
        input_text: `[BATCH: ${texts.length} texts]`,
        threat_scores: {
          prompt_injection: 0,
          jailbreak: 0,
          pii: 0
        },
        action: 'batch',
        latency_ms: latencyMs,
        user_id: req.user?.id || null,
        is_authenticated: isAuthenticated,
        client_ip: req.ip
      };

      const [log] = await db('request_logs').insert(batchLogEntry).returning('*');

      // Publish batch event
      const event = {
        id: log.id,
        timestamp: log.timestamp,
        action: 'batch',
        batchSize: texts.length,
        successCount: batchResult.success_count,
        failureCount: batchResult.failure_count,
        latencyMs,
        isAuthenticated
      };

      await publishEvent(CHANNELS.FIREWALL_EVENTS, event);

      // Log based on authentication status
      if (isAuthenticated) {
        logger.info('Firewall batch analysis (authenticated)', {
          batchSize: texts.length,
          successCount: batchResult.success_count,
          failureCount: batchResult.failure_count,
          latencyMs,
          userId: req.user.id,
          userEmail: req.user.email
        });
      } else {
        logger.info('Firewall batch analysis (anonymous)', {
          batchSize: texts.length,
          successCount: batchResult.success_count,
          failureCount: batchResult.failure_count,
          latencyMs,
          clientIp: req.ip
        });
      }

      res.json({
        id: log.id,
        results: processedResults,
        totalCount: batchResult.total_count,
        successCount: batchResult.success_count,
        failureCount: batchResult.failure_count,
        processingTimeMs: batchResult.processing_time_ms,
        latencyMs
      });
    } catch (error) {
      logger.error('Firewall batch analysis error', {
        error: error.message,
        batchSize: texts.length,
        isAuthenticated,
        userId: req.user?.id || null,
        clientIp: req.ip
      });

      // Return appropriate error status based on error type
      const isModelDown = error.message === 'Model service unavailable'
        || error.message === 'Model service not available';
      if (isModelDown) {
        try {
          const fwConfig = await getFirewallConfig();
          if (fwConfig.failMode === 'closed') {
            logger.warn('Fail-closed: blocking batch request due to model unavailability');
            return res.status(503).json({
              action: 'blocked',
              detectedThreats: ['model_unavailable'],
              reason: 'Fail-closed mode: requests blocked while model service is unavailable',
            });
          }
        } catch (configError) {
          logger.error('Failed to read fail mode config', { error: configError.message });
        }
        return res.status(503).json({ error: 'Model service unavailable' });
      }

      res.status(500).json({ error: 'Batch analysis failed' });
    }
  }
);

router.get('/config',
  authMiddleware,  // Require authentication - config reveals detection thresholds
  async (req, res) => {
    try {
      const firewallConfig = await getFirewallConfig();
      logger.info('Firewall config accessed', { userId: req.user.id });
      const { _raw, ...clientConfig } = firewallConfig;
      res.json(clientConfig);
    } catch (error) {
      logger.error('Get config error', { error: error.message, userId: req.user?.id });
      res.status(500).json({ error: 'Failed to get config' });
    }
  }
);

router.put('/config',
  require('../middleware/auth').authMiddleware,
  require('../middleware/auth').requireAdmin,
  body('thresholds').isObject().withMessage('Thresholds must be an object'),
  body('thresholds.promptInjection')
    .isFloat({ min: 0, max: 1 })
    .withMessage('promptInjection threshold must be between 0 and 1'),
  body('thresholds.jailbreak')
    .isFloat({ min: 0, max: 1 })
    .withMessage('jailbreak threshold must be between 0 and 1'),
  body('thresholds.pii')
    .isFloat({ min: 0, max: 1 })
    .withMessage('pii threshold must be between 0 and 1'),
  body('actions').isObject().withMessage('Actions must be an object'),
  body('actions.promptInjection')
    .isIn(VALID_ACTIONS)
    .withMessage('promptInjection action must be block, flag, or allow'),
  body('actions.jailbreak')
    .isIn(VALID_ACTIONS)
    .withMessage('jailbreak action must be block, flag, or allow'),
  body('actions.pii')
    .isIn(VALID_ACTIONS)
    .withMessage('pii action must be block, flag, or allow'),
  validateRequest,
  async (req, res) => {
    try {
      const { thresholds, actions, modelConfig } = req.body;

      // Get old config for audit logging
      const oldConfig = await getFirewallConfig();

      // Read existing row to preserve model config columns if not being updated
      const existingRow = await db('firewall_config').first();

      // Build the insert payload
      const VALID_SAFEGUARD_MODELS = ['20b', '120b'];

      const insertData = {
        threshold_prompt_injection: thresholds.promptInjection,
        threshold_jailbreak: thresholds.jailbreak,
        threshold_pii: thresholds.pii,
        action_prompt_injection: actions.promptInjection,
        action_jailbreak: actions.jailbreak,
        action_pii: actions.pii,
        // Preserve existing model config by default
        model_provider_type: existingRow?.model_provider_type || 'none',
        model_endpoint_url: existingRow?.model_endpoint_url || null,
        model_api_key_encrypted: existingRow?.model_api_key_encrypted || null,
        model_name: existingRow?.model_name || null,
        safeguard_model: existingRow?.safeguard_model || '20b',
        data_retention_days: existingRow?.data_retention_days ?? 90,
        fail_mode: existingRow?.fail_mode || 'open',
        cache_enabled: existingRow?.cache_enabled ?? true,
        cache_ttl_seconds: existingRow?.cache_ttl_seconds ?? 300,
        analysis_mode: existingRow?.analysis_mode || 'sync',
      };

      // Apply analysis mode update if provided
      const VALID_ANALYSIS_MODES = ['sync', 'async'];
      if (req.body.analysisMode !== undefined) {
        if (!VALID_ANALYSIS_MODES.includes(req.body.analysisMode)) {
          return res.status(400).json({ error: 'Invalid analysisMode. Must be: sync, async' });
        }
        insertData.analysis_mode = req.body.analysisMode;
      }

      // Apply cache config updates if provided
      if (req.body.cacheEnabled !== undefined) {
        insertData.cache_enabled = !!req.body.cacheEnabled;
      }
      if (req.body.cacheTtlSeconds !== undefined) {
        const ttl = parseInt(req.body.cacheTtlSeconds, 10);
        if (isNaN(ttl) || ttl < 0 || ttl > 3600) {
          return res.status(400).json({ error: 'cacheTtlSeconds must be between 0 and 3600' });
        }
        insertData.cache_ttl_seconds = ttl;
      }

      // Apply data retention / fail mode updates if provided
      if (req.body.dataRetentionDays !== undefined) {
        const days = parseInt(req.body.dataRetentionDays, 10);
        if (isNaN(days) || days < 0 || days > 3650) {
          return res.status(400).json({ error: 'dataRetentionDays must be between 0 and 3650' });
        }
        insertData.data_retention_days = days;
      }

      const VALID_FAIL_MODES = ['open', 'closed'];
      if (req.body.failMode !== undefined) {
        if (!VALID_FAIL_MODES.includes(req.body.failMode)) {
          return res.status(400).json({ error: 'Invalid failMode. Must be: open, closed' });
        }
        insertData.fail_mode = req.body.failMode;
      }

      // Apply model config updates if provided
      if (modelConfig) {
        if (modelConfig.providerType && !VALID_PROVIDER_TYPES.includes(modelConfig.providerType)) {
          return res.status(400).json({ error: 'Invalid providerType. Must be: none, openai_compatible' });
        }

        if (modelConfig.providerType) {
          insertData.model_provider_type = modelConfig.providerType;
        }
        if (modelConfig.endpointUrl !== undefined) {
          insertData.model_endpoint_url = modelConfig.endpointUrl || null;
        }
        if (modelConfig.modelName !== undefined) {
          insertData.model_name = modelConfig.modelName || null;
        }

        // Handle API key: "__UNCHANGED__" preserves existing, empty clears, new value encrypts
        if (modelConfig.apiKey !== undefined && modelConfig.apiKey !== '__UNCHANGED__') {
          insertData.model_api_key_encrypted = modelConfig.apiKey ? encrypt(modelConfig.apiKey) : null;
        }
      }

      // Handle safeguard model selection
      if (req.body.safeguardModel) {
        if (!VALID_SAFEGUARD_MODELS.includes(req.body.safeguardModel)) {
          return res.status(400).json({ error: 'Invalid safeguardModel. Must be: 20b, 120b' });
        }
        insertData.safeguard_model = req.body.safeguardModel;
      }

      await db.transaction(async (trx) => {
        await trx('firewall_config').del();
        await trx('firewall_config').insert(insertData);
      });

      clearConfigCache();
      const newConfig = await getFirewallConfig();

      // Notify model-service if safeguard model changed
      if (oldConfig.safeguardModel !== newConfig.safeguardModel) {
        try {
          await axios.post(`${config.modelService.url}/config`, {
            safeguard_model: newConfig.safeguardModel,
          }, { timeout: 30000 });
          logger.info('Model-service notified of safeguard model change', {
            from: oldConfig.safeguardModel,
            to: newConfig.safeguardModel,
          });
        } catch (err) {
          logger.warn('Failed to notify model-service of safeguard model change', {
            error: err.message,
          });
        }
      }

      // Create audit log entry (strip internal _raw from logged values)
      const { _raw: _oldRaw, ...oldConfigClean } = oldConfig;
      const { _raw: _newRaw, ...newConfigClean } = newConfig;
      await createAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: ACTION_TYPES.CONFIG_UPDATE,
        resource: 'firewall_config',
        resourceId: null,
        oldValue: oldConfigClean,
        newValue: newConfigClean,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      logger.info('Firewall config updated', { userId: req.user.id });
      res.json({ success: true });
    } catch (error) {
      logger.error('Update config error', { error: error.message });
      res.status(500).json({ error: 'Failed to update config' });
    }
  }
);

/**
 * Output analysis endpoint
 * Analyzes LLM output for sensitive data before returning to users
 *
 * This endpoint detects:
 * - PII (SSN, credit cards, emails, phone numbers)
 * - System prompt disclosure patterns
 * - API keys and secrets
 */
router.post('/analyze-output',
  authMiddleware,      // Require authentication for output analysis
  userAnalyzeLimiter,  // Tiered rate limiter: admin 100/min, viewer 30/min, anon 15/min
  body('text')
    .isString()
    .isLength({ min: 1, max: 100000 })
    .withMessage('Text must be a string between 1 and 100000 characters'),
  validateRequest,
  async (req, res) => {
    const { text } = req.body;
    const startTime = Date.now();

    try {
      // Call model service to analyze output
      const analysis = await analyzeOutput(text);

      // Determine action based on analysis and default config
      const decision = shouldBlockOutput(analysis);

      const latencyMs = Date.now() - startTime;

      // Log the output analysis
      const logEntry = {
        input_text: `[OUTPUT ANALYSIS: ${text.length} chars]`,
        threat_scores: {
          prompt_injection: 0,
          jailbreak: 0,
          pii: analysis.scores.pii_score || 0
        },
        action: decision.action,
        latency_ms: latencyMs,
        user_id: req.user?.id || null,
        is_authenticated: true,
        client_ip: req.ip
      };

      const [log] = await db('request_logs').insert(logEntry).returning('*');

      // Publish event for real-time monitoring
      const event = {
        id: log.id,
        timestamp: log.timestamp,
        type: 'output_analysis',
        action: decision.action,
        safe: analysis.safe,
        detectedCount: analysis.detected?.length || 0,
        scores: analysis.scores,
        latencyMs
      };

      await publishEvent(CHANNELS.FIREWALL_EVENTS, event);

      logger.info('Output analysis completed', {
        action: decision.action,
        safe: analysis.safe,
        detectedCount: analysis.detected?.length || 0,
        latencyMs,
        userId: req.user.id
      });

      res.json({
        id: log.id,
        safe: analysis.safe,
        action: decision.action,
        blocked: decision.blocked,
        sanitized: decision.sanitized,
        detected: analysis.detected,
        sanitizedOutput: decision.sanitizedOutput,
        scores: analysis.scores,
        reasons: decision.reasons,
        latencyMs,
        processingTimeMs: analysis.processing_time_ms
      });
    } catch (error) {
      logger.error('Output analysis error', {
        error: error.message,
        userId: req.user?.id || null,
        clientIp: req.ip
      });

      // Return appropriate error status based on error type
      if (error.message === 'Model service unavailable' || error.message === 'Model service not available') {
        return res.status(503).json({ error: 'Model service unavailable' });
      }

      res.status(500).json({ error: 'Output analysis failed' });
    }
  }
);

// ============================================================
// Model Discovery & Test Endpoints
// ============================================================

/**
 * Discover available models at an OAI-compatible endpoint.
 * Used by Settings UI before saving config.
 */
router.post('/model/discover',
  authMiddleware,
  require('../middleware/auth').requireAdmin,
  body('endpointUrl').isString().isURL({ require_tld: false }).withMessage('Valid endpoint URL required'),
  body('apiKey').optional().isString(),
  validateRequest,
  async (req, res) => {
    try {
      const { endpointUrl, apiKey } = req.body;
      const headers = {};

      // Use provided API key, or fall back to the saved (encrypted) key
      let resolvedKey = apiKey;
      if (!resolvedKey) {
        const savedConfig = await getModelConfig();
        if (savedConfig?.apiKey) {
          resolvedKey = savedConfig.apiKey;
        }
      }
      if (resolvedKey) {
        headers['Authorization'] = `Bearer ${resolvedKey}`;
      }

      const response = await axios.get(`${endpointUrl.replace(/\/$/, '')}/models`, {
        headers,
        timeout: 5000,
      });

      const models = (response.data.data || []).map(m => m.id).filter(Boolean);

      logger.info('Model discovery completed', { endpointUrl, modelsFound: models.length, userId: req.user.id });
      res.json({ models });
    } catch (error) {
      const message = error.code === 'ECONNREFUSED'
        ? 'Connection refused — is the endpoint running?'
        : error.code === 'ECONNABORTED'
          ? 'Connection timed out'
          : error.code === 'ECONNRESET'
            ? 'Connection reset — check endpoint URL and network access'
            : error.response?.status === 401
              ? 'Unauthorized — check API key'
              : error.response?.status === 404
                ? 'Not found — check the endpoint URL includes /v1 if required'
                : error.message;

      logger.warn('Model discovery failed', { error: message, userId: req.user.id });
      res.status(400).json({ error: message });
    }
  }
);

/**
 * Test connection to an OAI-compatible endpoint.
 * Sends a minimal chat completion request to verify the endpoint works.
 */
router.post('/model/test',
  authMiddleware,
  require('../middleware/auth').requireAdmin,
  body('endpointUrl').isString().isURL({ require_tld: false }).withMessage('Valid endpoint URL required'),
  body('apiKey').optional().isString(),
  body('modelName').optional().isString(),
  validateRequest,
  async (req, res) => {
    try {
      const { endpointUrl, apiKey, modelName } = req.body;
      const headers = { 'Content-Type': 'application/json' };

      // Use provided API key, or fall back to the saved (encrypted) key
      let resolvedKey = apiKey;
      if (!resolvedKey) {
        const savedConfig = await getModelConfig();
        if (savedConfig?.apiKey) {
          resolvedKey = savedConfig.apiKey;
        }
      }
      if (resolvedKey) {
        headers['Authorization'] = `Bearer ${resolvedKey}`;
      }

      const startTime = Date.now();
      const response = await axios.post(
        `${endpointUrl.replace(/\/$/, '')}/chat/completions`,
        {
          model: modelName || 'test',
          messages: [{ role: 'user', content: 'ping' }],
          max_tokens: 1,
        },
        { headers, timeout: 10000 }
      );
      const latencyMs = Date.now() - startTime;

      const model = response.data?.model || modelName || 'unknown';

      logger.info('Model test succeeded', { endpointUrl, model, latencyMs, userId: req.user.id });
      res.json({ success: true, latencyMs, model });
    } catch (error) {
      const message = error.code === 'ECONNREFUSED'
        ? 'Connection refused'
        : error.code === 'ECONNABORTED'
          ? 'Connection timed out'
          : error.response?.status === 401
            ? 'Unauthorized — check API key'
            : error.response?.status === 404
              ? 'Model not found'
              : error.message;

      logger.warn('Model test failed', { error: message, userId: req.user.id });
      res.json({ success: false, error: message });
    }
  }
);

module.exports = { router, initDb, getFirewallConfig, getModelConfig, determineAction, clearConfigCache };
