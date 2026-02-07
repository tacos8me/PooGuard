/**
 * Tests for Proxy Routes (/v1/chat/completions, /v1/models)
 */
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const config = require('../../src/config');
const { analyzeTextCached } = require('../../src/services/modelService');
const { publishEvent } = require('../../src/services/redis');

// Mock rate limiter
jest.mock('../../src/middleware/rateLimiter', () => ({
  authLimiter: (req, res, next) => next(),
  registerLimiter: (req, res, next) => next(),
  analyzeLimiter: (req, res, next) => next(),
  batchLimiter: (req, res, next) => next(),
  batchAnalyzeLimiter: (req, res, next) => next(),
  generalLimiter: (req, res, next) => next(),
  userAnalyzeLimiter: (req, res, next) => next(),
  userBatchAnalyzeLimiter: (req, res, next) => next(),
  userGeneralLimiter: (req, res, next) => next(),
}));

// Mock sessionTracker (imported transitively by firewall.js)
jest.mock('../../src/services/sessionTracker', () => ({
  updateSessionThreat: jest.fn().mockResolvedValue({
    sessionId: 'user:1',
    cumulativeScore: 0.1,
    requestThreatScore: 0.1,
    thresholdExceeded: false,
    alertTriggered: false,
  }),
}));

// Mock auditLog (imported transitively by firewall.js)
jest.mock('../../src/middleware/auditLog', () => {
  const original = jest.requireActual('../../src/middleware/auditLog');
  return {
    ...original,
    createAuditLog: jest.fn().mockResolvedValue({ id: 1 }),
    initDb: jest.fn(),
  };
});

// Mock encryption (imported transitively by firewall.js)
jest.mock('../../src/utils/encryption', () => ({
  encrypt: jest.fn((v) => `encrypted:${v}`),
  decrypt: jest.fn((v) => v ? v.replace('encrypted:', '') : null),
}));

// Mock axios
jest.mock('axios');

const { router: proxyRouter, initDb: initProxyDb } = require('../../src/routes/proxy');
const { initDb: initFirewallDb } = require('../../src/routes/firewall');

// ── Helpers ─────────────────────────────────────────────────────────

function generateToken(payload, expiresIn = '15m') {
  return jwt.sign(payload, config.jwt.secret, { expiresIn });
}

const adminUser = { id: 1, email: 'admin@test.com', role: 'admin' };
const viewerUser = { id: 2, email: 'viewer@test.com', role: 'viewer' };
const adminToken = generateToken(adminUser);
const viewerToken = generateToken(viewerUser);

function createMockDb(options = {}) {
  const { firewallConfig = null } = options;
  let _firewallConfig = firewallConfig;
  const requestLogs = [];
  let logIdCounter = 1;

  const mockDb = jest.fn((tableName) => {
    if (tableName === 'firewall_config') {
      return {
        first: jest.fn().mockImplementation(() => Promise.resolve(_firewallConfig)),
        del: jest.fn().mockResolvedValue(1),
        insert: jest.fn().mockImplementation((data) => {
          _firewallConfig = { ...data, id: 1 };
          return Promise.resolve();
        }),
      };
    }
    if (tableName === 'request_logs') {
      return {
        insert: jest.fn().mockImplementation((data) => ({
          returning: jest.fn().mockImplementation(() => {
            const log = { ...data, id: logIdCounter++, timestamp: new Date().toISOString() };
            requestLogs.push(log);
            return Promise.resolve([log]);
          }),
        })),
      };
    }
    // Chainable mock for any other table (e.g. api_keys in proxyAuth)
    const chainable = {
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      whereNull: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
      insert: jest.fn().mockReturnThis(),
      returning: jest.fn().mockResolvedValue([]),
      del: jest.fn().mockResolvedValue(0),
      update: jest.fn().mockResolvedValue(0),
    };
    return chainable;
  });

  mockDb.transaction = jest.fn().mockImplementation(async (cb) => {
    const trx = jest.fn((_tableName) => ({
      del: jest.fn().mockResolvedValue(0),
      insert: jest.fn().mockResolvedValue(undefined),
    }));
    return cb(trx);
  });

  mockDb.setFirewallConfig = (cfg) => { _firewallConfig = cfg; };
  mockDb.reset = () => { _firewallConfig = firewallConfig; requestLogs.length = 0; logIdCounter = 1; };

  return mockDb;
}

function createApp(db) {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  initFirewallDb(db);
  initProxyDb(db);
  app.use('/v1', proxyRouter);
  app.use((err, req, res, _next) => {
    res.status(500).json({ error: 'Internal server error' });
  });
  return app;
}

// A valid OAI chat completion request body
const validChatBody = {
  model: 'gpt-4',
  messages: [
    { role: 'system', content: 'You are a helpful assistant.' },
    { role: 'user', content: 'Hello, how are you?' },
  ],
};

// Upstream OAI-like response
const upstreamResponse = {
  id: 'chatcmpl-abc123',
  object: 'chat.completion',
  model: 'gpt-4',
  choices: [
    {
      index: 0,
      message: { role: 'assistant', content: 'I am doing well!' },
      finish_reason: 'stop',
    },
  ],
};

// ── Test Suite ───────────────────────────────────────────────────────

describe('Proxy Routes', () => {
  let app;
  let mockDb;

  beforeEach(() => {
    // Default: model provider configured
    mockDb = createMockDb({
      firewallConfig: {
        threshold_prompt_injection: 0.7,
        threshold_jailbreak: 0.7,
        threshold_pii: 0.5,
        action_prompt_injection: 'block',
        action_jailbreak: 'block',
        action_pii: 'flag',
        model_provider_type: 'openai_compatible',
        model_endpoint_url: 'http://upstream:8080/v1',
        model_api_key_encrypted: 'encrypted:sk-upstream-key',
        model_name: 'gpt-4',
        safeguard_model: '20b',
        fail_mode: 'open',
        cache_enabled: true,
        cache_ttl_seconds: 300,
      },
    });
    app = createApp(mockDb);
    jest.clearAllMocks();

    // Default: safe text
    analyzeTextCached.mockResolvedValue({
      prompt_injection_score: 0.1,
      jailbreak_score: 0.1,
      pii_score: 0.1,
      processing_time_ms: 50,
    });

    // Default: successful upstream forward
    axios.post.mockResolvedValue({ data: upstreamResponse });
    axios.create = jest.fn().mockReturnValue(axios);
  });

  afterEach(() => {
    mockDb.reset();
  });

  // ── POST /v1/chat/completions ─────────────────────────────────────

  describe('POST /v1/chat/completions', () => {
    it('should require authentication', async () => {
      const res = await request(app)
        .post('/v1/chat/completions')
        .send(validChatBody)
        .expect(401);

      expect(res.body.error).toHaveProperty('code', 'missing_api_key');
    });

    it('should reject invalid auth tokens', async () => {
      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', 'Bearer bad-token')
        .send(validChatBody)
        .expect(401);

      expect(res.body.error).toHaveProperty('code', 'invalid_api_key');
    });

    it('should reject missing messages', async () => {
      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ model: 'gpt-4' })
        .expect(400);

      expect(res.body.error).toHaveProperty('code', 'invalid_messages');
    });

    it('should reject empty messages array', async () => {
      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ model: 'gpt-4', messages: [] })
        .expect(400);

      expect(res.body.error).toHaveProperty('code', 'invalid_messages');
    });

    it('should forward safe requests to upstream and return response', async () => {
      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(200);

      expect(res.body).toHaveProperty('id', 'chatcmpl-abc123');
      expect(res.body.choices[0].message.content).toBe('I am doing well!');
      // Verify analyzeTextCached was called with user text and cache options
      expect(analyzeTextCached).toHaveBeenCalledWith('Hello, how are you?', expect.objectContaining({
        cacheEnabled: true,
        cacheTtlSeconds: 300,
        modelVariant: '20b',
      }));
      // Verify upstream request was made
      expect(axios.post).toHaveBeenCalled();
    });

    it('should block requests with high threat scores', async () => {
      analyzeTextCached.mockResolvedValue({
        prompt_injection_score: 0.95,
        jailbreak_score: 0.1,
        pii_score: 0.1,
        processing_time_ms: 50,
      });

      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(400);

      expect(res.body.error).toHaveProperty('code', 'content_blocked');
      expect(res.body.error).toHaveProperty('type', 'content_filter');
      expect(res.body.error.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'prompt_injection' }),
        ])
      );
      // Should NOT have forwarded to upstream
      expect(axios.post).not.toHaveBeenCalled();
    });

    it('should allow flagged requests through to upstream', async () => {
      analyzeTextCached.mockResolvedValue({
        prompt_injection_score: 0.1,
        jailbreak_score: 0.1,
        pii_score: 0.8, // Above PII threshold, but PII action is 'flag'
        processing_time_ms: 50,
      });

      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(200);

      expect(res.body).toHaveProperty('id', 'chatcmpl-abc123');
    });

    it('should return 503 when no upstream model is configured', async () => {
      // Reset to no model config
      mockDb.setFirewallConfig({
        threshold_prompt_injection: 0.7,
        threshold_jailbreak: 0.7,
        threshold_pii: 0.5,
        action_prompt_injection: 'block',
        action_jailbreak: 'block',
        action_pii: 'flag',
        model_provider_type: 'none',
        model_endpoint_url: null,
        model_api_key_encrypted: null,
        model_name: null,
        safeguard_model: '20b',
        fail_mode: 'open',
        cache_enabled: true,
        cache_ttl_seconds: 300,
      });

      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(503);

      expect(res.body.error).toHaveProperty('code', 'no_upstream');
    });

    it('should return 503 when threat analysis service is unavailable', async () => {
      analyzeTextCached.mockRejectedValue(new Error('Model service unavailable'));

      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(503);

      expect(res.body.error).toHaveProperty('code', 'analysis_unavailable');
    });

    it('should extract user text from multiple user messages', async () => {
      const body = {
        model: 'gpt-4',
        messages: [
          { role: 'system', content: 'System prompt' },
          { role: 'user', content: 'First message' },
          { role: 'assistant', content: 'Response' },
          { role: 'user', content: 'Second message' },
        ],
      };

      await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(body)
        .expect(200);

      // analyzeTextCached should be called with concatenated user messages
      expect(analyzeTextCached).toHaveBeenCalledWith('First message\nSecond message', expect.objectContaining({
        cacheEnabled: true,
      }));
    });

    it('should handle upstream errors with appropriate status', async () => {
      axios.post.mockRejectedValue({
        response: {
          status: 429,
          data: { error: { message: 'Rate limited by upstream' } },
        },
      });

      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(429);

      expect(res.body.error).toHaveProperty('type', 'upstream_error');
    });

    it('should handle upstream connection refused', async () => {
      axios.post.mockRejectedValue({
        code: 'ECONNREFUSED',
        message: 'connect ECONNREFUSED',
      });

      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(502);

      expect(res.body.error.message).toContain('Upstream');
    });

    it('should log proxy request to database', async () => {
      await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validChatBody)
        .expect(200);

      expect(publishEvent).toHaveBeenCalled();
    });

    it('should override upstream model name from config', async () => {
      await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ ...validChatBody, model: 'user-specified-model' })
        .expect(200);

      // The upstream call should use the config model name (gpt-4), not the user's
      const callArgs = axios.post.mock.calls[0];
      const sentBody = callArgs[1];
      expect(sentBody.model).toBe('gpt-4');
    });

    it('should work for viewer role', async () => {
      const res = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${viewerToken}`)
        .send(validChatBody)
        .expect(200);

      expect(res.body).toHaveProperty('id');
    });

    it('should handle content arrays in user messages (vision)', async () => {
      const body = {
        model: 'gpt-4-vision',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'What is in this image?' },
              { type: 'image_url', image_url: { url: 'http://example.com/img.png' } },
            ],
          },
        ],
      };

      await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(body)
        .expect(200);

      expect(analyzeTextCached).toHaveBeenCalledWith('What is in this image?', expect.objectContaining({
        cacheEnabled: true,
      }));
    });
  });

  // ── GET /v1/models ────────────────────────────────────────────────

  describe('GET /v1/models', () => {
    it('should require authentication', async () => {
      await request(app)
        .get('/v1/models')
        .expect(401);
    });

    it('should return empty list when no upstream configured', async () => {
      mockDb.setFirewallConfig({
        threshold_prompt_injection: 0.7,
        threshold_jailbreak: 0.7,
        threshold_pii: 0.5,
        action_prompt_injection: 'block',
        action_jailbreak: 'block',
        action_pii: 'flag',
        model_provider_type: 'none',
        model_endpoint_url: null,
        model_api_key_encrypted: null,
        model_name: null,
        safeguard_model: '20b',
      });

      const res = await request(app)
        .get('/v1/models')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body).toHaveProperty('object', 'list');
      expect(res.body).toHaveProperty('data');
      expect(res.body.data).toHaveLength(0);
    });

    it('should proxy model list from upstream', async () => {
      axios.get.mockResolvedValue({
        data: {
          object: 'list',
          data: [{ id: 'gpt-4' }, { id: 'gpt-3.5-turbo' }],
        },
      });

      const res = await request(app)
        .get('/v1/models')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body).toHaveProperty('object', 'list');
      expect(res.body.data).toHaveLength(2);
    });

    it('should return empty list on upstream error', async () => {
      axios.get.mockRejectedValue(new Error('Connection refused'));

      const res = await request(app)
        .get('/v1/models')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(res.body).toHaveProperty('object', 'list');
      expect(res.body.data).toHaveLength(0);
    });
  });
});
