/**
 * Tests for Model Service Client
 *
 * Tests the real modelService module (not the setup.js mock) by:
 * 1. Unmocking modelService so we get the real implementation
 * 2. Mocking axios to control HTTP responses
 * 3. Testing circuit breaker behavior, error handling, and caching
 */

// Must unmock before requiring
jest.unmock('../../src/services/modelService');

// Mock axios.create to return a controllable mock client
const mockPost = jest.fn();
const mockGet = jest.fn();
jest.mock('axios', () => {
  const realAxios = jest.requireActual('axios');
  return {
    ...realAxios,
    create: jest.fn().mockReturnValue({
      post: mockPost,
      get: mockGet,
    }),
  };
});

const {
  analyzeText,
  analyzeTextCached,
  buildCacheKey,
  analyzeBatch,
  analyzeOutput,
  checkHealth,
  getCircuitState,
  resetCircuitBreaker,
} = require('../../src/services/modelService');

const { cacheGet, cacheSet } = require('../../src/services/redis');

describe('Model Service Client', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetCircuitBreaker();

    // Default: successful model response
    mockPost.mockResolvedValue({
      data: {
        prompt_injection_score: 0.15,
        jailbreak_score: 0.05,
        pii_score: 0.02,
        semantic_similarity_score: 0.1,
        processing_time_ms: 45,
      },
    });
  });

  // ── analyzeText ───────────────────────────────────────────────────

  describe('analyzeText', () => {
    it('should return expected score format', async () => {
      const result = await analyzeText('Hello world');

      expect(result).toHaveProperty('prompt_injection_score', 0.15);
      expect(result).toHaveProperty('jailbreak_score', 0.05);
      expect(result).toHaveProperty('pii_score', 0.02);
      expect(result).toHaveProperty('latencyMs');
      expect(typeof result.latencyMs).toBe('number');
    });

    it('should call model client with text', async () => {
      await analyzeText('test input');
      expect(mockPost).toHaveBeenCalledWith('/analyze', { text: 'test input' });
    });

    it('should throw "Model service unavailable" on ECONNREFUSED', async () => {
      mockPost.mockRejectedValue({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' });

      await expect(analyzeText('test')).rejects.toThrow('Model service unavailable');
    });

    it('should throw on non-ECONNREFUSED errors', async () => {
      mockPost.mockRejectedValue(new Error('timeout'));

      await expect(analyzeText('test')).rejects.toThrow('timeout');
    });
  });

  // ── Circuit Breaker ───────────────────────────────────────────────

  describe('Circuit Breaker', () => {
    it('should start in closed state', () => {
      expect(getCircuitState()).toBe('closed');
    });

    it('should open after 5 consecutive failures', async () => {
      mockPost.mockRejectedValue(new Error('Connection failed'));

      for (let i = 0; i < 5; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      expect(getCircuitState()).toBe('open');
    });

    it('should reject requests when open', async () => {
      mockPost.mockRejectedValue(new Error('Connection failed'));

      // Trip the breaker
      for (let i = 0; i < 5; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      // Next request should fail with circuit breaker message
      await expect(analyzeText('test')).rejects.toThrow('circuit breaker is open');
    });

    it('should not trip on 401 errors', async () => {
      const authError = new Error('Unauthorized');
      authError.response = { status: 401 };
      mockPost.mockRejectedValue(authError);

      // 401 errors should not increment failure count
      for (let i = 0; i < 10; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      // Circuit should still be closed
      expect(getCircuitState()).toBe('closed');
    });

    it('should not trip on 403 errors', async () => {
      const authError = new Error('Forbidden');
      authError.response = { status: 403 };
      mockPost.mockRejectedValue(authError);

      for (let i = 0; i < 10; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      expect(getCircuitState()).toBe('closed');
    });

    it('should transition to half-open after timeout', async () => {
      mockPost.mockRejectedValue(new Error('Connection failed'));

      // Trip the breaker
      for (let i = 0; i < 5; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      // Fast-forward by manipulating the lastFailureTime
      // The circuit breaker uses Date.now() internally, so we use the reset timeout
      const originalDateNow = Date.now;
      Date.now = () => originalDateNow() + 31000; // 31 seconds (> 30s timeout)

      expect(getCircuitState()).toBe('half-open');

      Date.now = originalDateNow;
    });

    it('should close after successful request in half-open', async () => {
      mockPost.mockRejectedValue(new Error('Connection failed'));

      // Trip the breaker
      for (let i = 0; i < 5; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      // Fast-forward past timeout
      const originalDateNow = Date.now;
      Date.now = () => originalDateNow() + 31000;

      // Now restore normal response and try again
      mockPost.mockResolvedValue({
        data: { prompt_injection_score: 0.1, jailbreak_score: 0.1, pii_score: 0.1 },
      });

      const result = await analyzeText('test');
      expect(result.prompt_injection_score).toBe(0.1);
      expect(getCircuitState()).toBe('closed');

      Date.now = originalDateNow;
    });

    it('should reset with resetCircuitBreaker()', async () => {
      mockPost.mockRejectedValue(new Error('Connection failed'));

      for (let i = 0; i < 5; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      expect(getCircuitState()).toBe('open');
      resetCircuitBreaker();
      expect(getCircuitState()).toBe('closed');
    });
  });

  // ── analyzeOutput ─────────────────────────────────────────────────

  describe('analyzeOutput', () => {
    it('should call /analyze-output endpoint', async () => {
      mockPost.mockResolvedValue({
        data: {
          safe: true,
          detected: [],
          scores: { pii_score: 0, system_prompt_disclosure_score: 0, secret_score: 0 },
          processing_time_ms: 10,
        },
      });

      const result = await analyzeOutput('Some LLM output');
      expect(mockPost).toHaveBeenCalledWith('/analyze-output', { text: 'Some LLM output' });
      expect(result).toHaveProperty('safe', true);
      expect(result).toHaveProperty('latencyMs');
    });

    it('should share the circuit breaker with analyzeText', async () => {
      mockPost.mockRejectedValue(new Error('Connection failed'));

      // Trip breaker via analyzeText
      for (let i = 0; i < 5; i++) {
        await expect(analyzeText('test')).rejects.toThrow();
      }

      // analyzeOutput should also be blocked
      await expect(analyzeOutput('test')).rejects.toThrow('circuit breaker is open');
    });
  });

  // ── analyzeBatch ──────────────────────────────────────────────────

  describe('analyzeBatch', () => {
    it('should call /analyze/batch endpoint with texts and batch size', async () => {
      mockPost.mockResolvedValue({
        data: {
          results: [{ index: 0, success: true, result: { prompt_injection_score: 0.1, jailbreak_score: 0.1, pii_score: 0.1 } }],
          total_count: 1,
          success_count: 1,
          failure_count: 0,
        },
      });

      const result = await analyzeBatch(['text1', 'text2'], 5);

      expect(mockPost).toHaveBeenCalledWith(
        '/analyze/batch',
        { texts: ['text1', 'text2'], max_batch_size: 5 },
        { timeout: 60000 }
      );
      expect(result.total_count).toBe(1);
    });

    it('should throw "Model service unavailable" on ECONNREFUSED', async () => {
      mockPost.mockRejectedValue({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' });

      await expect(analyzeBatch(['test'])).rejects.toThrow('Model service unavailable');
    });

    it('should throw "Model service not available" on 503', async () => {
      mockPost.mockRejectedValue({
        response: { status: 503, data: {} },
        message: 'Request failed',
      });

      await expect(analyzeBatch(['test'])).rejects.toThrow('Model service not available');
    });
  });

  // ── checkHealth ───────────────────────────────────────────────────

  describe('checkHealth', () => {
    it('should return true when model service is healthy', async () => {
      mockGet.mockResolvedValue({ data: { status: 'healthy' } });
      expect(await checkHealth()).toBe(true);
    });

    it('should return false when model service is down', async () => {
      mockGet.mockRejectedValue(new Error('Connection refused'));
      expect(await checkHealth()).toBe(false);
    });

    it('should return false when status is not healthy', async () => {
      mockGet.mockResolvedValue({ data: { status: 'loading' } });
      expect(await checkHealth()).toBe(false);
    });
  });

  // ── buildCacheKey ─────────────────────────────────────────────────

  describe('buildCacheKey', () => {
    it('should include model variant in key', () => {
      const key = buildCacheKey('hello', '20b');
      expect(key).toMatch(/^cache:analyze:20b:/);
    });

    it('should produce different keys for different model variants', () => {
      const key20b = buildCacheKey('hello', '20b');
      const key120b = buildCacheKey('hello', '120b');
      expect(key20b).not.toBe(key120b);
    });

    it('should produce different keys for different texts', () => {
      const key1 = buildCacheKey('hello', '20b');
      const key2 = buildCacheKey('world', '20b');
      expect(key1).not.toBe(key2);
    });

    it('should produce consistent keys for same input', () => {
      const key1 = buildCacheKey('test', '20b');
      const key2 = buildCacheKey('test', '20b');
      expect(key1).toBe(key2);
    });
  });

  // ── analyzeTextCached ─────────────────────────────────────────────

  describe('analyzeTextCached', () => {
    it('should return result with cache_hit false on miss', async () => {
      cacheGet.mockResolvedValue(null);

      const result = await analyzeTextCached('hello', {
        cacheEnabled: true,
        cacheTtlSeconds: 300,
        modelVariant: '20b',
      });

      expect(result.cache_hit).toBe(false);
      expect(result.prompt_injection_score).toBe(0.15);
      expect(cacheGet).toHaveBeenCalled();
      expect(cacheSet).toHaveBeenCalled();
    });

    it('should return cached result with cache_hit true on hit', async () => {
      cacheGet.mockResolvedValue({
        prompt_injection_score: 0.05,
        jailbreak_score: 0.02,
        pii_score: 0.01,
      });

      const result = await analyzeTextCached('hello', {
        cacheEnabled: true,
        cacheTtlSeconds: 300,
        modelVariant: '20b',
      });

      expect(result.cache_hit).toBe(true);
      expect(result.prompt_injection_score).toBe(0.05);
      // Should NOT have called model service
      expect(mockPost).not.toHaveBeenCalled();
    });

    it('should skip cache when cacheEnabled is false', async () => {
      const result = await analyzeTextCached('hello', {
        cacheEnabled: false,
        modelVariant: '20b',
      });

      expect(result.cache_hit).toBe(false);
      expect(cacheGet).not.toHaveBeenCalled();
      expect(cacheSet).not.toHaveBeenCalled();
    });

    it('should skip cache when noCache is true', async () => {
      const result = await analyzeTextCached('hello', {
        cacheEnabled: true,
        cacheTtlSeconds: 300,
        modelVariant: '20b',
        noCache: true,
      });

      expect(result.cache_hit).toBe(false);
      expect(cacheGet).not.toHaveBeenCalled();
    });

    it('should fall through to model on cache read error', async () => {
      cacheGet.mockRejectedValue(new Error('Redis connection error'));

      const result = await analyzeTextCached('hello', {
        cacheEnabled: true,
        cacheTtlSeconds: 300,
        modelVariant: '20b',
      });

      expect(result.cache_hit).toBe(false);
      expect(result.prompt_injection_score).toBe(0.15);
    });

    it('should still return result on cache write error', async () => {
      cacheGet.mockResolvedValue(null);
      cacheSet.mockRejectedValue(new Error('Redis write error'));

      const result = await analyzeTextCached('hello', {
        cacheEnabled: true,
        cacheTtlSeconds: 300,
        modelVariant: '20b',
      });

      expect(result.cache_hit).toBe(false);
      expect(result.prompt_injection_score).toBe(0.15);
    });
  });
});
