// Load test environment variables
require('dotenv').config({ path: '.env.test' });

// Set NODE_ENV to test
process.env.NODE_ENV = 'test';

// Mock external services
jest.mock('../src/services/redis', () => ({
  getClient: jest.fn().mockResolvedValue({
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    quit: jest.fn()
  }),
  getSubscriber: jest.fn().mockResolvedValue({
    subscribe: jest.fn(),
    unsubscribe: jest.fn(),
    quit: jest.fn()
  }),
  publishEvent: jest.fn().mockResolvedValue(undefined),
  closeAll: jest.fn().mockResolvedValue(undefined),
  cacheGet: jest.fn().mockResolvedValue(null),
  cacheSet: jest.fn().mockResolvedValue(undefined),
  getCacheStats: jest.fn().mockReturnValue({ hits: 0, misses: 0, hitRate: 0 }),
  resetCacheStats: jest.fn(),
  CHANNELS: {
    FIREWALL_EVENTS: 'firewall:events',
    ALERTS: 'alerts'
  }
}));

jest.mock('../src/services/modelService', () => ({
  analyzeText: jest.fn().mockResolvedValue({
    prompt_injection_score: 0.1,
    jailbreak_score: 0.1,
    pii_score: 0.1,
    latencyMs: 50
  }),
  analyzeTextCached: jest.fn().mockResolvedValue({
    prompt_injection_score: 0.1,
    jailbreak_score: 0.1,
    pii_score: 0.1,
    latencyMs: 50,
    cache_hit: false
  }),
  buildCacheKey: jest.fn().mockReturnValue('cache:analyze:20b:testhash'),
  analyzeBatch: jest.fn().mockResolvedValue({
    results: [],
    total_count: 0,
    success_count: 0,
    failure_count: 0,
    processing_time_ms: 50,
  }),
  analyzeOutput: jest.fn().mockResolvedValue({
    safe: true,
    detected: [],
    scores: { pii_score: 0, system_prompt_disclosure_score: 0, secret_score: 0 },
    sanitized_output: null,
    processing_time_ms: 10,
    latencyMs: 20
  }),
  checkHealth: jest.fn().mockResolvedValue(true),
  getCircuitState: jest.fn().mockReturnValue('closed'),
  resetCircuitBreaker: jest.fn()
}));

jest.mock('../src/services/analysisQueue', () => ({
  enqueue: jest.fn().mockResolvedValue('test-request-id-123'),
  getResult: jest.fn().mockResolvedValue(null),
  startWorker: jest.fn(),
  stopWorker: jest.fn(),
  isWorkerRunning: jest.fn().mockReturnValue(false),
  processJob: jest.fn().mockResolvedValue(undefined),
}));

// Silence logger during tests
jest.mock('../src/services/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn()
}));

// Global test timeout
jest.setTimeout(10000);

// Clean up after all tests
afterAll(async () => {
  // Allow any pending async operations to complete
  await new Promise(resolve => setTimeout(resolve, 100));
});
