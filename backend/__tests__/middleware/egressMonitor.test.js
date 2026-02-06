const egressMonitor = require('../../src/middleware/egressMonitor');
const { analyzeResponse, redactPII, EGRESS_CONFIG, PII_PATTERNS } = egressMonitor;

// Mock the redis service
jest.mock('../../src/services/redis', () => ({
  publishEvent: jest.fn().mockResolvedValue(undefined),
  CHANNELS: {
    FIREWALL_EVENTS: 'firewall:events',
    ALERTS: 'alerts:triggered'
  }
}));

// Mock the logger
jest.mock('../../src/services/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const { publishEvent, CHANNELS } = require('../../src/services/redis');
const logger = require('../../src/services/logger');

describe('Egress Monitor Middleware', () => {
  let mockReq;
  let mockRes;
  let nextFn;
  let originalJson;

  beforeEach(() => {
    mockReq = {
      path: '/api/test',
      method: 'GET',
      ip: '127.0.0.1',
      user: { id: 'user-123' }
    };

    originalJson = jest.fn().mockReturnThis();
    mockRes = {
      json: originalJson,
      statusCode: 200
    };

    nextFn = jest.fn();
    jest.clearAllMocks();
  });

  describe('analyzeResponse', () => {
    it('should detect API keys in response', () => {
      const body = { data: 'Your API key is sk-abc123xyz456789012345678901234567890' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.secrets.length).toBeGreaterThan(0);
      expect(result.secrets.some(s => s.type === 'openai_key')).toBe(true);
    });

    it('should detect AWS credentials in response', () => {
      const body = { credentials: 'Access key: AKIAIOSFODNN7EXAMPLE' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.secrets.some(s => s.type === 'aws_access_key')).toBe(true);
    });

    it('should detect GitHub tokens in response', () => {
      const body = { token: 'ghp_123456789012345678901234567890123456' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.secrets.some(s => s.type === 'github_pat')).toBe(true);
    });

    it('should detect JWT tokens in response', () => {
      const body = {
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
      };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.secrets.some(s => s.type === 'jwt')).toBe(true);
    });

    it('should detect SSN in response', () => {
      const body = { ssn: '123-45-6789' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.pii.some(p => p.type === 'ssn')).toBe(true);
    });

    it('should detect credit card numbers in response', () => {
      const body = { card: '4111-1111-1111-1111' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.pii.some(p => p.type === 'credit_card')).toBe(true);
    });

    it('should detect email addresses in response', () => {
      const body = { email: 'user@example.com' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.pii.some(p => p.type === 'email')).toBe(true);
    });

    it('should return no sensitive data for clean response', () => {
      const body = { message: 'Hello, world!', status: 'ok' };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(false);
      expect(result.secrets.length).toBe(0);
      expect(result.pii.length).toBe(0);
    });

    it('should handle string input', () => {
      const body = 'API key: sk-abc123xyz456789012345678901234567890';
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
    });

    it('should detect multiple types of sensitive data', () => {
      const body = {
        key: 'sk-abc123xyz456789012345678901234567890',
        ssn: '123-45-6789',
        email: 'test@example.com'
      };
      const result = analyzeResponse(body);

      expect(result.hasSensitiveData).toBe(true);
      expect(result.secrets.length).toBeGreaterThan(0);
      // SSN, email, and also credit_card pattern may match numeric sequences
      expect(result.pii.length).toBeGreaterThanOrEqual(2);
      expect(result.pii.some(p => p.type === 'ssn')).toBe(true);
      expect(result.pii.some(p => p.type === 'email')).toBe(true);
    });
  });

  describe('middleware function', () => {
    it('should call next() for all requests', () => {
      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
    });

    it('should skip excluded paths', () => {
      mockReq.path = '/api/health';
      const middleware = egressMonitor();

      middleware(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      // The json method should not be overridden
      expect(mockRes.json).toBe(originalJson);
    });

    it('should skip csrf-token path', () => {
      mockReq.path = '/api/csrf-token';
      const middleware = egressMonitor();

      middleware(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockRes.json).toBe(originalJson);
    });

    it('should skip non-API paths', () => {
      mockReq.path = '/static/file.js';
      const middleware = egressMonitor();

      middleware(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockRes.json).toBe(originalJson);
    });

    it('should override json method for monitored paths', () => {
      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      expect(mockRes.json).not.toBe(originalJson);
    });

    it('should still call original json method', () => {
      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      const responseBody = { message: 'Hello' };
      mockRes.json(responseBody);

      expect(originalJson).toHaveBeenCalledWith(responseBody);
    });

    it('should respect custom config options', () => {
      const customConfig = {
        excludedPaths: [/^\/api\/test/]
      };
      const middleware = egressMonitor(customConfig);
      mockReq.path = '/api/test';

      middleware(mockReq, mockRes, nextFn);

      expect(mockRes.json).toBe(originalJson);
    });

    it('should skip responses below minimum size', () => {
      const middleware = egressMonitor({ minResponseSize: 100 });
      middleware(mockReq, mockRes, nextFn);

      const smallBody = { a: 1 };
      mockRes.json(smallBody);

      expect(originalJson).toHaveBeenCalledWith(smallBody);
    });

    it('should skip responses above maximum size', () => {
      const middleware = egressMonitor({ maxResponseSize: 10 });
      middleware(mockReq, mockRes, nextFn);

      const largeBody = { data: 'a'.repeat(100) };
      mockRes.json(largeBody);

      expect(originalJson).toHaveBeenCalledWith(largeBody);
    });
  });

  describe('EGRESS_CONFIG', () => {
    it('should have monitored paths configured', () => {
      expect(EGRESS_CONFIG.monitoredPaths).toBeDefined();
      expect(EGRESS_CONFIG.monitoredPaths.length).toBeGreaterThan(0);
    });

    it('should have excluded paths configured', () => {
      expect(EGRESS_CONFIG.excludedPaths).toBeDefined();
      expect(EGRESS_CONFIG.excludedPaths.length).toBeGreaterThan(0);
    });

    it('should have size limits configured', () => {
      expect(EGRESS_CONFIG.minResponseSize).toBeDefined();
      expect(EGRESS_CONFIG.maxResponseSize).toBeDefined();
      expect(EGRESS_CONFIG.minResponseSize).toBeLessThan(EGRESS_CONFIG.maxResponseSize);
    });

    it('should have alert threshold configured', () => {
      expect(EGRESS_CONFIG.alertThreshold).toBeDefined();
      expect(EGRESS_CONFIG.alertThreshold).toBeGreaterThan(0);
    });
  });

  describe('PII_PATTERNS', () => {
    it('should match valid SSN', () => {
      const ssnPattern = PII_PATTERNS.find(p => p.name === 'ssn');
      expect(ssnPattern.pattern.test('123-45-6789')).toBe(true);
    });

    it('should not match invalid SSN', () => {
      const ssnPattern = PII_PATTERNS.find(p => p.name === 'ssn');
      expect(ssnPattern.pattern.test('12345-6789')).toBe(false);
    });

    it('should match credit card with dashes', () => {
      const ccPattern = PII_PATTERNS.find(p => p.name === 'credit_card');
      expect(ccPattern.pattern.test('4111-1111-1111-1111')).toBe(true);
    });

    it('should match credit card with spaces', () => {
      const ccPattern = PII_PATTERNS.find(p => p.name === 'credit_card');
      expect(ccPattern.pattern.test('4111 1111 1111 1111')).toBe(true);
    });

    it('should match credit card without separators', () => {
      const ccPattern = PII_PATTERNS.find(p => p.name === 'credit_card');
      expect(ccPattern.pattern.test('4111111111111111')).toBe(true);
    });

    it('should match valid email', () => {
      const emailPattern = PII_PATTERNS.find(p => p.name === 'email');
      expect(emailPattern.pattern.test('user@example.com')).toBe(true);
      expect(emailPattern.pattern.test('user.name+tag@example.co.uk')).toBe(true);
    });
  });

  describe('synchronous redaction', () => {
    it('should redact API keys from response BEFORE sending', () => {
      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      const sensitiveBody = { key: 'sk-abc123xyz456789012345678901234567890' };
      mockRes.json(sensitiveBody);

      // originalJson should be called with REDACTED body, not the original
      expect(originalJson).toHaveBeenCalled();
      const sentBody = originalJson.mock.calls[0][0];
      expect(JSON.stringify(sentBody)).not.toContain('sk-abc123xyz456789012345678901234567890');
      expect(JSON.stringify(sentBody)).toContain('[REDACTED');
    });

    it('should redact SSN from response BEFORE sending', () => {
      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      const sensitiveBody = { data: 'SSN: 123-45-6789' };
      mockRes.json(sensitiveBody);

      const sentBody = originalJson.mock.calls[0][0];
      expect(JSON.stringify(sentBody)).not.toContain('123-45-6789');
      expect(JSON.stringify(sentBody)).toContain('SSN REDACTED');
    });

    it('should pass clean responses through unchanged', () => {
      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      const cleanBody = { message: 'Hello, world!', count: 42 };
      mockRes.json(cleanBody);

      expect(originalJson).toHaveBeenCalledWith(cleanBody);
    });
  });

  describe('redactPII', () => {
    it('should redact SSN patterns', () => {
      expect(redactPII('SSN: 123-45-6789')).toBe('SSN: [SSN REDACTED]');
    });

    it('should redact credit card patterns', () => {
      expect(redactPII('Card: 4111-1111-1111-1111')).toBe('Card: [CC REDACTED]');
    });

    it('should leave clean text unchanged', () => {
      const text = 'This is normal text';
      expect(redactPII(text)).toBe(text);
    });
  });

  describe('alert publishing', () => {
    it('should publish alert when sensitive data is detected', async () => {
      // Initialize with a mock db that resolves
      const mockDb = jest.fn().mockReturnValue({
        insert: jest.fn().mockResolvedValue([1])
      });
      egressMonitor.initDb(mockDb);

      const middleware = egressMonitor({ alertThreshold: 1 });
      middleware(mockReq, mockRes, nextFn);

      // Send response with sensitive data
      const sensitiveBody = { key: 'sk-abc123xyz456789012345678901234567890' };
      mockRes.json(sensitiveBody);

      // Wait for async logging/alerting to complete
      await new Promise(resolve => setImmediate(resolve));

      // Check that alert was published
      expect(publishEvent).toHaveBeenCalledWith(
        CHANNELS.ALERTS,
        expect.objectContaining({
          type: 'egress_sensitive_data',
          path: '/api/test',
          method: 'GET',
          user_id: 'user-123',
        })
      );
    });
  });

  describe('database logging', () => {
    it('should log egress event when sensitive data is detected', async () => {
      const mockInsert = jest.fn().mockResolvedValue([1]);
      const mockDb = jest.fn().mockReturnValue({
        insert: mockInsert
      });
      egressMonitor.initDb(mockDb);

      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      // Send response with sensitive data
      const sensitiveBody = { ssn: '123-45-6789' };
      mockRes.json(sensitiveBody);

      // Wait for async logging to complete
      await new Promise(resolve => setImmediate(resolve));

      // Check that db was called
      expect(mockDb).toHaveBeenCalledWith('egress_logs');
      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          path: '/api/test',
          method: 'GET',
          user_id: 'user-123',
          client_ip: '127.0.0.1',
          status_code: 200,
        })
      );
    });

    it('should handle missing user gracefully', async () => {
      const mockInsert = jest.fn().mockResolvedValue([1]);
      const mockDb = jest.fn().mockReturnValue({
        insert: mockInsert
      });
      egressMonitor.initDb(mockDb);

      mockReq.user = undefined;

      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      const sensitiveBody = { ssn: '123-45-6789' };
      mockRes.json(sensitiveBody);

      await new Promise(resolve => setImmediate(resolve));

      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          user_id: null,
        })
      );
    });

    it('should not log when no sensitive data is detected', async () => {
      const mockInsert = jest.fn().mockResolvedValue([1]);
      const mockDb = jest.fn().mockReturnValue({
        insert: mockInsert
      });
      egressMonitor.initDb(mockDb);

      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      // Send response without sensitive data
      const cleanBody = { message: 'Hello, world!' };
      mockRes.json(cleanBody);

      await new Promise(resolve => setImmediate(resolve));

      expect(mockInsert).not.toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      const mockInsert = jest.fn().mockRejectedValue(new Error('DB error'));
      const mockDb = jest.fn().mockReturnValue({
        insert: mockInsert
      });
      egressMonitor.initDb(mockDb);

      const middleware = egressMonitor();
      middleware(mockReq, mockRes, nextFn);

      const sensitiveBody = { ssn: '123-45-6789' };

      // Should not throw
      expect(() => mockRes.json(sensitiveBody)).not.toThrow();

      await new Promise(resolve => setImmediate(resolve));

      // Error should be logged
      expect(logger.error).toHaveBeenCalled();
    });
  });
});
