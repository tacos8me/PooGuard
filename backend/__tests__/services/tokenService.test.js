/**
 * Tests for Token Service
 *
 * NOTE: The global setup.js mock for redis provides basic get/set/del stubs.
 * This test file overrides the redis mock with a functional in-memory store
 * to test token storage/validation/revocation logic.
 */
const jwt = require('jsonwebtoken');
const config = require('../../src/config');

// Override redis mock with an in-memory store for functional testing
const mockStore = new Map();
jest.mock('../../src/services/redis', () => ({
  getClient: jest.fn().mockResolvedValue({
    get: jest.fn((key) => Promise.resolve(mockStore.get(key) || null)),
    set: jest.fn((key, value, opts) => {
      mockStore.set(key, value);
      return Promise.resolve('OK');
    }),
    del: jest.fn((key) => {
      const existed = mockStore.has(key);
      mockStore.delete(key);
      return Promise.resolve(existed ? 1 : 0);
    }),
    scan: jest.fn().mockResolvedValue({ cursor: '0', keys: [] }),
  }),
  publishEvent: jest.fn().mockResolvedValue(undefined),
  cacheGet: jest.fn().mockResolvedValue(null),
  cacheSet: jest.fn().mockResolvedValue(undefined),
  getCacheStats: jest.fn().mockReturnValue({ hits: 0, misses: 0, hitRate: 0 }),
  resetCacheStats: jest.fn(),
  closeAll: jest.fn().mockResolvedValue(undefined),
  CHANNELS: { FIREWALL_EVENTS: 'firewall:events', ALERTS: 'alerts' },
}));

// Override tokenService mock so we can test the REAL implementation
jest.unmock('../../src/services/tokenService');

const {
  generateAccessToken,
  generateRefreshToken,
  storeRefreshToken,
  validateRefreshToken,
  revokeRefreshToken,
  rotateRefreshToken,
} = require('../../src/services/tokenService');

describe('Token Service', () => {
  beforeEach(() => {
    mockStore.clear();
    jest.clearAllMocks();
  });

  describe('generateAccessToken', () => {
    it('should return a valid JWT', () => {
      const user = { id: 1, email: 'test@example.com', role: 'viewer' };
      const token = generateAccessToken(user);
      expect(typeof token).toBe('string');

      const decoded = jwt.verify(token, config.jwt.secret);
      expect(decoded.id).toBe(1);
      expect(decoded.email).toBe('test@example.com');
      expect(decoded.role).toBe('viewer');
    });

    it('should include admin role in token', () => {
      const user = { id: 2, email: 'admin@example.com', role: 'admin' };
      const token = generateAccessToken(user);
      const decoded = jwt.verify(token, config.jwt.secret);
      expect(decoded.role).toBe('admin');
    });

    it('should set an expiration', () => {
      const user = { id: 1, email: 'test@example.com', role: 'viewer' };
      const token = generateAccessToken(user);
      const decoded = jwt.verify(token, config.jwt.secret);
      expect(decoded.exp).toBeDefined();
      expect(decoded.exp).toBeGreaterThan(decoded.iat);
    });
  });

  describe('generateRefreshToken', () => {
    it('should return a 128-character hex string', () => {
      const token = generateRefreshToken({ id: 1 });
      expect(typeof token).toBe('string');
      expect(token).toMatch(/^[0-9a-f]{128}$/);
    });

    it('should generate unique tokens', () => {
      const tokens = new Set(Array.from({ length: 10 }, () => generateRefreshToken({ id: 1 })));
      expect(tokens.size).toBe(10);
    });
  });

  describe('storeRefreshToken', () => {
    it('should store token in Redis', async () => {
      const token = 'test-refresh-token-abc';
      await storeRefreshToken(42, token);

      const stored = mockStore.get(`refresh_token:${token}`);
      expect(stored).toBe('42');
    });
  });

  describe('validateRefreshToken', () => {
    it('should return userId for a valid stored token', async () => {
      const token = 'valid-refresh-token';
      mockStore.set(`refresh_token:${token}`, '7');

      const result = await validateRefreshToken(token);
      expect(result).toEqual({ userId: '7' });
    });

    it('should return null for a non-existent token', async () => {
      const result = await validateRefreshToken('nonexistent-token');
      expect(result).toBeNull();
    });

    it('should return null for a revoked token', async () => {
      const token = 'revoked-token';
      mockStore.set(`refresh_token:${token}`, '5');
      mockStore.delete(`refresh_token:${token}`);

      const result = await validateRefreshToken(token);
      expect(result).toBeNull();
    });
  });

  describe('revokeRefreshToken', () => {
    it('should delete token from Redis and return true', async () => {
      const token = 'to-revoke';
      mockStore.set(`refresh_token:${token}`, '3');

      const result = await revokeRefreshToken(token);
      expect(result).toBe(true);
      expect(mockStore.has(`refresh_token:${token}`)).toBe(false);
    });

    it('should return false for non-existent token', async () => {
      const result = await revokeRefreshToken('does-not-exist');
      expect(result).toBe(false);
    });

    it('should make token invalid after revocation', async () => {
      const token = 'revoke-test';
      mockStore.set(`refresh_token:${token}`, '1');

      await revokeRefreshToken(token);
      const result = await validateRefreshToken(token);
      expect(result).toBeNull();
    });
  });

  describe('rotateRefreshToken', () => {
    it('should revoke old token and return a new one', async () => {
      const oldToken = 'old-refresh-token';
      mockStore.set(`refresh_token:${oldToken}`, '10');

      const newToken = await rotateRefreshToken(oldToken, 10);

      expect(typeof newToken).toBe('string');
      expect(newToken).not.toBe(oldToken);
      // Old token should be revoked
      expect(mockStore.has(`refresh_token:${oldToken}`)).toBe(false);
      // New token should be stored
      expect(mockStore.has(`refresh_token:${newToken}`)).toBe(true);
      expect(mockStore.get(`refresh_token:${newToken}`)).toBe('10');
    });
  });
});
