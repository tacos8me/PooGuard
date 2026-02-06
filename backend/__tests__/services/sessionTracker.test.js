/**
 * Tests for Session Tracker Service
 */

const sessionTracker = require('../../src/services/sessionTracker');

// Mock the redis module
jest.mock('../../src/services/redis', () => {
  const mockData = new Map();
  const mockLists = new Map();

  return {
    getClient: jest.fn().mockResolvedValue({
      get: jest.fn((key) => Promise.resolve(mockData.get(key) || null)),
      setEx: jest.fn((key, ttl, value) => {
        mockData.set(key, value);
        return Promise.resolve('OK');
      }),
      del: jest.fn((key) => {
        mockData.delete(key);
        mockLists.delete(key);
        return Promise.resolve(1);
      }),
      lPush: jest.fn((key, value) => {
        if (!mockLists.has(key)) {
          mockLists.set(key, []);
        }
        mockLists.get(key).unshift(value);
        return Promise.resolve(mockLists.get(key).length);
      }),
      lTrim: jest.fn(() => Promise.resolve('OK')),
      lRange: jest.fn((key, start, end) => {
        const list = mockLists.get(key) || [];
        return Promise.resolve(list.slice(start, end + 1));
      }),
      expire: jest.fn(() => Promise.resolve(1)),
      scan: jest.fn().mockResolvedValue({ cursor: '0', keys: [] }),
    }),
    publishEvent: jest.fn().mockResolvedValue(undefined),
    CHANNELS: {
      FIREWALL_EVENTS: 'firewall:events',
      ALERTS: 'alerts:triggered',
    },
  };
});

// Mock logger
jest.mock('../../src/services/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

describe('Session Tracker Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getSessionId', () => {
    it('returns user-based session ID when authenticated', () => {
      const req = {
        user: { id: 123 },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const sessionId = sessionTracker.getSessionId(req);
      expect(sessionId).toBe('user:123');
    });

    it('returns fingerprint-based session ID when anonymous', () => {
      const req = {
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const sessionId = sessionTracker.getSessionId(req);
      expect(sessionId).toMatch(/^anon:[a-f0-9]{16}$/);
    });

    it('generates consistent fingerprint for same IP and UA', () => {
      const req1 = {
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };
      const req2 = {
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const sessionId1 = sessionTracker.getSessionId(req1);
      const sessionId2 = sessionTracker.getSessionId(req2);
      expect(sessionId1).toBe(sessionId2);
    });

    it('generates different fingerprint for different IP', () => {
      const req1 = {
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };
      const req2 = {
        ip: '192.168.1.2',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const sessionId1 = sessionTracker.getSessionId(req1);
      const sessionId2 = sessionTracker.getSessionId(req2);
      expect(sessionId1).not.toBe(sessionId2);
    });
  });

  describe('getSessionThreatData', () => {
    it('returns default values for non-existent session', async () => {
      const data = await sessionTracker.getSessionThreatData('nonexistent');

      expect(data).toEqual({
        cumulativeScore: 0,
        lastUpdateTime: null,
        requestCount: 0,
        threatCount: 0,
        alertTriggeredAt: null,
        alertCount: 0,
      });
    });
  });

  describe('updateSessionThreat', () => {
    it('updates session with blocked request threat score', async () => {
      const req = {
        user: { id: 1 },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };
      const threatScores = {
        prompt_injection: 0.8,
        jailbreak: 0.3,
        pii: 0.2,
      };

      const result = await sessionTracker.updateSessionThreat(
        req,
        threatScores,
        'blocked',
        [{ type: 'prompt_injection' }]
      );

      expect(result).toHaveProperty('sessionId', 'user:1');
      expect(result).toHaveProperty('cumulativeScore');
      expect(result.cumulativeScore).toBeGreaterThan(0);
      expect(result).toHaveProperty('requestThreatScore');
      expect(result).toHaveProperty('thresholdExceeded');
    });

    it('does not add threat score for allowed requests', async () => {
      const req = {
        user: { id: 2 },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };
      const threatScores = {
        prompt_injection: 0.1,
        jailbreak: 0.1,
        pii: 0.1,
      };

      const result = await sessionTracker.updateSessionThreat(
        req,
        threatScores,
        'allowed',
        []
      );

      expect(result.requestThreatScore).toBe(0);
    });

    it('adds lower threat score for flagged requests', async () => {
      const req = {
        user: { id: 3 },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };
      const threatScores = {
        prompt_injection: 0.6,
        jailbreak: 0.4,
        pii: 0.3,
      };

      const result = await sessionTracker.updateSessionThreat(
        req,
        threatScores,
        'flagged',
        [{ type: 'prompt_injection' }]
      );

      // Flagged should have lower multiplier than blocked
      expect(result.requestThreatScore).toBeGreaterThan(0);
      expect(result.requestThreatScore).toBeLessThan(
        threatScores.prompt_injection * 1.5 +
        threatScores.jailbreak * 1.5 +
        threatScores.pii * 1.0
      );
    });
  });

  describe('CUMULATIVE_THRESHOLD', () => {
    it('is defined and reasonable', () => {
      expect(sessionTracker.CUMULATIVE_THRESHOLD).toBeDefined();
      expect(sessionTracker.CUMULATIVE_THRESHOLD).toBeGreaterThan(0);
      expect(sessionTracker.CUMULATIVE_THRESHOLD).toBeLessThanOrEqual(10);
    });
  });

  describe('ALERT_COOLDOWN_MS', () => {
    it('is exported and reasonable', () => {
      expect(sessionTracker.ALERT_COOLDOWN_MS).toBeDefined();
      expect(sessionTracker.ALERT_COOLDOWN_MS).toBeGreaterThan(0);
      // Should be at least 5 minutes
      expect(sessionTracker.ALERT_COOLDOWN_MS).toBeGreaterThanOrEqual(5 * 60 * 1000);
    });
  });

  describe('alert re-triggering', () => {
    it('triggers alert on first threshold crossing', async () => {
      const { publishEvent } = require('../../src/services/redis');
      const req = {
        user: { id: 'alert-test-1' },
        ip: '10.0.0.1',
        headers: { 'user-agent': 'TestBot' },
      };

      // Send high threat that should exceed threshold
      const result = await sessionTracker.updateSessionThreat(
        req,
        { prompt_injection: 1.0, jailbreak: 1.0, pii: 0.5 },
        'blocked',
        [{ type: 'prompt_injection' }]
      );

      expect(result.alertTriggered).toBe(true);
      expect(publishEvent).toHaveBeenCalledWith(
        'alerts:triggered',
        expect.objectContaining({
          type: 'session_threat_threshold',
        })
      );
    });

    it('stores alertTriggeredAt and alertCount in session data', async () => {
      const req = {
        user: { id: 'alert-test-2' },
        ip: '10.0.0.2',
        headers: { 'user-agent': 'TestBot' },
      };

      await sessionTracker.updateSessionThreat(
        req,
        { prompt_injection: 1.0, jailbreak: 1.0, pii: 0.5 },
        'blocked',
        [{ type: 'prompt_injection' }]
      );

      const sessionData = await sessionTracker.getSessionThreatData('user:alert-test-2');
      expect(sessionData.alertTriggeredAt).toBeDefined();
      expect(sessionData.alertTriggeredAt).not.toBeNull();
      expect(sessionData.alertCount).toBeGreaterThanOrEqual(1);
    });
  });
});
