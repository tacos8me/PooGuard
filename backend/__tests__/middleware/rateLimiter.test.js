/**
 * Tests for Rate Limiter Middleware
 */

const {
  getUserRateLimitKey,
  getUserTier,
  getTierLimits,
  USER_TIER_LIMITS,
} = require('../../src/middleware/rateLimiter');

// Mock redis service
jest.mock('../../src/services/redis', () => ({
  getClient: jest.fn().mockResolvedValue(null),
}));

// Mock logger
jest.mock('../../src/services/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

describe('Rate Limiter Middleware', () => {
  describe('USER_TIER_LIMITS', () => {
    it('defines limits for all tiers', () => {
      expect(USER_TIER_LIMITS).toHaveProperty('admin');
      expect(USER_TIER_LIMITS).toHaveProperty('viewer');
      expect(USER_TIER_LIMITS).toHaveProperty('anonymous');
    });

    it('admin tier has highest limits', () => {
      expect(USER_TIER_LIMITS.admin.analyze.max).toBeGreaterThan(
        USER_TIER_LIMITS.viewer.analyze.max
      );
      expect(USER_TIER_LIMITS.admin.batch.max).toBeGreaterThan(
        USER_TIER_LIMITS.viewer.batch.max
      );
      expect(USER_TIER_LIMITS.admin.general.max).toBeGreaterThan(
        USER_TIER_LIMITS.viewer.general.max
      );
    });

    it('viewer tier has higher limits than anonymous', () => {
      expect(USER_TIER_LIMITS.viewer.analyze.max).toBeGreaterThan(
        USER_TIER_LIMITS.anonymous.analyze.max
      );
      expect(USER_TIER_LIMITS.viewer.batch.max).toBeGreaterThan(
        USER_TIER_LIMITS.anonymous.batch.max
      );
      expect(USER_TIER_LIMITS.viewer.general.max).toBeGreaterThan(
        USER_TIER_LIMITS.anonymous.general.max
      );
    });

    it('all tiers have all limit types', () => {
      Object.values(USER_TIER_LIMITS).forEach((tier) => {
        expect(tier).toHaveProperty('analyze');
        expect(tier).toHaveProperty('batch');
        expect(tier).toHaveProperty('general');
      });
    });

    it('all limits have windowMs and max properties', () => {
      Object.values(USER_TIER_LIMITS).forEach((tier) => {
        Object.values(tier).forEach((limit) => {
          expect(limit).toHaveProperty('windowMs');
          expect(limit).toHaveProperty('max');
          expect(typeof limit.windowMs).toBe('number');
          expect(typeof limit.max).toBe('number');
        });
      });
    });
  });

  describe('getUserRateLimitKey', () => {
    it('returns user-based key for authenticated users', () => {
      const req = {
        user: { id: 123, email: 'test@example.com', role: 'viewer' },
        ip: '192.168.1.1',
      };

      const key = getUserRateLimitKey(req);
      expect(key).toBe('user:123');
    });

    it('returns IP-based key for anonymous users', () => {
      const req = {
        ip: '192.168.1.1',
      };

      const key = getUserRateLimitKey(req);
      expect(key).toBe('ip:192.168.1.1');
    });

    it('handles missing user property', () => {
      const req = {
        user: null,
        ip: '10.0.0.1',
      };

      const key = getUserRateLimitKey(req);
      expect(key).toBe('ip:10.0.0.1');
    });

    it('handles missing user id', () => {
      const req = {
        user: { email: 'test@example.com' },
        ip: '10.0.0.1',
      };

      const key = getUserRateLimitKey(req);
      expect(key).toBe('ip:10.0.0.1');
    });

    it('falls back to connection remoteAddress when ip is missing', () => {
      const req = {
        connection: { remoteAddress: '172.16.0.1' },
      };

      const key = getUserRateLimitKey(req);
      expect(key).toBe('ip:172.16.0.1');
    });

    it('returns unknown when no IP information available', () => {
      const req = {};

      const key = getUserRateLimitKey(req);
      expect(key).toBe('ip:unknown');
    });

    it('tracks same user across different IPs', () => {
      const req1 = {
        user: { id: 456, role: 'admin' },
        ip: '192.168.1.1',
      };
      const req2 = {
        user: { id: 456, role: 'admin' },
        ip: '10.0.0.1',
      };

      const key1 = getUserRateLimitKey(req1);
      const key2 = getUserRateLimitKey(req2);

      expect(key1).toBe(key2);
      expect(key1).toBe('user:456');
    });
  });

  describe('getUserTier', () => {
    it('returns admin for admin users', () => {
      const req = { user: { id: 1, role: 'admin' } };
      expect(getUserTier(req)).toBe('admin');
    });

    it('returns viewer for viewer users', () => {
      const req = { user: { id: 2, role: 'viewer' } };
      expect(getUserTier(req)).toBe('viewer');
    });

    it('returns anonymous for unauthenticated requests', () => {
      const req = {};
      expect(getUserTier(req)).toBe('anonymous');
    });

    it('returns anonymous when user is null', () => {
      const req = { user: null };
      expect(getUserTier(req)).toBe('anonymous');
    });

    it('returns viewer for unknown roles', () => {
      const req = { user: { id: 3, role: 'unknown' } };
      expect(getUserTier(req)).toBe('viewer');
    });
  });

  describe('getTierLimits', () => {
    it('returns admin limits for admin users', () => {
      const req = { user: { id: 1, role: 'admin' } };
      const limits = getTierLimits(req, 'analyze');

      expect(limits).toEqual(USER_TIER_LIMITS.admin.analyze);
    });

    it('returns viewer limits for viewer users', () => {
      const req = { user: { id: 2, role: 'viewer' } };
      const limits = getTierLimits(req, 'analyze');

      expect(limits).toEqual(USER_TIER_LIMITS.viewer.analyze);
    });

    it('returns anonymous limits for unauthenticated requests', () => {
      const req = {};
      const limits = getTierLimits(req, 'analyze');

      expect(limits).toEqual(USER_TIER_LIMITS.anonymous.analyze);
    });

    it('returns correct limits for batch type', () => {
      const adminReq = { user: { id: 1, role: 'admin' } };
      const viewerReq = { user: { id: 2, role: 'viewer' } };
      const anonReq = {};

      expect(getTierLimits(adminReq, 'batch')).toEqual(USER_TIER_LIMITS.admin.batch);
      expect(getTierLimits(viewerReq, 'batch')).toEqual(USER_TIER_LIMITS.viewer.batch);
      expect(getTierLimits(anonReq, 'batch')).toEqual(USER_TIER_LIMITS.anonymous.batch);
    });

    it('returns correct limits for general type', () => {
      const adminReq = { user: { id: 1, role: 'admin' } };
      const limits = getTierLimits(adminReq, 'general');

      expect(limits).toEqual(USER_TIER_LIMITS.admin.general);
    });
  });

  describe('Rate limit values sanity checks', () => {
    it('all windowMs values are positive', () => {
      Object.values(USER_TIER_LIMITS).forEach((tier) => {
        Object.values(tier).forEach((limit) => {
          expect(limit.windowMs).toBeGreaterThan(0);
        });
      });
    });

    it('all max values are positive', () => {
      Object.values(USER_TIER_LIMITS).forEach((tier) => {
        Object.values(tier).forEach((limit) => {
          expect(limit.max).toBeGreaterThan(0);
        });
      });
    });

    it('windowMs is set to 1 minute for all limits', () => {
      const oneMinute = 60 * 1000;
      Object.values(USER_TIER_LIMITS).forEach((tier) => {
        Object.values(tier).forEach((limit) => {
          expect(limit.windowMs).toBe(oneMinute);
        });
      });
    });
  });
});
