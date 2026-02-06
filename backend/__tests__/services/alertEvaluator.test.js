/**
 * Tests for Enhanced Alert Evaluator Service
 */

const {
  ALERT_TYPES,
  DEFAULTS,
  evaluateThresholdAlert,
  evaluateSessionThreatAlert,
  evaluateConfigChangeAlert,
} = require('../../src/services/alertEvaluator');

// Mock redis service
jest.mock('../../src/services/redis', () => ({
  getClient: jest.fn().mockResolvedValue(null),
  publishEvent: jest.fn().mockResolvedValue(undefined),
  CHANNELS: {
    ALERTS: 'alerts:triggered',
    FIREWALL_EVENTS: 'firewall:events',
  },
}));

// Mock logger
jest.mock('../../src/services/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

describe('Alert Evaluator Service', () => {
  describe('ALERT_TYPES', () => {
    it('defines all required alert types', () => {
      expect(ALERT_TYPES.THRESHOLD).toBe('threshold');
      expect(ALERT_TYPES.RATE).toBe('rate');
      expect(ALERT_TYPES.SESSION_THREAT).toBe('session_threat');
      expect(ALERT_TYPES.ACCESS_PATTERN).toBe('access_pattern');
      expect(ALERT_TYPES.CONFIG_CHANGE).toBe('config_change');
      expect(ALERT_TYPES.REPEAT_BLOCK).toBe('repeat_block');
    });

    it('has 6 alert types', () => {
      expect(Object.keys(ALERT_TYPES)).toHaveLength(6);
    });
  });

  describe('DEFAULTS', () => {
    it('defines session threat threshold', () => {
      expect(DEFAULTS.SESSION_THREAT_THRESHOLD).toBe(2.0);
    });

    it('defines repeat block configuration', () => {
      expect(DEFAULTS.REPEAT_BLOCK_COUNT).toBe(5);
      expect(DEFAULTS.REPEAT_BLOCK_WINDOW_MINUTES).toBe(10);
    });

    it('defines access pattern configuration', () => {
      expect(DEFAULTS.ACCESS_PATTERN_WINDOW_MINUTES).toBe(60);
      expect(DEFAULTS.ACCESS_PATTERN_THRESHOLD_MULTIPLIER).toBe(3);
    });

    it('defines cooldown period', () => {
      expect(DEFAULTS.COOLDOWN_MINUTES).toBe(5);
    });
  });

  describe('evaluateThresholdAlert', () => {
    it('returns false for non-blocked events', async () => {
      const alert = {
        id: 1,
        config: { threatType: 'prompt_injection', threshold: 0.8 },
      };
      const event = {
        action: 'allowed',
        threatScores: { prompt_injection: 0.9 },
      };

      const result = await evaluateThresholdAlert(alert, event);

      expect(result).toBe(false);
    });

    it('returns false when score is below threshold', async () => {
      const alert = {
        id: 1,
        config: { threatType: 'prompt_injection', threshold: 0.8 },
      };
      const event = {
        action: 'blocked',
        threatScores: { prompt_injection: 0.5 },
      };

      const result = await evaluateThresholdAlert(alert, event);

      expect(result).toBe(false);
    });

    it('returns false for missing config', async () => {
      const alert = {
        id: 1,
        config: {},
      };
      const event = {
        action: 'blocked',
        threatScores: { prompt_injection: 0.9 },
      };

      const result = await evaluateThresholdAlert(alert, event);

      expect(result).toBe(false);
    });

    it('handles missing threatScores gracefully', async () => {
      const alert = {
        id: 1,
        config: { threatType: 'prompt_injection', threshold: 0.8 },
      };
      const event = {
        action: 'blocked',
        threatScores: null,
      };

      const result = await evaluateThresholdAlert(alert, event);

      expect(result).toBe(false);
    });
  });

  describe('evaluateSessionThreatAlert', () => {
    it('returns false when no session threat alert info', async () => {
      const alert = {
        id: 1,
        config: { threshold: 2.0 },
      };
      const event = {
        action: 'blocked',
      };

      const result = await evaluateSessionThreatAlert(alert, event);

      expect(result).toBe(false);
    });

    it('returns false when cumulative score is below threshold', async () => {
      const alert = {
        id: 1,
        config: { threshold: 2.0 },
      };
      const event = {
        sessionThreatAlert: {
          sessionId: 'user:1',
          cumulativeScore: 1.5,
        },
      };

      const result = await evaluateSessionThreatAlert(alert, event);

      expect(result).toBe(false);
    });

    it('uses default threshold when not configured', async () => {
      const alert = {
        id: 1,
        config: {},
      };
      const event = {
        sessionThreatAlert: {
          sessionId: 'user:1',
          cumulativeScore: 1.5, // Below default 2.0
        },
      };

      const result = await evaluateSessionThreatAlert(alert, event);

      expect(result).toBe(false);
    });
  });

  describe('evaluateConfigChangeAlert', () => {
    it('returns false when no config change data', async () => {
      const alert = {
        id: 1,
        config: {},
      };

      const result = await evaluateConfigChangeAlert(alert, null);

      expect(result).toBe(false);
    });

    it('returns false when config change type is not config_update', async () => {
      const alert = {
        id: 1,
        config: {},
      };
      const configChange = {
        type: 'other',
      };

      const result = await evaluateConfigChangeAlert(alert, configChange);

      expect(result).toBe(false);
    });
  });

  describe('Alert type validation', () => {
    it('all alert types are strings', () => {
      Object.values(ALERT_TYPES).forEach((type) => {
        expect(typeof type).toBe('string');
      });
    });

    it('alert types are lowercase', () => {
      Object.values(ALERT_TYPES).forEach((type) => {
        expect(type).toBe(type.toLowerCase());
      });
    });

    it('alert types use snake_case', () => {
      Object.values(ALERT_TYPES).forEach((type) => {
        expect(type).toMatch(/^[a-z]+(_[a-z]+)*$/);
      });
    });
  });

  describe('Default values validation', () => {
    it('all defaults are positive numbers', () => {
      Object.values(DEFAULTS).forEach((value) => {
        expect(typeof value).toBe('number');
        expect(value).toBeGreaterThan(0);
      });
    });

    it('window minutes are reasonable', () => {
      expect(DEFAULTS.REPEAT_BLOCK_WINDOW_MINUTES).toBeGreaterThanOrEqual(1);
      expect(DEFAULTS.REPEAT_BLOCK_WINDOW_MINUTES).toBeLessThanOrEqual(60);

      expect(DEFAULTS.ACCESS_PATTERN_WINDOW_MINUTES).toBeGreaterThanOrEqual(1);
      expect(DEFAULTS.ACCESS_PATTERN_WINDOW_MINUTES).toBeLessThanOrEqual(1440); // 24 hours
    });

    it('thresholds are reasonable', () => {
      expect(DEFAULTS.SESSION_THREAT_THRESHOLD).toBeGreaterThan(0);
      expect(DEFAULTS.SESSION_THREAT_THRESHOLD).toBeLessThanOrEqual(10);

      expect(DEFAULTS.ACCESS_PATTERN_THRESHOLD_MULTIPLIER).toBeGreaterThanOrEqual(1);
      expect(DEFAULTS.ACCESS_PATTERN_THRESHOLD_MULTIPLIER).toBeLessThanOrEqual(10);
    });

    it('count thresholds are reasonable', () => {
      expect(DEFAULTS.REPEAT_BLOCK_COUNT).toBeGreaterThanOrEqual(3);
      expect(DEFAULTS.REPEAT_BLOCK_COUNT).toBeLessThanOrEqual(100);

      expect(DEFAULTS.COOLDOWN_MINUTES).toBeGreaterThanOrEqual(1);
      expect(DEFAULTS.COOLDOWN_MINUTES).toBeLessThanOrEqual(60);
    });
  });
});
