/**
 * Tests for Request Fingerprinter Service
 */

const {
  extractFingerprintComponents,
  generateFingerprintHash,
  generateIpAwareFingerprint,
  calculateTimingSimilarity,
  timesToIntervals,
  FINGERPRINT_TTL,
  TIMING_WINDOW_SIZE,
  TIMING_SIMILARITY_THRESHOLD,
  MIN_REQUESTS_FOR_PATTERN,
} = require('../../src/services/fingerprinter');

// Mock redis service
jest.mock('../../src/services/redis', () => ({
  getClient: jest.fn().mockResolvedValue(null),
  publishEvent: jest.fn().mockResolvedValue(undefined),
  CHANNELS: {
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

describe('Request Fingerprinter Service', () => {
  describe('Constants', () => {
    it('FINGERPRINT_TTL is 24 hours', () => {
      expect(FINGERPRINT_TTL).toBe(24 * 60 * 60);
    });

    it('TIMING_WINDOW_SIZE is reasonable', () => {
      expect(TIMING_WINDOW_SIZE).toBeGreaterThanOrEqual(5);
      expect(TIMING_WINDOW_SIZE).toBeLessThanOrEqual(100);
    });

    it('TIMING_SIMILARITY_THRESHOLD is between 0 and 1', () => {
      expect(TIMING_SIMILARITY_THRESHOLD).toBeGreaterThan(0);
      expect(TIMING_SIMILARITY_THRESHOLD).toBeLessThanOrEqual(1);
    });

    it('MIN_REQUESTS_FOR_PATTERN is at least 3', () => {
      expect(MIN_REQUESTS_FOR_PATTERN).toBeGreaterThanOrEqual(3);
    });
  });

  describe('extractFingerprintComponents', () => {
    it('extracts core components from request', () => {
      const req = {
        ip: '192.168.1.1',
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
        },
      };

      const components = extractFingerprintComponents(req);

      expect(components.ip).toBe('192.168.1.1');
      expect(components.userAgent).toContain('Mozilla');
      expect(components.acceptLanguage).toBe('en-US,en;q=0.9');
      expect(components.acceptEncoding).toBe('gzip, deflate, br');
    });

    it('handles missing headers gracefully', () => {
      const req = {
        ip: '10.0.0.1',
        headers: {},
      };

      const components = extractFingerprintComponents(req);

      expect(components.ip).toBe('10.0.0.1');
      expect(components.userAgent).toBe('unknown');
      expect(components.acceptLanguage).toBe('');
    });

    it('extracts Chrome Client Hints', () => {
      const req = {
        ip: '192.168.1.1',
        headers: {
          'user-agent': 'Chrome/120',
          'sec-ch-ua': '"Chromium";v="120", "Google Chrome";v="120"',
          'sec-ch-ua-platform': '"Windows"',
          'sec-ch-ua-mobile': '?0',
        },
      };

      const components = extractFingerprintComponents(req);

      expect(components.secChUa).toContain('Chromium');
      expect(components.secChUaPlatform).toBe('"Windows"');
      expect(components.secChUaMobile).toBe('?0');
    });

    it('extracts forwarded headers', () => {
      const req = {
        ip: '10.0.0.1',
        headers: {
          'user-agent': 'Browser',
          'x-forwarded-for': '203.0.113.195, 70.41.3.18',
          'x-real-ip': '203.0.113.195',
        },
      };

      const components = extractFingerprintComponents(req);

      expect(components.xForwardedFor).toBe('203.0.113.195, 70.41.3.18');
      expect(components.xRealIp).toBe('203.0.113.195');
    });

    it('falls back to connection.remoteAddress when ip is missing', () => {
      const req = {
        connection: { remoteAddress: '172.16.0.1' },
        headers: { 'user-agent': 'Test' },
      };

      const components = extractFingerprintComponents(req);

      expect(components.ip).toBe('172.16.0.1');
    });

    it('returns unknown for missing IP', () => {
      const req = {
        headers: { 'user-agent': 'Test' },
      };

      const components = extractFingerprintComponents(req);

      expect(components.ip).toBe('unknown');
    });
  });

  describe('generateFingerprintHash', () => {
    it('generates consistent hash for same components', () => {
      const components = {
        userAgent: 'Mozilla/5.0',
        acceptLanguage: 'en-US',
        acceptEncoding: 'gzip',
        secChUa: 'Chrome',
        secChUaPlatform: 'Windows',
      };

      const hash1 = generateFingerprintHash(components);
      const hash2 = generateFingerprintHash(components);

      expect(hash1).toBe(hash2);
    });

    it('generates different hash for different user agents', () => {
      const components1 = {
        userAgent: 'Mozilla/5.0 Chrome',
        acceptLanguage: 'en-US',
        acceptEncoding: 'gzip',
        secChUa: '',
        secChUaPlatform: '',
      };
      const components2 = {
        userAgent: 'Mozilla/5.0 Firefox',
        acceptLanguage: 'en-US',
        acceptEncoding: 'gzip',
        secChUa: '',
        secChUaPlatform: '',
      };

      const hash1 = generateFingerprintHash(components1);
      const hash2 = generateFingerprintHash(components2);

      expect(hash1).not.toBe(hash2);
    });

    it('generates 16-character hash', () => {
      const components = {
        userAgent: 'Test',
        acceptLanguage: 'en',
        acceptEncoding: 'gzip',
        secChUa: '',
        secChUaPlatform: '',
      };

      const hash = generateFingerprintHash(components);

      expect(hash).toHaveLength(16);
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('is not affected by IP changes', () => {
      const baseComponents = {
        userAgent: 'Mozilla/5.0',
        acceptLanguage: 'en-US',
        acceptEncoding: 'gzip',
        secChUa: '',
        secChUaPlatform: '',
      };

      const componentsIp1 = { ...baseComponents, ip: '192.168.1.1' };
      const componentsIp2 = { ...baseComponents, ip: '10.0.0.1' };

      const hash1 = generateFingerprintHash(componentsIp1);
      const hash2 = generateFingerprintHash(componentsIp2);

      expect(hash1).toBe(hash2);
    });
  });

  describe('generateIpAwareFingerprint', () => {
    it('generates different hash for different IPs', () => {
      const components1 = {
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        acceptLanguage: 'en-US',
      };
      const components2 = {
        ip: '10.0.0.1',
        userAgent: 'Mozilla/5.0',
        acceptLanguage: 'en-US',
      };

      const hash1 = generateIpAwareFingerprint(components1);
      const hash2 = generateIpAwareFingerprint(components2);

      expect(hash1).not.toBe(hash2);
    });

    it('generates consistent hash for same IP and UA', () => {
      const components = {
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        acceptLanguage: 'en-US',
      };

      const hash1 = generateIpAwareFingerprint(components);
      const hash2 = generateIpAwareFingerprint(components);

      expect(hash1).toBe(hash2);
    });

    it('generates 16-character hash', () => {
      const components = {
        ip: '192.168.1.1',
        userAgent: 'Test',
        acceptLanguage: 'en',
      };

      const hash = generateIpAwareFingerprint(components);

      expect(hash).toHaveLength(16);
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('timesToIntervals', () => {
    it('converts timestamps to intervals', () => {
      const times = [1000, 2000, 3500, 5000];
      const intervals = timesToIntervals(times);

      expect(intervals).toEqual([1000, 1500, 1500]);
    });

    it('returns empty array for single timestamp', () => {
      const times = [1000];
      const intervals = timesToIntervals(times);

      expect(intervals).toEqual([]);
    });

    it('returns empty array for empty input', () => {
      const intervals = timesToIntervals([]);

      expect(intervals).toEqual([]);
    });

    it('handles two timestamps', () => {
      const times = [1000, 3000];
      const intervals = timesToIntervals(times);

      expect(intervals).toEqual([2000]);
    });
  });

  describe('calculateTimingSimilarity', () => {
    it('returns 1 for identical patterns', () => {
      const pattern = [100, 200, 300, 400];
      const similarity = calculateTimingSimilarity(pattern, pattern);

      expect(similarity).toBeCloseTo(1, 2);
    });

    it('returns 0 for empty patterns', () => {
      expect(calculateTimingSimilarity([], [100, 200])).toBe(0);
      expect(calculateTimingSimilarity([100, 200], [])).toBe(0);
      expect(calculateTimingSimilarity([], [])).toBe(0);
    });

    it('returns high similarity for proportionally similar patterns', () => {
      const pattern1 = [100, 200, 300, 400];
      const pattern2 = [200, 400, 600, 800]; // Same ratios, doubled

      const similarity = calculateTimingSimilarity(pattern1, pattern2);

      expect(similarity).toBeGreaterThan(0.9);
    });

    it('returns lower similarity for different patterns', () => {
      const pattern1 = [100, 200, 300, 400];
      const pattern2 = [500, 100, 700, 50]; // Random different pattern

      const similarity = calculateTimingSimilarity(pattern1, pattern2);

      expect(similarity).toBeLessThan(0.5);
    });

    it('handles patterns of different lengths', () => {
      const pattern1 = [100, 200, 300];
      const pattern2 = [100, 200, 300, 400, 500];

      const similarity = calculateTimingSimilarity(pattern1, pattern2);

      expect(similarity).toBeCloseTo(1, 2);
    });

    it('handles constant patterns', () => {
      const pattern1 = [100, 100, 100, 100];
      const pattern2 = [200, 200, 200, 200];

      // Constant patterns should be similar (both normalized to same shape)
      const similarity = calculateTimingSimilarity(pattern1, pattern2);

      expect(similarity).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Fingerprinter class', () => {
    const { fingerprinter } = require('../../src/services/fingerprinter');

    it('fingerprints without Redis connection', async () => {
      const req = {
        ip: '192.168.1.1',
        headers: {
          'user-agent': 'Mozilla/5.0 Test Browser',
          'accept-language': 'en-US',
        },
      };

      const result = await fingerprinter.fingerprint(req);

      expect(result).toHaveProperty('browserFingerprint');
      expect(result).toHaveProperty('ipFingerprint');
      expect(result).toHaveProperty('components');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('linkedFingerprints');
      expect(result).toHaveProperty('suspiciousPatterns');
      expect(result).toHaveProperty('riskScore');

      expect(result.browserFingerprint).toHaveLength(16);
      expect(result.ipFingerprint).toHaveLength(16);
      expect(result.linkedFingerprints).toEqual([]);
      expect(result.suspiciousPatterns).toEqual([]);
      expect(result.riskScore).toBe(0);
    });

    it('includes truncated components in result', async () => {
      const longUserAgent = 'Mozilla/5.0 ' + 'A'.repeat(200);
      const req = {
        ip: '192.168.1.1',
        headers: {
          'user-agent': longUserAgent,
          'accept-language': 'en-US,en;q=0.9,fr;q=0.8' + ',de;q=0.7'.repeat(20),
        },
      };

      const result = await fingerprinter.fingerprint(req);

      expect(result.components.userAgent.length).toBeLessThanOrEqual(100);
      expect(result.components.acceptLanguage.length).toBeLessThanOrEqual(50);
    });

    it('getStats returns zeros without Redis', async () => {
      const stats = await fingerprinter.getStats();

      expect(stats).toEqual({ active: 0, suspicious: 0 });
    });

    it('findSimilarByTiming returns empty without Redis', async () => {
      const similar = await fingerprinter.findSimilarByTiming('testfingerprint');

      expect(similar).toEqual([]);
    });
  });

  describe('Edge cases', () => {
    it('handles request with no headers object', () => {
      const req = {
        ip: '192.168.1.1',
      };

      const components = extractFingerprintComponents(req);

      expect(components.ip).toBe('192.168.1.1');
      expect(components.userAgent).toBe('unknown');
    });

    it('handles undefined request properties', () => {
      const req = {
        ip: undefined,
        headers: {
          'user-agent': undefined,
        },
      };

      const components = extractFingerprintComponents(req);

      expect(components.ip).toBe('unknown');
      expect(components.userAgent).toBe('unknown');
    });
  });
});
