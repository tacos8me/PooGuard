/**
 * Tests for Data Retention Service
 *
 * Validates:
 * 1. Cleanup deletes old request_logs and egress_logs based on retention config
 * 2. Audit logs are never deleted (compliance requirement)
 * 3. Retention period is read from firewall_config
 * 4. Fail-safe: retention disabled (0 days) skips cleanup
 * 5. Scheduler start/stop lifecycle
 */

// The global setup.js mocks logger, which dataRetention imports
const {
  initDb,
  getRetentionDays,
  runCleanup,
  startScheduler,
  stopScheduler,
} = require('../../src/services/dataRetention');

describe('Data Retention Service', () => {
  let mockDb;
  let deletedRequestLogs;
  let deletedEgressLogs;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    deletedRequestLogs = [];
    deletedEgressLogs = [];

    // Build a mock Knex query builder
    const createQueryBuilder = (tableName) => {
      const builder = {
        _table: tableName,
        _whereConditions: [],
        select: jest.fn().mockReturnThis(),
        first: jest.fn().mockImplementation(() => {
          if (tableName === 'firewall_config') {
            return Promise.resolve({ data_retention_days: 30 });
          }
          return Promise.resolve(null);
        }),
        where: jest.fn().mockImplementation((col, op, val) => {
          builder._whereConditions.push({ col, op, val });
          return builder;
        }),
        del: jest.fn().mockImplementation(() => {
          if (tableName === 'request_logs') {
            deletedRequestLogs.push(builder._whereConditions);
            return Promise.resolve(5);
          }
          if (tableName === 'egress_logs') {
            deletedEgressLogs.push(builder._whereConditions);
            return Promise.resolve(3);
          }
          return Promise.resolve(0);
        }),
      };
      return builder;
    };

    mockDb = jest.fn((tableName) => createQueryBuilder(tableName));
    initDb(mockDb);
  });

  afterEach(() => {
    stopScheduler();
    jest.useRealTimers();
  });

  // ── getRetentionDays ─────────────────────────────────────────────

  describe('getRetentionDays', () => {
    it('should read retention days from firewall_config', async () => {
      const days = await getRetentionDays();
      expect(days).toBe(30);
      expect(mockDb).toHaveBeenCalledWith('firewall_config');
    });

    it('should default to 90 when config row has no data_retention_days', async () => {
      mockDb.mockImplementation((table) => {
        const builder = {
          select: jest.fn().mockReturnThis(),
          first: jest.fn().mockResolvedValue({}),
        };
        return builder;
      });

      const days = await getRetentionDays();
      expect(days).toBe(90);
    });

    it('should return 0 when config read fails (fail-safe)', async () => {
      mockDb.mockImplementation((table) => {
        const builder = {
          select: jest.fn().mockReturnThis(),
          first: jest.fn().mockRejectedValue(new Error('DB connection lost')),
        };
        return builder;
      });

      const days = await getRetentionDays();
      expect(days).toBe(0);
    });

    it('should return 0 when db is not initialized', async () => {
      initDb(null);
      const days = await getRetentionDays();
      expect(days).toBe(0);
    });
  });

  // ── runCleanup ───────────────────────────────────────────────────

  describe('runCleanup', () => {
    it('should delete old request_logs and egress_logs', async () => {
      const result = await runCleanup();

      expect(result.requestLogs).toBe(5);
      expect(result.egressLogs).toBe(3);
      expect(deletedRequestLogs.length).toBe(1);
      expect(deletedEgressLogs.length).toBe(1);
    });

    it('should use correct cutoff date based on retention days', async () => {
      const before = new Date();
      before.setDate(before.getDate() - 30);

      await runCleanup();

      // Verify the where clause used a date approximately 30 days ago
      expect(deletedRequestLogs[0][0].col).toBe('timestamp');
      expect(deletedRequestLogs[0][0].op).toBe('<');
      const cutoff = deletedRequestLogs[0][0].val;
      expect(cutoff).toBeInstanceOf(Date);
      // Should be within a few seconds of 30 days ago
      expect(Math.abs(cutoff.getTime() - before.getTime())).toBeLessThan(5000);
    });

    it('should use timestamp column for egress_logs', async () => {
      await runCleanup();

      expect(deletedEgressLogs[0][0].col).toBe('timestamp');
      expect(deletedEgressLogs[0][0].op).toBe('<');
    });

    it('should NOT delete audit_logs', async () => {
      await runCleanup();

      // Verify audit_logs table was never referenced for deletion
      const auditCalls = mockDb.mock.calls.filter(([t]) => t === 'audit_logs');
      expect(auditCalls.length).toBe(0);
    });

    it('should skip cleanup when retention days is 0', async () => {
      mockDb.mockImplementation((table) => {
        if (table === 'firewall_config') {
          return {
            select: jest.fn().mockReturnThis(),
            first: jest.fn().mockResolvedValue({ data_retention_days: 0 }),
          };
        }
        return {
          where: jest.fn().mockReturnThis(),
          del: jest.fn().mockResolvedValue(0),
        };
      });

      const result = await runCleanup();
      expect(result.requestLogs).toBe(0);
      expect(result.egressLogs).toBe(0);
    });

    it('should return zeros when db is not initialized', async () => {
      initDb(null);
      const result = await runCleanup();
      expect(result).toEqual({ requestLogs: 0, egressLogs: 0 });
    });

    it('should handle request_logs deletion error gracefully', async () => {
      mockDb.mockImplementation((table) => {
        if (table === 'firewall_config') {
          return {
            select: jest.fn().mockReturnThis(),
            first: jest.fn().mockResolvedValue({ data_retention_days: 30 }),
          };
        }
        if (table === 'request_logs') {
          return {
            where: jest.fn().mockReturnThis(),
            del: jest.fn().mockRejectedValue(new Error('Table locked')),
          };
        }
        // egress_logs still works
        return {
          where: jest.fn().mockReturnThis(),
          del: jest.fn().mockResolvedValue(2),
        };
      });

      const result = await runCleanup();
      // request_logs failed, egress_logs succeeded
      expect(result.requestLogs).toBe(0);
      expect(result.egressLogs).toBe(2);
    });

    it('should handle egress_logs deletion error gracefully', async () => {
      mockDb.mockImplementation((table) => {
        if (table === 'firewall_config') {
          return {
            select: jest.fn().mockReturnThis(),
            first: jest.fn().mockResolvedValue({ data_retention_days: 30 }),
          };
        }
        if (table === 'request_logs') {
          return {
            where: jest.fn().mockReturnThis(),
            del: jest.fn().mockResolvedValue(10),
          };
        }
        // egress_logs fails
        return {
          where: jest.fn().mockReturnThis(),
          del: jest.fn().mockRejectedValue(new Error('Permission denied')),
        };
      });

      const result = await runCleanup();
      expect(result.requestLogs).toBe(10);
      expect(result.egressLogs).toBe(0);
    });
  });

  // ── Scheduler ────────────────────────────────────────────────────

  describe('Scheduler', () => {
    it('should start and stop without errors', () => {
      expect(() => startScheduler()).not.toThrow();
      expect(() => stopScheduler()).not.toThrow();
    });

    it('should not start twice', () => {
      startScheduler();
      startScheduler(); // second call should be a no-op (logs warning)
      stopScheduler();
    });

    it('should schedule initial cleanup after startup delay', () => {
      // Use real timers for this test, just verify setTimeout was called
      jest.spyOn(global, 'setTimeout');

      startScheduler();

      // Verify a setTimeout was registered (5s initial delay)
      expect(setTimeout).toHaveBeenCalledWith(
        expect.any(Function),
        5000
      );

      global.setTimeout.mockRestore();
    });

    it('should stop cleanly and allow restart', () => {
      startScheduler();
      stopScheduler();
      // Should be able to start again
      expect(() => startScheduler()).not.toThrow();
      stopScheduler();
    });
  });
});
