/**
 * Tests for Audit Log Middleware
 */

const {
  initDb,
  ACTION_TYPES,
  createAuditLog,
  queryAuditLogs,
  getAuditLogById,
} = require('../../src/middleware/auditLog');

// Mock the logger
jest.mock('../../src/services/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

// Create mock database
const mockDb = {
  insert: jest.fn().mockReturnThis(),
  returning: jest.fn().mockResolvedValue([{ id: 1 }]),
  where: jest.fn().mockReturnThis(),
  first: jest.fn().mockResolvedValue(null),
  orderBy: jest.fn().mockReturnThis(),
  limit: jest.fn().mockReturnThis(),
  offset: jest.fn().mockReturnThis(),
  count: jest.fn().mockResolvedValue([{ count: '0' }]),
};

const mockKnex = jest.fn((tableName) => {
  if (tableName === 'audit_logs') {
    return mockDb;
  }
  return mockDb;
});

describe('Audit Log Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    initDb(mockKnex);
  });

  describe('ACTION_TYPES', () => {
    it('defines config actions', () => {
      expect(ACTION_TYPES.CONFIG_VIEW).toBe('config.view');
      expect(ACTION_TYPES.CONFIG_UPDATE).toBe('config.update');
    });

    it('defines user management actions', () => {
      expect(ACTION_TYPES.USER_CREATE).toBe('user.create');
      expect(ACTION_TYPES.USER_UPDATE).toBe('user.update');
      expect(ACTION_TYPES.USER_DELETE).toBe('user.delete');
      expect(ACTION_TYPES.USER_ROLE_CHANGE).toBe('user.role_change');
    });

    it('defines alert actions', () => {
      expect(ACTION_TYPES.ALERT_CREATE).toBe('alert.create');
      expect(ACTION_TYPES.ALERT_UPDATE).toBe('alert.update');
      expect(ACTION_TYPES.ALERT_DELETE).toBe('alert.delete');
      expect(ACTION_TYPES.ALERT_ACKNOWLEDGE).toBe('alert.acknowledge');
    });

    it('defines session actions', () => {
      expect(ACTION_TYPES.SESSION_RESET).toBe('session.reset');
      expect(ACTION_TYPES.SESSION_CLEAR).toBe('session.clear');
    });

    it('defines system actions', () => {
      expect(ACTION_TYPES.SYSTEM_EXPORT).toBe('system.export');
      expect(ACTION_TYPES.SYSTEM_PURGE).toBe('system.purge');
    });
  });

  describe('createAuditLog', () => {
    it('creates audit log entry with all fields', async () => {
      const params = {
        userId: 1,
        userEmail: 'admin@example.com',
        action: ACTION_TYPES.CONFIG_UPDATE,
        resource: 'firewall_config',
        resourceId: null,
        oldValue: { threshold: 0.7 },
        newValue: { threshold: 0.8 },
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        metadata: { reason: 'security update' },
      };

      const result = await createAuditLog(params);

      expect(result).toEqual({ id: 1 });
      expect(mockDb.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          user_id: 1,
          user_email: 'admin@example.com',
          action: 'config.update',
          resource: 'firewall_config',
        })
      );
    });

    it('handles null oldValue and newValue', async () => {
      const params = {
        userId: 1,
        userEmail: 'admin@example.com',
        action: ACTION_TYPES.CONFIG_VIEW,
        resource: 'firewall_config',
        ipAddress: '192.168.1.1',
      };

      await createAuditLog(params);

      expect(mockDb.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          old_value: null,
          new_value: null,
        })
      );
    });

    it('serializes values to JSON', async () => {
      const params = {
        userId: 1,
        userEmail: 'admin@example.com',
        action: ACTION_TYPES.CONFIG_UPDATE,
        resource: 'firewall_config',
        oldValue: { a: 1 },
        newValue: { a: 2 },
        ipAddress: '192.168.1.1',
      };

      await createAuditLog(params);

      expect(mockDb.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          old_value: '{"a":1}',
          new_value: '{"a":2}',
        })
      );
    });

    it('truncates long user agent', async () => {
      const longUserAgent = 'A'.repeat(600);
      const params = {
        userId: 1,
        userEmail: 'admin@example.com',
        action: ACTION_TYPES.CONFIG_VIEW,
        resource: 'firewall_config',
        ipAddress: '192.168.1.1',
        userAgent: longUserAgent,
      };

      await createAuditLog(params);

      expect(mockDb.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          user_agent: expect.any(String),
        })
      );

      const insertCall = mockDb.insert.mock.calls[0][0];
      expect(insertCall.user_agent.length).toBeLessThanOrEqual(500);
    });

    it('returns null and logs warning when db not initialized', async () => {
      initDb(null);
      const logger = require('../../src/services/logger');

      const result = await createAuditLog({
        userId: 1,
        userEmail: 'test@example.com',
        action: 'test',
        resource: 'test',
        ipAddress: '127.0.0.1',
      });

      expect(result).toBeNull();
      expect(logger.warn).toHaveBeenCalledWith('Audit log: Database not initialized');
    });
  });

  describe('queryAuditLogs', () => {
    it('returns empty result when db not initialized', async () => {
      initDb(null);

      const result = await queryAuditLogs({});

      expect(result).toEqual({ logs: [], total: 0 });
    });

    it('queries with filters', async () => {
      const mockQueryDb = {
        where: jest.fn().mockReturnThis(),
        orderBy: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        offset: jest.fn().mockReturnThis(),
        count: jest.fn().mockResolvedValue([{ count: '5' }]),
      };

      // Mock returns empty array for this test
      mockQueryDb.offset.mockResolvedValue([]);

      const queryKnex = jest.fn(() => mockQueryDb);
      initDb(queryKnex);

      await queryAuditLogs({
        userId: 1,
        action: 'config.update',
        resource: 'firewall_config',
        limit: 10,
        offset: 0,
      });

      expect(mockQueryDb.where).toHaveBeenCalled();
    });
  });

  describe('getAuditLogById', () => {
    it('returns null when db not initialized', async () => {
      initDb(null);

      const result = await getAuditLogById(1);

      expect(result).toBeNull();
    });

    it('returns null when log not found', async () => {
      mockDb.first.mockResolvedValueOnce(null);

      const result = await getAuditLogById(999);

      expect(result).toBeNull();
    });

    it('parses JSON fields in returned log', async () => {
      mockDb.first.mockResolvedValueOnce({
        id: 1,
        old_value: '{"threshold":0.7}',
        new_value: '{"threshold":0.8}',
        metadata: '{"reason":"test"}',
      });

      const result = await getAuditLogById(1);

      expect(result.old_value).toEqual({ threshold: 0.7 });
      expect(result.new_value).toEqual({ threshold: 0.8 });
      expect(result.metadata).toEqual({ reason: 'test' });
    });
  });
});
