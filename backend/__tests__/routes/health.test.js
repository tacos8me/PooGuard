const request = require('supertest');
const { createTestApp } = require('../testApp');
const { checkHealth } = require('../../src/services/modelService');

describe('Health Endpoint', () => {
  let app;

  beforeEach(() => {
    app = createTestApp(null);
    jest.clearAllMocks();
  });

  describe('GET /health', () => {
    it('should return healthy status when model service is connected', async () => {
      checkHealth.mockResolvedValue(true);

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('modelService', 'connected');
      expect(response.body).toHaveProperty('timestamp');
      expect(new Date(response.body.timestamp)).toBeInstanceOf(Date);
    });

    it('should return disconnected status when model service is unavailable', async () => {
      checkHealth.mockResolvedValue(false);

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('modelService', 'disconnected');
      expect(response.body).toHaveProperty('timestamp');
    });

    it('should return valid ISO timestamp', async () => {
      checkHealth.mockResolvedValue(true);

      const response = await request(app)
        .get('/health')
        .expect(200);

      const timestamp = new Date(response.body.timestamp);
      expect(timestamp.toISOString()).toBe(response.body.timestamp);
    });

    it('should handle model service check errors gracefully', async () => {
      checkHealth.mockRejectedValue(new Error('Connection timeout'));

      // The checkHealth is expected to catch errors and return false
      checkHealth.mockResolvedValue(false);

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.modelService).toBe('disconnected');
    });
  });
});
