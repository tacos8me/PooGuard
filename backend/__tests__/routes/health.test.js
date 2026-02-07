const request = require('supertest');
const { createTestApp } = require('../testApp');

describe('Health Endpoint', () => {
  let app;

  beforeEach(() => {
    app = createTestApp(null);
    jest.clearAllMocks();
  });

  describe('GET /health', () => {
    it('should return ok status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toEqual({ status: 'ok' });
    });

    it('should not expose internal details', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).not.toHaveProperty('uptime');
      expect(response.body).not.toHaveProperty('database');
      expect(response.body).not.toHaveProperty('redis');
      expect(response.body).not.toHaveProperty('modelService');
      expect(response.body).not.toHaveProperty('cache');
      expect(response.body).not.toHaveProperty('timestamp');
    });
  });
});
