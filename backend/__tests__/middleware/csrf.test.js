/**
 * Tests for CSRF Middleware
 */
const express = require('express');
const request = require('supertest');
const cookieParser = require('cookie-parser');
const {
  setCsrfCookie,
  verifyCsrfToken,
  csrfProtection,
  getCsrfTokenHandler,
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  generateToken,
} = require('../../src/middleware/csrf');

/**
 * Build a minimal Express app with CSRF middleware for testing.
 */
function createCsrfApp() {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());

  // Apply CSRF middleware globally
  app.use(setCsrfCookie);
  app.use(verifyCsrfToken);

  // CSRF token endpoint
  app.get('/api/csrf-token', getCsrfTokenHandler);

  // Test routes
  app.get('/api/test', (req, res) => res.json({ ok: true }));
  app.post('/api/test', (req, res) => res.json({ ok: true }));
  app.put('/api/test', (req, res) => res.json({ ok: true }));
  app.delete('/api/test', (req, res) => res.json({ ok: true }));

  // Excluded auth routes
  app.post('/api/auth/login', (req, res) => res.json({ ok: true }));
  app.post('/api/auth/register', (req, res) => res.json({ ok: true }));
  app.post('/api/auth/refresh', (req, res) => res.json({ ok: true }));

  return app;
}

/**
 * Helper: extract the XSRF-TOKEN cookie value from a response.
 */
function extractCsrfCookie(res) {
  const cookies = res.headers['set-cookie'];
  if (!cookies) return null;
  const arr = Array.isArray(cookies) ? cookies : [cookies];
  for (const c of arr) {
    if (c.startsWith(`${CSRF_COOKIE_NAME}=`)) {
      return c.split(';')[0].split('=')[1];
    }
  }
  return null;
}

describe('CSRF Middleware', () => {
  let app;

  beforeEach(() => {
    app = createCsrfApp();
  });

  describe('generateToken', () => {
    it('should generate a 64-character hex string', () => {
      const token = generateToken();
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should generate unique tokens', () => {
      const tokens = new Set(Array.from({ length: 10 }, () => generateToken()));
      expect(tokens.size).toBe(10);
    });
  });

  describe('setCsrfCookie', () => {
    it('should set a CSRF cookie on the first request', async () => {
      const res = await request(app).get('/api/test').expect(200);
      const token = extractCsrfCookie(res);
      expect(token).toBeTruthy();
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should not replace an existing CSRF cookie', async () => {
      const existingToken = generateToken();
      const res = await request(app)
        .get('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${existingToken}`)
        .expect(200);

      // Should not set a new cookie when one already exists
      const newToken = extractCsrfCookie(res);
      expect(newToken).toBeNull();
    });
  });

  describe('verifyCsrfToken - safe methods bypass', () => {
    it('should allow GET requests without a CSRF token', async () => {
      await request(app).get('/api/test').expect(200);
    });

    it('should allow HEAD requests without a CSRF token', async () => {
      await request(app).head('/api/test').expect(200);
    });

    it('should allow OPTIONS requests without a CSRF token', async () => {
      // OPTIONS may return 204 depending on CORS, but shouldn't be 403
      const res = await request(app).options('/api/test');
      expect(res.status).not.toBe(403);
    });
  });

  describe('verifyCsrfToken - excluded routes', () => {
    it('should allow POST /api/auth/login without CSRF token', async () => {
      await request(app).post('/api/auth/login').send({}).expect(200);
    });

    it('should allow POST /api/auth/register without CSRF token', async () => {
      await request(app).post('/api/auth/register').send({}).expect(200);
    });

    it('should allow POST /api/auth/refresh without CSRF token', async () => {
      await request(app).post('/api/auth/refresh').send({}).expect(200);
    });
  });

  describe('verifyCsrfToken - validation', () => {
    it('should reject POST without any CSRF token', async () => {
      const res = await request(app).post('/api/test').send({}).expect(403);
      expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
    });

    it('should reject POST with cookie but no header', async () => {
      const token = generateToken();
      const res = await request(app)
        .post('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${token}`)
        .send({})
        .expect(403);
      expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
    });

    it('should reject POST with header but no cookie', async () => {
      const token = generateToken();
      const res = await request(app)
        .post('/api/test')
        .set(CSRF_HEADER_NAME, token)
        .send({})
        .expect(403);
      expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
    });

    it('should reject POST when cookie and header tokens differ', async () => {
      const cookieToken = generateToken();
      const headerToken = generateToken();
      const res = await request(app)
        .post('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${cookieToken}`)
        .set(CSRF_HEADER_NAME, headerToken)
        .send({})
        .expect(403);
      expect(res.body.code).toBe('CSRF_TOKEN_MISMATCH');
    });

    it('should allow POST when cookie and header tokens match', async () => {
      const token = generateToken();
      await request(app)
        .post('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${token}`)
        .set(CSRF_HEADER_NAME, token)
        .send({})
        .expect(200);
    });

    it('should allow PUT when cookie and header tokens match', async () => {
      const token = generateToken();
      await request(app)
        .put('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${token}`)
        .set(CSRF_HEADER_NAME, token)
        .send({})
        .expect(200);
    });

    it('should allow DELETE when cookie and header tokens match', async () => {
      const token = generateToken();
      await request(app)
        .delete('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${token}`)
        .set(CSRF_HEADER_NAME, token)
        .expect(200);
    });
  });

  describe('verifyCsrfToken - timing-safe comparison', () => {
    it('should reject tokens of different lengths', async () => {
      const cookieToken = generateToken();
      const headerToken = 'short';
      const res = await request(app)
        .post('/api/test')
        .set('Cookie', `${CSRF_COOKIE_NAME}=${cookieToken}`)
        .set(CSRF_HEADER_NAME, headerToken)
        .send({})
        .expect(403);
      expect(res.body.code).toBe('CSRF_TOKEN_MISMATCH');
    });
  });

  describe('getCsrfTokenHandler', () => {
    it('should return a new token in the response body', async () => {
      const res = await request(app).get('/api/csrf-token').expect(200);
      expect(res.body).toHaveProperty('csrfToken');
      expect(res.body.csrfToken).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should set a CSRF cookie', async () => {
      const res = await request(app).get('/api/csrf-token').expect(200);
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      // At least one cookie should be the XSRF-TOKEN
      const csrfCookies = (Array.isArray(cookies) ? cookies : [cookies])
        .filter(c => c.startsWith(`${CSRF_COOKIE_NAME}=`));
      expect(csrfCookies.length).toBeGreaterThan(0);
    });
  });
});
