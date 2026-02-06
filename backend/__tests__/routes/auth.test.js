const request = require('supertest');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createTestApp, createMockDb } = require('../testApp');
const config = require('../../src/config');

describe('Auth Routes', () => {
  let app;
  let mockDb;

  beforeEach(() => {
    mockDb = createMockDb();
    app = createTestApp(mockDb);
    jest.clearAllMocks();
  });

  afterEach(() => {
    if (mockDb.reset) {
      mockDb.reset();
    }
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(201);

      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body.user).toHaveProperty('id');
      expect(response.body.user).toHaveProperty('email', 'test@example.com');
      expect(response.body.user).toHaveProperty('role', 'viewer');

      // Verify token is valid JWT
      const decoded = jwt.verify(response.body.accessToken, config.jwt.secret);
      expect(decoded).toHaveProperty('id');
      expect(decoded).toHaveProperty('email', 'test@example.com');
    });

    it('should return 400 for invalid email', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'invalid-email',
          password: 'password123'
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
      expect(response.body.errors).toBeInstanceOf(Array);
      expect(response.body.errors[0]).toHaveProperty('path', 'email');
    });

    it('should return 400 for password shorter than 8 characters', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: 'short'
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
      expect(response.body.errors).toBeInstanceOf(Array);
      expect(response.body.errors[0]).toHaveProperty('path', 'password');
    });

    it('should return 400 when email is missing', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          password: 'password123'
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
    });

    it('should return 400 when password is missing', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com'
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
    });

    it('should normalize email to lowercase', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'Test@Example.COM',
          password: 'password123'
        })
        .expect(201);

      expect(response.body.user.email).toBe('test@example.com');
    });

    it('should return 409 when email already exists', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send({
          email: 'duplicate@example.com',
          password: 'password123'
        })
        .expect(201);

      // Second registration with same email
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'duplicate@example.com',
          password: 'password456'
        })
        .expect(409);

      expect(response.body).toHaveProperty('error', 'Email already registered');
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      // Create a test user before each login test
      await request(app)
        .post('/api/auth/register')
        .send({
          email: 'logintest@example.com',
          password: 'password123'
        });
    });

    it('should login successfully with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'logintest@example.com',
          password: 'password123'
        })
        .expect(200);

      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('accessToken');
      expect(response.body).toHaveProperty('refreshToken');
      expect(response.body.user).toHaveProperty('id');
      expect(response.body.user).toHaveProperty('email', 'logintest@example.com');
      expect(response.body.user).toHaveProperty('role');

      // Verify token is valid
      const decoded = jwt.verify(response.body.accessToken, config.jwt.secret);
      expect(decoded).toHaveProperty('email', 'logintest@example.com');
    });

    it('should return 401 for invalid password', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'logintest@example.com',
          password: 'wrongpassword'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should return 401 for non-existent user', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password123'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should return 400 for invalid email format', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'invalid-email',
          password: 'password123'
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
    });

    it('should return 400 when password is empty', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'logintest@example.com',
          password: ''
        })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
    });
  });

  describe('GET /api/auth/me', () => {
    let authToken;
    let userId;

    beforeEach(async () => {
      // Create and login a test user
      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'metest@example.com',
          password: 'password123'
        });

      authToken = registerResponse.body.accessToken;
      userId = registerResponse.body.user.id;
    });

    it('should return user info with valid token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('id', userId);
      expect(response.body.user).toHaveProperty('email', 'metest@example.com');
      expect(response.body.user).toHaveProperty('role');
    });

    it('should return 401 without token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'No token provided');
    });

    it('should return 401 with invalid token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid token');
    });

    it('should return 401 with malformed authorization header', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'NotBearer token')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'No token provided');
    });

    it('should return 401 with expired token', async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        { id: userId, email: 'metest@example.com', role: 'viewer' },
        config.jwt.secret,
        { expiresIn: '-1h' }
      );

      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid token');
    });
  });
});
