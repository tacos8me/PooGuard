const jwt = require('jsonwebtoken');
const { authMiddleware, optionalAuth, requireAdmin } = require('../../src/middleware/auth');
const config = require('../../src/config');

describe('Auth Middleware', () => {
  let mockReq;
  let mockRes;
  let nextFn;

  beforeEach(() => {
    mockReq = {
      headers: {}
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    nextFn = jest.fn();
    jest.clearAllMocks();
  });

  describe('authMiddleware', () => {
    it('should call next() with valid token', () => {
      const token = jwt.sign(
        { id: 1, email: 'test@example.com', role: 'viewer' },
        config.jwt.secret,
        { expiresIn: '1h' }
      );
      mockReq.headers.authorization = `Bearer ${token}`;

      authMiddleware(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
      expect(mockReq.user.id).toBe(1);
      expect(mockReq.user.email).toBe('test@example.com');
      expect(mockReq.user.role).toBe('viewer');
    });

    it('should return 401 when no authorization header', () => {
      authMiddleware(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'No token provided' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 401 when authorization header does not start with Bearer', () => {
      mockReq.headers.authorization = 'Basic sometoken';

      authMiddleware(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'No token provided' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 401 with invalid token', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      authMiddleware(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 401 with expired token', () => {
      const token = jwt.sign(
        { id: 1, email: 'test@example.com', role: 'viewer' },
        config.jwt.secret,
        { expiresIn: '-1h' }
      );
      mockReq.headers.authorization = `Bearer ${token}`;

      authMiddleware(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 401 with token signed with wrong secret', () => {
      const token = jwt.sign(
        { id: 1, email: 'test@example.com', role: 'viewer' },
        'wrong-secret',
        { expiresIn: '1h' }
      );
      mockReq.headers.authorization = `Bearer ${token}`;

      authMiddleware(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid token' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should extract user data from token payload', () => {
      const userData = {
        id: 42,
        email: 'admin@example.com',
        role: 'admin'
      };
      const token = jwt.sign(userData, config.jwt.secret, { expiresIn: '1h' });
      mockReq.headers.authorization = `Bearer ${token}`;

      authMiddleware(mockReq, mockRes, nextFn);

      expect(mockReq.user.id).toBe(42);
      expect(mockReq.user.email).toBe('admin@example.com');
      expect(mockReq.user.role).toBe('admin');
    });
  });

  describe('optionalAuth', () => {
    it('should call next() and set user with valid token', () => {
      const token = jwt.sign(
        { id: 1, email: 'test@example.com', role: 'viewer' },
        config.jwt.secret,
        { expiresIn: '1h' }
      );
      mockReq.headers.authorization = `Bearer ${token}`;

      optionalAuth(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
      expect(mockReq.user.id).toBe(1);
    });

    it('should call next() without user when no authorization header', () => {
      optionalAuth(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockReq.user).toBeUndefined();
    });

    it('should call next() without user when token is invalid', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      optionalAuth(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockReq.user).toBeUndefined();
    });

    it('should call next() without user when authorization header is malformed', () => {
      mockReq.headers.authorization = 'NotBearer token';

      optionalAuth(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockReq.user).toBeUndefined();
    });

    it('should call next() without user when token is expired', () => {
      const token = jwt.sign(
        { id: 1, email: 'test@example.com', role: 'viewer' },
        config.jwt.secret,
        { expiresIn: '-1h' }
      );
      mockReq.headers.authorization = `Bearer ${token}`;

      optionalAuth(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
      expect(mockReq.user).toBeUndefined();
    });
  });

  describe('requireAdmin', () => {
    it('should call next() when user is admin', () => {
      mockReq.user = { id: 1, email: 'admin@example.com', role: 'admin' };

      requireAdmin(mockReq, mockRes, nextFn);

      expect(nextFn).toHaveBeenCalled();
    });

    it('should return 403 when user is not admin', () => {
      mockReq.user = { id: 1, email: 'user@example.com', role: 'viewer' };

      requireAdmin(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Admin access required' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 403 when user is not set', () => {
      requireAdmin(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Admin access required' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 403 when user role is operator', () => {
      mockReq.user = { id: 1, email: 'operator@example.com', role: 'operator' };

      requireAdmin(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Admin access required' });
      expect(nextFn).not.toHaveBeenCalled();
    });

    it('should return 403 when user role is undefined', () => {
      mockReq.user = { id: 1, email: 'user@example.com' };

      requireAdmin(mockReq, mockRes, nextFn);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Admin access required' });
      expect(nextFn).not.toHaveBeenCalled();
    });
  });
});
