const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');
const { getClient } = require('./redis');
const logger = require('./logger');

const REFRESH_TOKEN_PREFIX = 'refresh_token:';
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60; // 7 days in seconds

/**
 * Generate an access token for a user
 * @param {Object} user - User object with id, email, role
 * @returns {string} JWT access token
 */
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    config.jwt.secret,
    { algorithm: 'HS256', expiresIn: config.jwt.accessToken.expiresIn }
  );
};

/**
 * Generate a refresh token for a user
 * @param {Object} _user - User object with id (unused, token is random)
 * @returns {string} Refresh token
 */
const generateRefreshToken = (_user) => {
  const token = crypto.randomBytes(64).toString('hex');
  return token;
};

/**
 * Store refresh token in Redis with TTL
 * @param {number} userId - User ID
 * @param {string} token - Refresh token
 */
const storeRefreshToken = async (userId, token) => {
  try {
    const redis = await getClient();
    const key = `${REFRESH_TOKEN_PREFIX}${token}`;
    await redis.set(key, userId.toString(), { EX: REFRESH_TOKEN_TTL });
    logger.info('Refresh token stored', { userId });
  } catch (error) {
    logger.error('Failed to store refresh token', { error: error.message, userId });
    throw error;
  }
};

/**
 * Validate refresh token by checking Redis
 * @param {string} token - Refresh token to validate
 * @returns {Object|null} { userId } if valid, null otherwise
 */
const validateRefreshToken = async (token) => {
  try {
    const redis = await getClient();
    const key = `${REFRESH_TOKEN_PREFIX}${token}`;
    const userId = await redis.get(key);

    if (!userId) {
      logger.warn('Invalid or expired refresh token');
      return null;
    }

    return { userId };
  } catch (error) {
    logger.error('Failed to validate refresh token', { error: error.message });
    throw error;
  }
};

/**
 * Revoke a specific refresh token
 * @param {string} token - Refresh token to revoke
 */
const revokeRefreshToken = async (token) => {
  try {
    const redis = await getClient();
    const key = `${REFRESH_TOKEN_PREFIX}${token}`;
    const result = await redis.del(key);
    logger.info('Refresh token revoked', { success: result > 0 });
    return result > 0;
  } catch (error) {
    logger.error('Failed to revoke refresh token', { error: error.message });
    throw error;
  }
};

/**
 * Revoke all refresh tokens for a user (optional - for logout all devices)
 * @param {number} userId - User ID
 */
const revokeAllUserRefreshTokens = async (userId) => {
  try {
    const redis = await getClient();
    const pattern = `${REFRESH_TOKEN_PREFIX}*`;

    // Scan for all refresh tokens and delete those belonging to this user
    let cursor = 0;
    let deletedCount = 0;

    do {
      const result = await redis.scan(cursor, { MATCH: pattern, COUNT: 100 });
      cursor = result.cursor;
      const keys = result.keys;

      for (const key of keys) {
        const storedUserId = await redis.get(key);
        if (storedUserId === userId.toString()) {
          await redis.del(key);
          deletedCount++;
        }
      }
    } while (cursor !== 0);

    logger.info('All user refresh tokens revoked', { userId, deletedCount });
    return deletedCount;
  } catch (error) {
    logger.error('Failed to revoke all user refresh tokens', { error: error.message, userId });
    throw error;
  }
};

/**
 * Rotate refresh token - revoke old one and issue new one
 * @param {string} oldToken - Current refresh token
 * @param {number} userId - User ID
 * @returns {string} New refresh token
 */
const rotateRefreshToken = async (oldToken, userId) => {
  await revokeRefreshToken(oldToken);
  const newToken = generateRefreshToken({ id: userId });
  await storeRefreshToken(userId, newToken);
  return newToken;
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  storeRefreshToken,
  validateRefreshToken,
  revokeRefreshToken,
  revokeAllUserRefreshTokens,
  rotateRefreshToken
};
