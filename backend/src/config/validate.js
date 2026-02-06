/**
 * Configuration validation module
 * Ensures all required environment variables are set before application starts
 */

class ConfigValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

/**
 * Validates the application configuration on startup
 * @throws {ConfigValidationError} If required configuration is missing or invalid
 */
function validateConfig() {
  const errors = [];
  const nodeEnv = process.env.NODE_ENV;

  // Check NODE_ENV is set
  if (!nodeEnv) {
    errors.push('NODE_ENV must be set (development, production, or test)');
  }

  const isProduction = nodeEnv === 'production';

  // In production, sensitive config must be explicitly set
  if (isProduction) {
    if (!process.env.DATABASE_URL) {
      errors.push('DATABASE_URL is required in production');
    }

    if (!process.env.REDIS_URL) {
      errors.push('REDIS_URL is required in production');
    }

    if (!process.env.JWT_SECRET) {
      errors.push('JWT_SECRET is required in production');
    }
  }

  // JWT_SECRET minimum length check (applies when set, regardless of environment)
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret && jwtSecret.length < 32) {
    errors.push('JWT_SECRET must be at least 32 characters long');
  }

  // In production, also validate JWT_SECRET length even if the above check passed
  if (isProduction && jwtSecret && jwtSecret.length < 32) {
    // Already added above, no duplicate needed
  }

  // If there are any validation errors, throw with all messages
  if (errors.length > 0) {
    const errorMessage = [
      'Configuration validation failed:',
      ...errors.map(err => `  - ${err}`),
      '',
      'Please set the required environment variables before starting the application.',
      'See .env.example for reference.'
    ].join('\n');

    throw new ConfigValidationError(errorMessage);
  }
}

module.exports = {
  validateConfig,
  ConfigValidationError
};
