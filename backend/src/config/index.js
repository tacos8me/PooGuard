require('dotenv').config();

const isDevelopment = process.env.NODE_ENV === 'development';

// Only allow fallback values in development mode
const getConfigValue = (envVar, devFallback) => {
  const value = process.env[envVar];
  if (value) return value;
  if (isDevelopment) return devFallback;
  return undefined;
};

module.exports = {
  port: process.env.PORT || 3001,
  nodeEnv: process.env.NODE_ENV || 'development',

  database: {
    url: getConfigValue('DATABASE_URL', 'postgres://clawguard:devpassword@localhost:5432/clawguard_dev')
  },

  redis: {
    url: getConfigValue('REDIS_URL', 'redis://localhost:6379')
  },

  jwt: {
    secret: getConfigValue('JWT_SECRET', 'dev-secret-minimum-32-characters-long'),
    accessToken: {
      expiresIn: '15m'
    },
    refreshToken: {
      expiresIn: '7d'
    }
  },

  modelService: {
    url: process.env.MODEL_SERVICE_URL || 'http://localhost:8000',
    apiKey: process.env.MODEL_SERVICE_API_KEY || ''
  },

  firewall: {
    defaultThresholds: {
      promptInjection: 0.70,
      jailbreak: 0.70,
      pii: 0.70
    }
  }
};
