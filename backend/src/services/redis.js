const { createClient } = require('redis');
const config = require('../config');
const logger = require('./logger');

let client = null;
let subscriber = null;

const RECONNECT_MAX_DELAY = 30000;
const RECONNECT_BASE_DELAY = 1000;

const createReconnectClient = (name) => {
  const redisClient = createClient({
    url: config.redis.url,
    socket: {
      reconnectStrategy: (retries) => {
        const delay = Math.min(RECONNECT_BASE_DELAY * Math.pow(2, retries), RECONNECT_MAX_DELAY);
        logger.warn(`Redis ${name} reconnecting`, { retries, delayMs: delay });
        return delay;
      }
    }
  });

  redisClient.on('error', (err) => logger.error(`Redis ${name} error`, { error: err.message }));
  redisClient.on('connect', () => logger.info(`Redis ${name} connected`));
  redisClient.on('reconnecting', () => logger.info(`Redis ${name} reconnecting`));
  redisClient.on('ready', () => logger.info(`Redis ${name} ready`));

  return redisClient;
};

const getClient = async () => {
  if (!client) {
    client = createReconnectClient('client');
    await client.connect();
  }
  return client;
};

const getSubscriber = async () => {
  if (!subscriber) {
    subscriber = createReconnectClient('subscriber');
    await subscriber.connect();
  }
  return subscriber;
};

const closeAll = async () => {
  const errors = [];
  if (subscriber) {
    try { await subscriber.quit(); } catch (e) { errors.push(e); }
    subscriber = null;
  }
  if (client) {
    try { await client.quit(); } catch (e) { errors.push(e); }
    client = null;
  }
  if (errors.length) {
    logger.warn('Errors closing Redis connections', { count: errors.length });
  }
};

const publishEvent = async (channel, data) => {
  const redis = await getClient();
  await redis.publish(channel, JSON.stringify(data));
};

// --- Cache helpers ---
const cacheStats = { hits: 0, misses: 0 };

const cacheGet = async (key) => {
  const redis = await getClient();
  const value = await redis.get(key);
  if (value !== null) {
    cacheStats.hits++;
    return JSON.parse(value);
  }
  cacheStats.misses++;
  return null;
};

const cacheSet = async (key, value, ttlSeconds) => {
  const redis = await getClient();
  await redis.set(key, JSON.stringify(value), { EX: ttlSeconds });
};

const getCacheStats = () => {
  const total = cacheStats.hits + cacheStats.misses;
  return {
    hits: cacheStats.hits,
    misses: cacheStats.misses,
    hitRate: total > 0 ? cacheStats.hits / total : 0
  };
};

const resetCacheStats = () => {
  cacheStats.hits = 0;
  cacheStats.misses = 0;
};

const CHANNELS = {
  FIREWALL_EVENTS: 'firewall:events',
  ALERTS: 'alerts:triggered'
};

/**
 * Create a dedicated Redis client for blocking operations (e.g. BRPOP).
 * Unlike getClient(), each call returns a NEW independent connection
 * so blocking commands don't starve other Redis operations.
 */
const createDedicatedClient = async (name = 'dedicated') => {
  const dedicatedClient = createReconnectClient(name);
  await dedicatedClient.connect();
  return dedicatedClient;
};

module.exports = { getClient, getSubscriber, publishEvent, closeAll, CHANNELS, cacheGet, cacheSet, getCacheStats, resetCacheStats, createDedicatedClient };
