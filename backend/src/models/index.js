const knex = require('knex');
const knexConfig = require('../../knexfile');

// Determine environment
const environment = process.env.NODE_ENV || 'development';

// Get configuration for current environment
const config = knexConfig[environment];

if (!config) {
  throw new Error(`No database configuration found for environment: ${environment}`);
}

// Create and export the Knex instance
const db = knex(config);

// Test database connection on startup
db.raw('SELECT 1')
  .then(() => {
    console.log(`Database connected successfully (${environment})`);
  })
  .catch((err) => {
    console.error('Database connection failed:', err.message);
  });

module.exports = db;
