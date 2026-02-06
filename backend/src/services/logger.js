const winston = require('winston');
const path = require('path');
const config = require('../config');

// Import daily rotate file transport if file logging is enabled
let DailyRotateFile;
const fileLoggingEnabled = process.env.LOG_FILE_ENABLED === 'true';

if (fileLoggingEnabled) {
  DailyRotateFile = require('winston-daily-rotate-file');
}

// Base transports - always include console
const transports = [
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  })
];

// Add file transports if file logging is enabled
if (fileLoggingEnabled && DailyRotateFile) {
  const logsDir = process.env.LOG_DIR || 'logs';

  // Combined log file for all levels
  const combinedTransport = new DailyRotateFile({
    filename: path.join(logsDir, 'app-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '14d',
    zippedArchive: true,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    )
  });

  // Separate error log file
  const errorTransport = new DailyRotateFile({
    filename: path.join(logsDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '14d',
    zippedArchive: true,
    level: 'error',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    )
  });

  // Handle rotation events
  combinedTransport.on('rotate', (oldFilename, newFilename) => {
    console.log(`Log rotated: ${oldFilename} -> ${newFilename}`);
  });

  errorTransport.on('rotate', (oldFilename, newFilename) => {
    console.log(`Error log rotated: ${oldFilename} -> ${newFilename}`);
  });

  transports.push(combinedTransport, errorTransport);
}

const logger = winston.createLogger({
  level: config.nodeEnv === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'pooguard-api' },
  transports
});

module.exports = logger;
