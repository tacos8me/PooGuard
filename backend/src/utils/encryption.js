/**
 * AES-256-GCM encryption utility for storing sensitive config values (API keys).
 * Key is derived from JWT_SECRET via scrypt.
 */
const crypto = require('crypto');
const config = require('../config');

const ALGORITHM = 'aes-256-gcm';
const SALT = process.env.ENCRYPTION_SALT || (() => {
  if (process.env.NODE_ENV === 'production') {
    console.warn('WARNING: ENCRYPTION_SALT not set. Set it in production for key isolation.');
  }
  return 'pooguard-encryption-salt';
})();
const IV_LENGTH = 12;
// GCM auth tag length: 16 bytes (default)

let derivedKey = null;

function getKey() {
  if (!derivedKey) {
    derivedKey = crypto.scryptSync(config.jwt.secret, SALT, 32);
  }
  return derivedKey;
}

/**
 * Encrypt a plaintext string.
 * @param {string|null} plaintext
 * @returns {string|null} Base64-encoded "iv:authTag:ciphertext", or null if input is empty
 */
function encrypt(plaintext) {
  if (!plaintext) return null;

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const authTag = cipher.getAuthTag();

  return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
}

/**
 * Decrypt an encrypted string.
 * @param {string|null} encrypted - Base64-encoded "iv:authTag:ciphertext"
 * @returns {string|null} Decrypted plaintext, or null if input is empty
 */
function decrypt(encrypted) {
  if (!encrypted) return null;

  try {
    const [ivB64, authTagB64, ciphertext] = encrypted.split(':');

    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(authTagB64, 'base64');
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (_err) {
    // Decryption failed — key may have changed or data is corrupt
    return null;
  }
}

module.exports = { encrypt, decrypt };
