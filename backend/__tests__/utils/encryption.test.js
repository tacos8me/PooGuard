/**
 * Tests for Encryption Utility (AES-256-GCM)
 */
const { encrypt, decrypt } = require('../../src/utils/encryption');

describe('Encryption Utility', () => {
  describe('encrypt', () => {
    it('should return null for null input', () => {
      expect(encrypt(null)).toBeNull();
    });

    it('should return null for empty string', () => {
      expect(encrypt('')).toBeNull();
    });

    it('should return null for undefined', () => {
      expect(encrypt(undefined)).toBeNull();
    });

    it('should return a non-empty encrypted string', () => {
      const result = encrypt('my-secret-key');
      expect(result).toBeTruthy();
      expect(typeof result).toBe('string');
    });

    it('should produce output different from input', () => {
      const plaintext = 'sk-abc123secretkey';
      const ciphertext = encrypt(plaintext);
      expect(ciphertext).not.toBe(plaintext);
    });

    it('should produce output in iv:authTag:ciphertext format', () => {
      const result = encrypt('test-data');
      const parts = result.split(':');
      expect(parts).toHaveLength(3);
      // Each part should be valid base64
      for (const part of parts) {
        expect(part.length).toBeGreaterThan(0);
      }
    });

    it('should produce different ciphertexts for the same input (random IV)', () => {
      const plaintext = 'same-input-text';
      const result1 = encrypt(plaintext);
      const result2 = encrypt(plaintext);
      expect(result1).not.toBe(result2);
    });

    it('should produce different ciphertexts for different inputs', () => {
      const result1 = encrypt('input-one');
      const result2 = encrypt('input-two');
      expect(result1).not.toBe(result2);
    });
  });

  describe('decrypt', () => {
    it('should return null for null input', () => {
      expect(decrypt(null)).toBeNull();
    });

    it('should return null for empty string', () => {
      expect(decrypt('')).toBeNull();
    });

    it('should return null for undefined', () => {
      expect(decrypt(undefined)).toBeNull();
    });

    it('should return null for malformed ciphertext', () => {
      expect(decrypt('not-valid-encrypted-data')).toBeNull();
    });

    it('should return null for tampered ciphertext', () => {
      const encrypted = encrypt('original-data');
      // Tamper with the ciphertext portion
      const parts = encrypted.split(':');
      parts[2] = 'AAAA' + parts[2].substring(4);
      const tampered = parts.join(':');
      expect(decrypt(tampered)).toBeNull();
    });

    it('should return null for tampered auth tag', () => {
      const encrypted = encrypt('original-data');
      const parts = encrypted.split(':');
      // Replace auth tag with garbage
      parts[1] = Buffer.from('tamperedauthtag!').toString('base64');
      const tampered = parts.join(':');
      expect(decrypt(tampered)).toBeNull();
    });
  });

  describe('encrypt/decrypt round-trip', () => {
    it('should round-trip a simple string', () => {
      const plaintext = 'hello world';
      expect(decrypt(encrypt(plaintext))).toBe(plaintext);
    });

    it('should round-trip an API key', () => {
      const apiKey = 'sk-proj-abc123def456ghi789';
      expect(decrypt(encrypt(apiKey))).toBe(apiKey);
    });

    it('should round-trip unicode text', () => {
      const text = 'Hello 世界 🔐';
      expect(decrypt(encrypt(text))).toBe(text);
    });

    it('should round-trip a long string', () => {
      const longText = 'a'.repeat(10000);
      expect(decrypt(encrypt(longText))).toBe(longText);
    });

    it('should round-trip special characters', () => {
      const special = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`\'"\\';
      expect(decrypt(encrypt(special))).toBe(special);
    });

    it('should round-trip a JSON string', () => {
      const json = JSON.stringify({ key: 'value', nested: { arr: [1, 2, 3] } });
      expect(decrypt(encrypt(json))).toBe(json);
    });
  });
});
