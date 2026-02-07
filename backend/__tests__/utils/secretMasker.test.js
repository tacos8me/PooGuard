const { mask, containsSecrets, detectSecretTypes, normalizeText, SECRET_PATTERNS } = require('../../src/utils/secretMasker');

describe('secretMasker', () => {
  describe('mask()', () => {
    it('should mask OpenAI API keys', () => {
      const input = 'my key is sk-testFAKE00000000000000000000000';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:openai_key]');
      expect(result.masked).not.toContain('sk-testFAKE');
      expect(result.detected.length).toBeGreaterThanOrEqual(1);
      expect(result.detected.some(d => d.type === 'openai_key')).toBe(true);
    });

    it('should mask Anthropic API keys', () => {
      const input = 'key: sk-ant-testFAKE0000000000000000000000';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:anthropic_key]');
      expect(result.masked).not.toContain('sk-ant-testFAKE');
    });

    it('should mask AWS access keys', () => {
      const input = 'AWS_ACCESS_KEY_ID=AKIAEXAMPLE00000FAKE';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:aws_key]');
      expect(result.masked).not.toContain('AKIAEXAMPLE00000FAKE');
    });

    it('should mask AWS secret keys', () => {
      const input = 'aws_secret_access_key="wJalrXUtnFEMI/EXAMPLEKEY000000000000FAKE"';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:aws_secret]');
      expect(result.masked).not.toContain('wJalrXUtnFEMI');
    });

    it('should mask GitHub personal access tokens', () => {
      const input = 'token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:github_token]');
      expect(result.masked).not.toContain('ghp_xxxx');
    });

    it('should mask GitHub OAuth tokens', () => {
      const input = 'oauth: gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:github_token]');
      expect(result.masked).not.toContain('gho_xxxx');
    });

    it('should mask GitHub app tokens (ghs_ and ghr_)', () => {
      const input = 'ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx and ghr_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy';
      const result = mask(input);
      expect(result.masked).not.toContain('ghs_xxxx');
      expect(result.masked).not.toContain('ghr_yyyy');
      expect(result.masked.match(/\[REDACTED:github_token\]/g).length).toBe(2);
    });

    it('should mask JWT tokens', () => {
      const input = 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:jwt]');
      expect(result.masked).not.toContain('eyJhbGciOiJIUzI1NiI');
    });

    it('should mask bearer tokens', () => {
      const input = 'Authorization: Bearer sk12345678901234567890';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:bearer_token]');
      expect(result.masked).not.toContain('sk12345678901234567890');
    });

    it('should mask generic API keys', () => {
      const input = 'api_key = "abcdef1234567890abcdef12"';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:api_key]');
      expect(result.masked).not.toContain('abcdef1234567890');
    });

    it('should mask database connection strings', () => {
      const input = 'postgres://user:password123@localhost:5432/mydb';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:db_url]');
      expect(result.masked).not.toContain('password123');
    });

    it('should mask MySQL connection strings', () => {
      const input = 'mysql://admin:secretpass@db.example.com/production';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:db_url]');
      expect(result.masked).not.toContain('secretpass');
    });

    it('should mask MongoDB connection strings', () => {
      const input = 'mongodb://user:pass@cluster.mongodb.net/database';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:db_url]');
      expect(result.masked).not.toContain('pass');
    });

    it('should mask private key headers', () => {
      const input = '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:private_key]');
    });

    it('should mask RSA private key headers', () => {
      const input = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBA...';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:private_key]');
    });

    it('should mask high entropy secrets', () => {
      const input = 'password="AbCdEf123456!@#$%^"';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:secret]');
      expect(result.masked).not.toContain('AbCdEf123456');
    });

    it('should not mask normal text', () => {
      const input = 'Hello, how are you today?';
      const result = mask(input);
      expect(result.masked).toBe(input);
      expect(result.detected).toHaveLength(0);
    });

    it('should not mask short strings that look like patterns', () => {
      const input = 'sk-short';
      const result = mask(input);
      expect(result.masked).toBe(input);
      expect(result.detected).toHaveLength(0);
    });

    it('should detect multiple secrets', () => {
      const input = 'key1: sk-testFAKE0000000000000aa and key2: ghp_TESTFAKE000000000000000000000000fake';
      const result = mask(input);
      expect(result.detected.length).toBeGreaterThanOrEqual(2);
      expect(result.masked).toContain('[REDACTED:openai_key]');
      expect(result.masked).toContain('[REDACTED:github_token]');
    });

    it('should handle empty string', () => {
      const result = mask('');
      expect(result.masked).toBe('');
      expect(result.detected).toHaveLength(0);
    });

    it('should handle null input', () => {
      const result = mask(null);
      expect(result.masked).toBe('');
      expect(result.detected).toHaveLength(0);
    });

    it('should handle undefined input', () => {
      const result = mask(undefined);
      expect(result.masked).toBe('');
      expect(result.detected).toHaveLength(0);
    });

    it('should return detected secrets sorted by position', () => {
      const input = 'first: ghp_TESTFAKE000000000000000000000000fake second: sk-testFAKE00000000000000000bb';
      const result = mask(input);
      expect(result.detected.length).toBeGreaterThanOrEqual(2);
      // Check that positions are sorted
      for (let i = 1; i < result.detected.length; i++) {
        expect(result.detected[i].position).toBeGreaterThanOrEqual(result.detected[i - 1].position);
      }
    });
  });

  describe('containsSecrets()', () => {
    it('should return true when OpenAI key present', () => {
      expect(containsSecrets('sk-testFAKE000000000000cc')).toBe(true);
    });

    it('should return true when GitHub token present', () => {
      expect(containsSecrets('ghp_TESTFAKE000000000000000000000000fake')).toBe(true);
    });

    it('should return true when AWS key present', () => {
      expect(containsSecrets('AKIAEXAMPLE00000FAKE')).toBe(true);
    });

    it('should return true when JWT present', () => {
      expect(containsSecrets('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123')).toBe(true);
    });

    it('should return false for normal text', () => {
      expect(containsSecrets('hello world')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(containsSecrets('')).toBe(false);
    });

    it('should return false for null', () => {
      expect(containsSecrets(null)).toBe(false);
    });

    it('should return false for undefined', () => {
      expect(containsSecrets(undefined)).toBe(false);
    });
  });

  describe('detectSecretTypes()', () => {
    it('should return array with openai_key for OpenAI keys', () => {
      const types = detectSecretTypes('sk-testFAKE000000000000cc');
      expect(types).toContain('openai_key');
    });

    it('should return array with github_pat for GitHub PATs', () => {
      const types = detectSecretTypes('ghp_TESTFAKE000000000000000000000000fake');
      expect(types).toContain('github_pat');
    });

    it('should return array with aws_access_key for AWS keys', () => {
      const types = detectSecretTypes('AKIAEXAMPLE00000FAKE');
      expect(types).toContain('aws_access_key');
    });

    it('should return array with jwt for JWT tokens', () => {
      const types = detectSecretTypes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc');
      expect(types).toContain('jwt');
    });

    it('should return multiple types for multiple secrets', () => {
      const input = 'sk-testFAKE000000000000cc and ghp_TESTFAKE000000000000000000000000fake';
      const types = detectSecretTypes(input);
      expect(types).toContain('openai_key');
      expect(types).toContain('github_pat');
    });

    it('should return empty array for normal text', () => {
      const types = detectSecretTypes('hello world');
      expect(types).toHaveLength(0);
    });

    it('should return empty array for null', () => {
      const types = detectSecretTypes(null);
      expect(types).toHaveLength(0);
    });

    it('should return empty array for undefined', () => {
      const types = detectSecretTypes(undefined);
      expect(types).toHaveLength(0);
    });
  });

  describe('cloud provider patterns', () => {
    it('should mask Azure account keys', () => {
      const input = 'AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:azure_key]');
      expect(result.masked).not.toContain('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==');
      expect(result.detected.some(d => d.type === 'azure_key')).toBe(true);
    });

    it('should mask GCP API keys', () => {
      const input = 'AIzaSyA1234567890abcdefghijklmnopqrstuvw';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:gcp_key]');
      expect(result.masked).not.toContain('AIzaSyA1234567890abcdefghijklmnopqrstuvw');
      expect(result.detected.some(d => d.type === 'gcp_api_key')).toBe(true);
    });

    it('should mask Stripe secret keys', () => {
      const input = 'sk_live_1234567890abcdefghijklmn';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:stripe_key]');
      expect(result.masked).not.toContain('sk_live_1234567890abcdefghijklmn');
      expect(result.detected.some(d => d.type === 'stripe_key')).toBe(true);
    });

    it('should mask Stripe publishable keys', () => {
      const input = 'pk_test_1234567890abcdefghijklmn';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:stripe_key]');
      expect(result.masked).not.toContain('pk_test_1234567890abcdefghijklmn');
    });

    it('should not match OpenAI keys with Stripe pattern', () => {
      const input = 'sk-testFAKE000000000000cc';
      const result = mask(input);
      expect(result.detected.some(d => d.type === 'stripe_key')).toBe(false);
      expect(result.detected.some(d => d.type === 'openai_key')).toBe(true);
    });

    it('should mask GitLab personal access tokens', () => {
      const input = 'glpat-abcdefghijklmnopqrst';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:gitlab_token]');
      expect(result.masked).not.toContain('glpat-abcdefghijklmnopqrst');
      expect(result.detected.some(d => d.type === 'gitlab_pat')).toBe(true);
    });

    it('should mask Slack bot tokens', () => {
      const input = 'xoxb-1234567890-abcdefghij';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:slack_token]');
      expect(result.masked).not.toContain('xoxb-1234567890-abcdefghij');
      expect(result.detected.some(d => d.type === 'slack_token')).toBe(true);
    });

    it('should mask Slack user tokens', () => {
      const input = 'xoxp-1234567890-abcdefghij';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:slack_token]');
      expect(result.masked).not.toContain('xoxp-1234567890-abcdefghij');
    });

    it('should mask NPM tokens', () => {
      const input = 'npm_abcdefghijklmnopqrstuvwxyz0123456789';
      const result = mask(input);
      expect(result.masked).toContain('[REDACTED:npm_token]');
      expect(result.masked).not.toContain('npm_abcdefghijklmnopqrstuvwxyz0123456789');
      expect(result.detected.some(d => d.type === 'npm_token')).toBe(true);
    });
  });

  describe('SECRET_PATTERNS', () => {
    it('should export SECRET_PATTERNS array', () => {
      expect(Array.isArray(SECRET_PATTERNS)).toBe(true);
      expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(10);
    });

    it('should have required properties for each pattern', () => {
      SECRET_PATTERNS.forEach(pattern => {
        expect(pattern).toHaveProperty('name');
        expect(pattern).toHaveProperty('pattern');
        expect(pattern).toHaveProperty('replacement');
        expect(typeof pattern.name).toBe('string');
        expect(pattern.pattern instanceof RegExp).toBe(true);
        expect(typeof pattern.replacement).toBe('string');
      });
    });

    it('should include patterns for common secret types', () => {
      const patternNames = SECRET_PATTERNS.map(p => p.name);
      expect(patternNames).toContain('openai_key');
      expect(patternNames).toContain('anthropic_key');
      expect(patternNames).toContain('aws_access_key');
      expect(patternNames).toContain('github_pat');
      expect(patternNames).toContain('jwt');
      expect(patternNames).toContain('private_key');
      expect(patternNames).toContain('db_url');
    });
  });

  describe('normalizeText()', () => {
    it('should decode base64 encoded secrets', () => {
      const secret = 'sk-testFAKE000000000000cc';
      const encoded = Buffer.from(secret).toString('base64');
      const result = normalizeText(encoded);
      expect(result).toContain(secret);
    });

    it('should decode hex encoded secrets', () => {
      const secret = 'sk-testFAKE000000000000cc';
      const encoded = Buffer.from(secret).toString('hex');
      const result = normalizeText(encoded);
      expect(result).toContain(secret);
    });

    it('should decode URL encoded text', () => {
      const text = 'key%3Dsk-testFAKE000000000000cc';
      const result = normalizeText(text);
      expect(result).toContain('key=sk-testFAKE000000000000cc');
    });

    it('should return original for normal text', () => {
      const text = 'Hello, this is normal text';
      const result = normalizeText(text);
      expect(result).toBe(text);
    });

    it('should handle empty string', () => {
      expect(normalizeText('')).toBe('');
    });

    it('should handle null', () => {
      expect(normalizeText(null)).toBe('');
    });
  });

  describe('encoded secret detection', () => {
    it('should detect base64-encoded OpenAI key in mask()', () => {
      const secret = 'sk-testFAKE000000000000cc';
      const encoded = Buffer.from(secret).toString('base64');
      const result = mask(`data: ${encoded}`);
      expect(result.detected.some(d => d.type === 'openai_key_encoded')).toBe(true);
      expect(result.masked).toContain('[REDACTED:openai_key_encoded]');
      expect(result.masked).not.toContain(encoded);
    });

    it('should detect base64-encoded secrets in containsSecrets()', () => {
      const secret = 'sk-testFAKE000000000000cc';
      const encoded = Buffer.from(secret).toString('base64');
      expect(containsSecrets(encoded)).toBe(true);
    });

    it('should detect base64-encoded secrets in detectSecretTypes()', () => {
      const secret = 'sk-testFAKE000000000000cc';
      const encoded = Buffer.from(secret).toString('base64');
      const types = detectSecretTypes(encoded);
      expect(types.some(t => t.includes('encoded'))).toBe(true);
    });

    it('should detect hex-encoded AWS key in mask()', () => {
      const secret = 'AKIAEXAMPLE00000FAKE';
      const encoded = Buffer.from(secret).toString('hex');
      const result = mask(encoded);
      expect(result.detected.some(d => d.type === 'aws_access_key_encoded')).toBe(true);
      expect(result.masked).toContain('[REDACTED:aws_access_key_encoded]');
    });

    it('should not false positive on normal base64 content', () => {
      // This is base64 but decodes to binary, not printable text with a secret
      const normalB64 = Buffer.from('This is just normal content without any secrets').toString('base64');
      const result = mask(normalB64);
      expect(result.detected.filter(d => d.type.includes('encoded'))).toHaveLength(0);
    });
  });
});
