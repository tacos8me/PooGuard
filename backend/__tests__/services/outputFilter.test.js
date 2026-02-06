/**
 * Tests for the Output Filter Service
 */

const { shouldBlockOutput, getDefaultConfig, DEFAULT_OUTPUT_CONFIG } = require('../../src/services/outputFilter');

describe('Output Filter Service', () => {
  describe('shouldBlockOutput', () => {
    it('should allow safe output with no detections', () => {
      const analysis = {
        safe: true,
        detected: [],
        sanitized_output: 'This is a safe response.',
        scores: {
          pii_score: 0.0,
          system_prompt_disclosure_score: 0.0,
          secret_score: 0.0
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.action).toBe('allow');
      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe(false);
      expect(result.reasons).toHaveLength(0);
    });

    it('should sanitize output with PII detected', () => {
      const analysis = {
        safe: false,
        detected: [
          { type: 'ssn', value: '[SSN REDACTED]', start: 10, end: 21 }
        ],
        sanitized_output: 'Your SSN: [SSN REDACTED]',
        scores: {
          pii_score: 0.4,
          system_prompt_disclosure_score: 0.0,
          secret_score: 0.0
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.action).toBe('sanitize');
      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe(true);
      expect(result.sanitizedOutput).toBe('Your SSN: [SSN REDACTED]');
      expect(result.reasons).toContainEqual(
        expect.objectContaining({ category: 'pii', action: 'sanitize' })
      );
    });

    it('should block output with system prompt disclosure', () => {
      const analysis = {
        safe: false,
        detected: [
          { type: 'system_prompt_disclosure', value: 'my instructions are', start: 0, end: 19 }
        ],
        sanitized_output: 'my instructions are to help users.',
        scores: {
          pii_score: 0.0,
          system_prompt_disclosure_score: 0.5,
          secret_score: 0.0
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.action).toBe('block');
      expect(result.blocked).toBe(true);
      expect(result.sanitized).toBe(false);
      expect(result.reasons).toContainEqual(
        expect.objectContaining({ category: 'system_prompt_disclosure', action: 'block' })
      );
    });

    it('should sanitize output with secrets detected', () => {
      const analysis = {
        safe: false,
        detected: [
          { type: 'api_key_openai', value: '[API KEY REDACTED]', start: 10, end: 50 }
        ],
        sanitized_output: 'API key: [API KEY REDACTED]',
        scores: {
          pii_score: 0.0,
          system_prompt_disclosure_score: 0.0,
          secret_score: 0.5
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.action).toBe('sanitize');
      expect(result.sanitized).toBe(true);
      expect(result.reasons).toContainEqual(
        expect.objectContaining({ category: 'secret', action: 'sanitize' })
      );
    });

    it('should block when multiple categories trigger and one is block', () => {
      const analysis = {
        safe: false,
        detected: [
          { type: 'ssn', value: '[SSN REDACTED]', start: 0, end: 15 },
          { type: 'system_prompt_disclosure', value: 'my instructions are', start: 20, end: 39 }
        ],
        sanitized_output: '[SSN REDACTED] my instructions are to help.',
        scores: {
          pii_score: 0.4,
          system_prompt_disclosure_score: 0.5,
          secret_score: 0.0
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.action).toBe('block');
      expect(result.blocked).toBe(true);
      expect(result.reasons).toHaveLength(2);
    });

    it('should respect custom configuration', () => {
      const analysis = {
        safe: false,
        detected: [
          { type: 'ssn', value: '[SSN REDACTED]', start: 10, end: 21 }
        ],
        sanitized_output: 'Your SSN: [SSN REDACTED]',
        scores: {
          pii_score: 0.4,
          system_prompt_disclosure_score: 0.0,
          secret_score: 0.0
        }
      };

      const customConfig = {
        thresholds: {
          pii: 0.3,
          systemPromptDisclosure: 0.3,
          secret: 0.3
        },
        actions: {
          pii: 'block',  // Changed from sanitize to block
          systemPromptDisclosure: 'block',
          secret: 'sanitize'
        }
      };

      const result = shouldBlockOutput(analysis, customConfig);

      expect(result.action).toBe('block');
      expect(result.blocked).toBe(true);
    });

    it('should allow output when scores are below thresholds', () => {
      const analysis = {
        safe: true,
        detected: [],
        sanitized_output: 'Safe text here.',
        scores: {
          pii_score: 0.1,
          system_prompt_disclosure_score: 0.1,
          secret_score: 0.1
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.action).toBe('allow');
      expect(result.blocked).toBe(false);
      expect(result.sanitized).toBe(false);
      expect(result.reasons).toHaveLength(0);
    });

    it('should include scores in result', () => {
      const analysis = {
        safe: true,
        detected: [],
        sanitized_output: 'Test',
        scores: {
          pii_score: 0.1,
          system_prompt_disclosure_score: 0.2,
          secret_score: 0.15
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.scores).toEqual({
        pii_score: 0.1,
        system_prompt_disclosure_score: 0.2,
        secret_score: 0.15
      });
    });

    it('should include detected items in result', () => {
      const analysis = {
        safe: false,
        detected: [
          { type: 'email', value: '[EMAIL REDACTED]', start: 0, end: 20 }
        ],
        sanitized_output: '[EMAIL REDACTED]',
        scores: {
          pii_score: 0.35,
          system_prompt_disclosure_score: 0.0,
          secret_score: 0.0
        }
      };

      const result = shouldBlockOutput(analysis);

      expect(result.detectedItems).toHaveLength(1);
      expect(result.detectedItems[0].type).toBe('email');
    });
  });

  describe('getDefaultConfig', () => {
    it('should return a copy of default configuration', () => {
      const config = getDefaultConfig();

      expect(config).toEqual(DEFAULT_OUTPUT_CONFIG);
      // Ensure it's a copy, not the same reference
      expect(config).not.toBe(DEFAULT_OUTPUT_CONFIG);
    });

    it('should have expected threshold values', () => {
      const config = getDefaultConfig();

      expect(config.thresholds.pii).toBe(0.3);
      expect(config.thresholds.systemPromptDisclosure).toBe(0.3);
      expect(config.thresholds.secret).toBe(0.3);
    });

    it('should have expected action values', () => {
      const config = getDefaultConfig();

      expect(config.actions.pii).toBe('sanitize');
      expect(config.actions.systemPromptDisclosure).toBe('block');
      expect(config.actions.secret).toBe('sanitize');
    });
  });

  describe('DEFAULT_OUTPUT_CONFIG', () => {
    it('should be a valid configuration object', () => {
      expect(DEFAULT_OUTPUT_CONFIG).toHaveProperty('thresholds');
      expect(DEFAULT_OUTPUT_CONFIG).toHaveProperty('actions');
      expect(DEFAULT_OUTPUT_CONFIG.thresholds).toHaveProperty('pii');
      expect(DEFAULT_OUTPUT_CONFIG.thresholds).toHaveProperty('systemPromptDisclosure');
      expect(DEFAULT_OUTPUT_CONFIG.thresholds).toHaveProperty('secret');
      expect(DEFAULT_OUTPUT_CONFIG.actions).toHaveProperty('pii');
      expect(DEFAULT_OUTPUT_CONFIG.actions).toHaveProperty('systemPromptDisclosure');
      expect(DEFAULT_OUTPUT_CONFIG.actions).toHaveProperty('secret');
    });
  });
});
