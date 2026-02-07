/**
 * Secret Masker Utility
 * Detects and masks sensitive patterns in text
 */

const SECRET_PATTERNS = [
  // OpenAI/Anthropic API keys
  { name: 'openai_key', pattern: /sk-[a-zA-Z0-9]{20,}/, replacement: '[REDACTED:openai_key]' },
  { name: 'anthropic_key', pattern: /sk-ant-[a-zA-Z0-9-]{20,}/, replacement: '[REDACTED:anthropic_key]' },

  // Generic API keys
  { name: 'api_key', pattern: /(?:api[_-]?key|apikey)["\s:=]+["']?([a-zA-Z0-9_-]{20,})["']?/i, replacement: '[REDACTED:api_key]' },
  { name: 'bearer_token', pattern: /bearer\s+[a-zA-Z0-9_.-]{20,}/i, replacement: '[REDACTED:bearer_token]' },

  // AWS credentials
  { name: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/, replacement: '[REDACTED:aws_key]' },
  { name: 'aws_secret', pattern: /(?:aws)?[_-]?secret[_-]?(?:access)?[_-]?key["\s:=]+["']?([a-zA-Z0-9/+=]{40})["']?/i, replacement: '[REDACTED:aws_secret]' },

  // GitHub tokens
  { name: 'github_pat', pattern: /ghp_[a-zA-Z0-9]{36}/, replacement: '[REDACTED:github_token]' },
  { name: 'github_oauth', pattern: /gho_[a-zA-Z0-9]{36}/, replacement: '[REDACTED:github_token]' },
  { name: 'github_app', pattern: /(?:ghs|ghr)_[a-zA-Z0-9]{36}/, replacement: '[REDACTED:github_token]' },

  // JWT tokens
  { name: 'jwt', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, replacement: '[REDACTED:jwt]' },

  // Private keys
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, replacement: '[REDACTED:private_key]' },

  // Database connection strings
  { name: 'db_url', pattern: /(?:postgres|mysql|mongodb):\/\/[^:]+:[^@]+@[^\s]+/i, replacement: '[REDACTED:db_url]' },

  // Azure keys
  { name: 'azure_key', pattern: /(?:AccountKey|azure[_-]?(?:api[_-]?)?key)["\s:=]+["']?([a-zA-Z0-9/+=]{44,88})["']?/i, replacement: '[REDACTED:azure_key]' },

  // GCP API keys (AIza prefix)
  { name: 'gcp_api_key', pattern: /AIza[0-9A-Za-z\-_]{35}/, replacement: '[REDACTED:gcp_key]' },

  // Stripe API keys (sk_live_, sk_test_, pk_live_, pk_test_)
  { name: 'stripe_key', pattern: /(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}/, replacement: '[REDACTED:stripe_key]' },

  // GitLab Personal Access Tokens (glpat- prefix)
  { name: 'gitlab_pat', pattern: /glpat-[0-9a-zA-Z_-]{20,}/, replacement: '[REDACTED:gitlab_token]' },

  // Slack tokens (xoxb-, xoxp-, xoxa-, xoxo-)
  { name: 'slack_token', pattern: /xox[bpao]-[0-9a-zA-Z-]{10,}/, replacement: '[REDACTED:slack_token]' },

  // NPM tokens (npm_ prefix)
  { name: 'npm_token', pattern: /npm_[0-9a-zA-Z]{36,}/, replacement: '[REDACTED:npm_token]' },

  // High entropy strings (potential secrets) - be careful with false positives
  { name: 'high_entropy', pattern: /(?:password|secret|token|key)["\s:=]{1,10}["']?([a-zA-Z0-9!@#$%^&*]{16,128})["']?/i, replacement: '[REDACTED:secret]' },
];

/**
 * Create a fresh RegExp from an existing pattern to avoid shared lastIndex state.
 * This prevents race conditions when the same pattern is used across concurrent requests.
 * @param {RegExp} pattern - The source pattern
 * @param {string} [extraFlags] - Additional flags to append (e.g. 'g')
 * @returns {RegExp}
 */
function freshRegex(pattern, extraFlags = '') {
  const flags = extraFlags
    ? pattern.flags + (pattern.flags.includes(extraFlags) ? '' : extraFlags)
    : pattern.flags;
  return new RegExp(pattern.source, flags);
}

/**
 * Normalize text by decoding common encoding schemes.
 * Catches encoded/obfuscated secrets in base64, hex, and URL encoding.
 * @param {string} text - Input text that may contain encoded secrets
 * @returns {string} Original text with decoded segments appended
 */
function normalizeText(text) {
  if (!text || typeof text !== 'string') return text || '';

  const decodedParts = [];

  // Try base64 decoding of segments (min 20 chars)
  const base64Re = /[A-Za-z0-9+/]{20,}={0,2}/g;
  let match;
  while ((match = base64Re.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(match[0], 'base64').toString('utf-8');
      if (decoded && /^[\x20-\x7e]+$/.test(decoded)) {
        decodedParts.push(decoded);
      }
    } catch { /* not valid base64 */ }
  }

  // Try URL decoding
  if (/%[0-9a-fA-F]{2}/.test(text)) {
    try {
      const urlDecoded = decodeURIComponent(text);
      if (urlDecoded !== text) decodedParts.push(urlDecoded);
    } catch { /* invalid URL encoding */ }
  }

  // Try hex decoding of segments (min 20 hex chars)
  const hexRe = /(?:0x)?([0-9a-fA-F]{20,})/g;
  while ((match = hexRe.exec(text)) !== null) {
    const hexStr = match[1];
    if (hexStr.length % 2 !== 0) continue;
    try {
      const decoded = Buffer.from(hexStr, 'hex').toString('utf-8');
      if (decoded && /^[\x20-\x7e]+$/.test(decoded)) {
        decodedParts.push(decoded);
      }
    } catch { /* not valid hex */ }
  }

  if (decodedParts.length === 0) return text;
  return text + ' ' + decodedParts.join(' ');
}

/**
 * Mask all detected secrets in text
 * @param {string} text - Input text to mask
 * @returns {{ masked: string, detected: Array<{type: string, position: number}> }}
 */
function mask(text) {
  if (!text || typeof text !== 'string') {
    return { masked: text || '', detected: [] };
  }

  let masked = text;
  const detected = [];

  for (const { name, pattern, replacement } of SECRET_PATTERNS) {
    const globalPattern = freshRegex(pattern, 'g');

    let match;
    while ((match = globalPattern.exec(text)) !== null) {
      detected.push({
        type: name,
        position: match.index
      });
    }

    masked = masked.replace(freshRegex(pattern, 'g'), replacement);
  }

  // Second pass: detect secrets hidden in encoded segments (base64, hex)
  const encodedReplacements = [];

  // Check base64-encoded segments
  const base64Re = /[A-Za-z0-9+/]{20,}={0,2}/g;
  let b64Match;
  while ((b64Match = base64Re.exec(masked)) !== null) {
    try {
      const decoded = Buffer.from(b64Match[0], 'base64').toString('utf-8');
      if (decoded && /^[\x20-\x7e]+$/.test(decoded)) {
        for (const { name, pattern: pat } of SECRET_PATTERNS) {
          if (freshRegex(pat).test(decoded)) {
            detected.push({ type: `${name}_encoded`, position: b64Match.index });
            encodedReplacements.push({
              start: b64Match.index,
              end: b64Match.index + b64Match[0].length,
              replacement: `[REDACTED:${name}_encoded]`,
            });
            break;
          }
        }
      }
    } catch { /* not valid base64 */ }
  }

  // Check hex-encoded segments
  const hexRe = /(?:0x)?([0-9a-fA-F]{20,})/g;
  let hexMatch;
  while ((hexMatch = hexRe.exec(masked)) !== null) {
    const hexStr = hexMatch[1];
    if (hexStr.length % 2 !== 0) continue;
    try {
      const decoded = Buffer.from(hexStr, 'hex').toString('utf-8');
      if (decoded && /^[\x20-\x7e]+$/.test(decoded)) {
        for (const { name, pattern: pat } of SECRET_PATTERNS) {
          if (freshRegex(pat).test(decoded)) {
            detected.push({ type: `${name}_encoded`, position: hexMatch.index });
            encodedReplacements.push({
              start: hexMatch.index,
              end: hexMatch.index + hexMatch[0].length,
              replacement: `[REDACTED:${name}_encoded]`,
            });
            break;
          }
        }
      }
    } catch { /* not valid hex */ }
  }

  // Apply encoded replacements in reverse order to maintain positions
  encodedReplacements.sort((a, b) => b.start - a.start);
  for (const { start, end, replacement } of encodedReplacements) {
    masked = masked.substring(0, start) + replacement + masked.substring(end);
  }

  // Sort detected by position
  detected.sort((a, b) => a.position - b.position);

  // Remove duplicate detections at the same position (can happen with overlapping patterns)
  const uniqueDetected = detected.filter((item, index, self) =>
    index === self.findIndex((t) => t.position === item.position && t.type === item.type)
  );

  return { masked, detected: uniqueDetected };
}

/**
 * Check if text contains any secrets
 * @param {string} text - Input text to check
 * @returns {boolean}
 */
function containsSecrets(text) {
  if (!text || typeof text !== 'string') {
    return false;
  }

  for (const { pattern } of SECRET_PATTERNS) {
    if (freshRegex(pattern).test(text)) {
      return true;
    }
  }

  // Also check decoded forms for encoded secrets
  const normalized = normalizeText(text);
  if (normalized !== text) {
    for (const { pattern } of SECRET_PATTERNS) {
      if (freshRegex(pattern).test(normalized)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Get list of detected secret types
 * @param {string} text - Input text to analyze
 * @returns {Array<string>}
 */
function detectSecretTypes(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const types = [];

  for (const { name, pattern } of SECRET_PATTERNS) {
    if (freshRegex(pattern).test(text)) {
      types.push(name);
    }
  }

  // Also check decoded forms for encoded secrets
  const normalized = normalizeText(text);
  if (normalized !== text) {
    for (const { name, pattern } of SECRET_PATTERNS) {
      if (freshRegex(pattern).test(normalized) && !types.includes(name)) {
        types.push(`${name}_encoded`);
      }
    }
  }

  return types;
}

module.exports = {
  mask,
  containsSecrets,
  detectSecretTypes,
  normalizeText,
  SECRET_PATTERNS, // Export for testing
};
