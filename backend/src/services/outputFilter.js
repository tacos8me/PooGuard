/**
 * Output Filter Service
 *
 * Analyzes LLM responses for sensitive data before returning to users.
 * Calls the model-service /analyze-output endpoint to detect:
 * - PII (SSN, credit cards, emails, phone numbers)
 * - System prompt disclosure patterns
 * - API keys and secrets
 */

const { analyzeOutput } = require('./modelService');

/**
 * Default output filter configuration
 */
const DEFAULT_OUTPUT_CONFIG = {
  // Score thresholds for blocking
  thresholds: {
    pii: 0.3,
    systemPromptDisclosure: 0.3,
    secret: 0.3
  },
  // Actions per category: 'block', 'sanitize', 'allow'
  actions: {
    pii: 'sanitize',
    systemPromptDisclosure: 'block',
    secret: 'sanitize'
  }
};

/**
 * Determine what action to take based on analysis results and configuration
 * @param {Object} analysis - The analysis result from analyzeOutput
 * @param {Object} outputConfig - Output filter configuration (optional)
 * @returns {Object} Decision with action, reasons, and sanitizedOutput
 */
function shouldBlockOutput(analysis, outputConfig = DEFAULT_OUTPUT_CONFIG) {
  const { scores, detected, sanitized_output } = analysis;
  const { thresholds, actions } = outputConfig;

  const reasons = [];
  let finalAction = 'allow';

  // Check PII score
  if (scores.pii_score >= thresholds.pii) {
    const action = actions.pii;
    reasons.push({
      category: 'pii',
      score: scores.pii_score,
      action
    });
    if (action === 'block') {
      finalAction = 'block';
    } else if (action === 'sanitize' && finalAction !== 'block') {
      finalAction = 'sanitize';
    }
  }

  // Check system prompt disclosure score
  if (scores.system_prompt_disclosure_score >= thresholds.systemPromptDisclosure) {
    const action = actions.systemPromptDisclosure;
    reasons.push({
      category: 'system_prompt_disclosure',
      score: scores.system_prompt_disclosure_score,
      action
    });
    if (action === 'block') {
      finalAction = 'block';
    } else if (action === 'sanitize' && finalAction !== 'block') {
      finalAction = 'sanitize';
    }
  }

  // Check secret score
  if (scores.secret_score >= thresholds.secret) {
    const action = actions.secret;
    reasons.push({
      category: 'secret',
      score: scores.secret_score,
      action
    });
    if (action === 'block') {
      finalAction = 'block';
    } else if (action === 'sanitize' && finalAction !== 'block') {
      finalAction = 'sanitize';
    }
  }

  return {
    action: finalAction,
    blocked: finalAction === 'block',
    sanitized: finalAction === 'sanitize',
    reasons,
    detectedItems: detected,
    sanitizedOutput: finalAction === 'sanitize' ? sanitized_output : null,
    scores
  };
}

/**
 * Get default output filter configuration
 * @returns {Object} Default configuration
 */
function getDefaultConfig() {
  return { ...DEFAULT_OUTPUT_CONFIG };
}

module.exports = {
  analyzeOutput,
  shouldBlockOutput,
  getDefaultConfig,
  DEFAULT_OUTPUT_CONFIG
};
