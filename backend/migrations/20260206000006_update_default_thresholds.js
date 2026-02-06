/**
 * Calibration-validated thresholds (Feb 2026).
 *
 * After benchmarking 294 examples against the live safeguard model, the
 * original 0.70/0.70/0.70 defaults proved optimal for the "Balanced" preset.
 * Model scores are bimodal (0.0 or 0.8-0.95), so any threshold in the
 * 0.01-0.79 range catches the same detections.
 *
 * This migration keeps the seed values intact. The previous version
 * briefly changed thresholds to F1-optimal values (0.85/0.80/0.85),
 * which we reverted back to 0.70 for simplicity and consistency.
 *
 * Preset profiles (configured in Settings UI):
 *   High Security: PI=0.40, JB=0.40, PII=0.50
 *   Balanced:      PI=0.70, JB=0.70, PII=0.70
 *   Low Friction:  PI=0.90, JB=0.90, PII=0.90
 *
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex('firewall_config')
    .update({
      threshold_prompt_injection: 0.70,
      threshold_jailbreak: 0.70,
      threshold_pii: 0.70,
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex('firewall_config')
    .update({
      threshold_prompt_injection: 0.7,
      threshold_jailbreak: 0.7,
      threshold_pii: 0.7,
    });
};
