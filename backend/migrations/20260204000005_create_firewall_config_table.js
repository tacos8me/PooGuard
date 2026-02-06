/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('firewall_config', (table) => {
    table.increments('id').primary();

    // Threshold settings (0.0 to 1.0)
    table.decimal('threshold_prompt_injection', 5, 4).notNullable().defaultTo(0.7);
    table.decimal('threshold_jailbreak', 5, 4).notNullable().defaultTo(0.7);
    table.decimal('threshold_pii', 5, 4).notNullable().defaultTo(0.8);

    // Action settings (block, allow, flag)
    table.enum('action_prompt_injection', ['block', 'allow', 'flag']).notNullable().defaultTo('block');
    table.enum('action_jailbreak', ['block', 'allow', 'flag']).notNullable().defaultTo('block');
    table.enum('action_pii', ['block', 'allow', 'flag']).notNullable().defaultTo('flag');

    table.timestamp('updated_at').notNullable().defaultTo(knex.fn.now());
  }).then(() => {
    // Insert default configuration row
    return knex('firewall_config').insert({
      threshold_prompt_injection: 0.7,
      threshold_jailbreak: 0.7,
      threshold_pii: 0.8,
      action_prompt_injection: 'block',
      action_jailbreak: 'block',
      action_pii: 'flag'
    });
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTableIfExists('firewall_config');
};
