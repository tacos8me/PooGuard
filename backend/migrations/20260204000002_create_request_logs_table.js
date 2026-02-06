/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('request_logs', (table) => {
    table.bigIncrements('id').primary();
    table.timestamp('timestamp').notNullable().defaultTo(knex.fn.now());
    table.text('input_text').notNullable();
    table.jsonb('threat_scores').notNullable().defaultTo('{}');
    table.enum('action', ['blocked', 'allowed', 'flagged', 'batch']).notNullable();
    table.integer('latency_ms').notNullable();
    table.uuid('user_id').nullable().references('id').inTable('users').onDelete('SET NULL');
    table.string('client_ip', 45).nullable();
    table.boolean('is_authenticated').notNullable().defaultTo(false);

    // Indexes for common queries
    table.index('timestamp');
    table.index('action');
    table.index('user_id');
    table.index('client_ip');
    table.index(['timestamp', 'action']);
    table.index(['client_ip', 'timestamp', 'action']);
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTableIfExists('request_logs');
};
