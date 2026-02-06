/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('egress_logs', (table) => {
    table.bigIncrements('id').primary();
    table.timestamp('timestamp').notNullable().defaultTo(knex.fn.now());
    table.string('path', 500).notNullable();
    table.string('method', 10).notNullable();
    table.uuid('user_id').nullable().references('id').inTable('users').onDelete('SET NULL');
    table.string('client_ip', 45).nullable();
    table.integer('status_code').notNullable();
    table.integer('response_size').notNullable();
    table.integer('secrets_detected').notNullable().defaultTo(0);
    table.integer('pii_detected').notNullable().defaultTo(0);
    table.jsonb('detected_types').notNullable().defaultTo('[]');

    // Indexes for common queries
    table.index('timestamp');
    table.index('user_id');
    table.index(['secrets_detected', 'pii_detected']);
    table.index(['timestamp', 'path']);
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTableIfExists('egress_logs');
};
