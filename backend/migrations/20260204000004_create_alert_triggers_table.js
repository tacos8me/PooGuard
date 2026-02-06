/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('alert_triggers', (table) => {
    table.bigIncrements('id').primary();
    table.integer('alert_id').notNullable().references('id').inTable('alerts').onDelete('CASCADE');
    table.timestamp('triggered_at').notNullable().defaultTo(knex.fn.now());
    table.jsonb('data').notNullable().defaultTo('{}');
    table.boolean('acknowledged').notNullable().defaultTo(false);
    table.timestamp('acknowledged_at').nullable();

    // Indexes for common queries
    table.index('alert_id');
    table.index('triggered_at');
    table.index('acknowledged');
    table.index(['alert_id', 'triggered_at']);
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTableIfExists('alert_triggers');
};
