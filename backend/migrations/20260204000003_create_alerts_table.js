/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTable('alerts', (table) => {
    table.increments('id').primary();
    table.string('name', 255).notNullable();
    table.enum('type', ['rate', 'threshold', 'pattern', 'session_threat', 'access_pattern', 'config_change', 'repeat_block']).notNullable();
    table.jsonb('config').notNullable().defaultTo('{}');
    table.boolean('enabled').notNullable().defaultTo(true);
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now());

    // Index for enabled alerts lookup
    table.index('enabled');
    table.index('type');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTableIfExists('alerts');
};
