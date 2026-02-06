/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.boolean('cache_enabled').notNullable().defaultTo(true);
    table.integer('cache_ttl_seconds').notNullable().defaultTo(300);
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.dropColumn('cache_enabled');
    table.dropColumn('cache_ttl_seconds');
  });
};
