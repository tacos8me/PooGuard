/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.string('analysis_mode', 10).notNullable().defaultTo('sync');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.dropColumn('analysis_mode');
  });
};
