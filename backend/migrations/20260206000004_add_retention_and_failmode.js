/**
 * Add data_retention_days and fail_mode columns to firewall_config.
 * - data_retention_days: how many days to keep request/egress logs (0 = keep forever)
 * - fail_mode: 'open' (503 on model failure) or 'closed' (block all when model is down)
 */
exports.up = function (knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.integer('data_retention_days').notNullable().defaultTo(90);
    table.string('fail_mode', 10).notNullable().defaultTo('open');
  });
};

exports.down = function (knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.dropColumn('data_retention_days');
    table.dropColumn('fail_mode');
  });
};
