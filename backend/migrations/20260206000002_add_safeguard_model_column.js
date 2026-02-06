/**
 * Add safeguard_model column to firewall_config table.
 * Controls which OSS-safeguard model the model-service loads (20b or 120b).
 */
exports.up = function (knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.string('safeguard_model', 50).notNullable().defaultTo('20b');
  });
};

exports.down = function (knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.dropColumn('safeguard_model');
  });
};
