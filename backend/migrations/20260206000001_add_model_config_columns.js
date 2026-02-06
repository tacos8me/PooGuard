/**
 * Add model configuration columns to firewall_config table.
 * Stores upstream LLM endpoint settings for OAI-compatible proxy mode.
 */
exports.up = function (knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.string('model_endpoint_url', 500).nullable().defaultTo(null);
    table.text('model_api_key_encrypted').nullable().defaultTo(null);
    table.string('model_name', 255).nullable().defaultTo(null);
    table.string('model_provider_type', 50).notNullable().defaultTo('none');
  });
};

exports.down = function (knex) {
  return knex.schema.alterTable('firewall_config', (table) => {
    table.dropColumn('model_endpoint_url');
    table.dropColumn('model_api_key_encrypted');
    table.dropColumn('model_name');
    table.dropColumn('model_provider_type');
  });
};
