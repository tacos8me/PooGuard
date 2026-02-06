/**
 * Create api_keys table for external client authentication on /v1 proxy routes.
 * Keys are stored as SHA-256 hashes; the raw key is shown once on creation.
 */
exports.up = function(knex) {
  return knex.schema.createTable('api_keys', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('key_prefix', 10).notNullable();
    table.string('key_hash', 64).notNullable().unique();
    table.string('name', 255).notNullable();
    table.timestamp('last_used_at').nullable();
    table.timestamp('expires_at').nullable();
    table.timestamp('revoked_at').nullable();
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now());

    table.index('user_id');
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('api_keys');
};
