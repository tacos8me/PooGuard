/**
 * Add missing columns to request_logs and update action constraint.
 * The original create table migration was modified after initial run.
 */
exports.up = function (knex) {
  return knex.schema.alterTable('request_logs', (table) => {
    table.string('client_ip', 45).nullable();
    table.boolean('is_authenticated').notNullable().defaultTo(false);
  }).then(() => {
    // Drop the old check constraint and add an updated one that includes 'batch'
    return knex.raw(`
      ALTER TABLE request_logs DROP CONSTRAINT IF EXISTS request_logs_action_check;
      ALTER TABLE request_logs ADD CONSTRAINT request_logs_action_check
        CHECK (action = ANY (ARRAY['blocked','allowed','flagged','batch']));
    `);
  });
};

exports.down = function (knex) {
  return knex.schema.alterTable('request_logs', (table) => {
    table.dropColumn('client_ip');
    table.dropColumn('is_authenticated');
  }).then(() => {
    return knex.raw(`
      ALTER TABLE request_logs DROP CONSTRAINT IF EXISTS request_logs_action_check;
      ALTER TABLE request_logs ADD CONSTRAINT request_logs_action_check
        CHECK (action = ANY (ARRAY['blocked','allowed','flagged']));
    `);
  });
};
