/**
 * Migration: Create audit_logs table for admin action logging
 *
 * This table stores an immutable log of all admin actions.
 * By design, there is no API to update or delete entries.
 */

exports.up = function (knex) {
  return knex.schema.createTable('audit_logs', (table) => {
    table.increments('id').primary();

    // Who performed the action
    table.uuid('user_id').nullable().references('id').inTable('users').onDelete('SET NULL');
    table.string('user_email', 255); // Stored separately in case user is deleted

    // What action was taken
    table.string('action', 100).notNullable().index(); // e.g., 'config.update', 'user.delete'
    table.string('resource', 100).notNullable().index(); // e.g., 'firewall_config', 'user', 'alert'
    table.string('resource_id', 100).index(); // ID of the specific resource affected

    // Before/after values for tracking changes
    table.text('old_value'); // JSON string of previous state
    table.text('new_value'); // JSON string of new state

    // Request context
    table.string('ip_address', 45); // IPv4 or IPv6
    table.string('user_agent', 500);

    // Additional metadata
    table.text('metadata'); // JSON string for extra context

    // Timestamp (immutable - no updated_at since entries cannot be modified)
    table.timestamp('created_at').defaultTo(knex.fn.now()).index();
  });
};

exports.down = function (knex) {
  return knex.schema.dropTable('audit_logs');
};
