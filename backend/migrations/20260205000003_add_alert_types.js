/**
 * Migration to add enhanced alert types
 *
 * Note: These types are now included in the initial alerts table migration.
 * This migration handles upgrading existing databases that were created
 * before the new types were added.
 */

exports.up = async function (knex) {
  // Check if the constraint already includes the new values (fresh install)
  const result = await knex.raw(`
    SELECT conname, pg_get_constraintdef(oid) as def
    FROM pg_constraint
    WHERE conrelid = 'alerts'::regclass AND contype = 'c' AND conname LIKE '%type%'
  `);

  if (result.rows.length === 0) return;

  const constraint = result.rows[0];
  if (constraint.def.includes('session_threat')) return; // Already has new types

  // Drop old constraint and add new one with all types
  await knex.raw(`ALTER TABLE alerts DROP CONSTRAINT "${constraint.conname}"`);
  await knex.raw(`
    ALTER TABLE alerts ADD CONSTRAINT "${constraint.conname}"
    CHECK (type = ANY(ARRAY['rate'::text, 'threshold'::text, 'pattern'::text,
      'session_threat'::text, 'access_pattern'::text, 'config_change'::text, 'repeat_block'::text]))
  `);
};

exports.down = async function (knex) {
  // No-op: removing enum values would break existing data
};
