const bcrypt = require('bcrypt');

exports.seed = async function(knex) {
  // Create default admin user
  const adminExists = await knex('users').where({ email: 'admin@pooguard.local' }).first();

  if (!adminExists) {
    const defaultPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const passwordHash = await bcrypt.hash(defaultPassword, 12);
    await knex('users').insert({
      email: process.env.ADMIN_EMAIL || 'admin@pooguard.local',
      password_hash: passwordHash,
      role: 'admin'
    });
    console.log(`Created default admin user: ${process.env.ADMIN_EMAIL || 'admin@pooguard.local'}`);
    if (!process.env.ADMIN_PASSWORD) {
      console.warn('WARNING: Using default admin password. Set ADMIN_PASSWORD env var for production!');
    }
  }

  // Create default firewall config
  const configExists = await knex('firewall_config').first();

  if (!configExists) {
    await knex('firewall_config').insert({
      threshold_prompt_injection: 0.7,
      threshold_jailbreak: 0.7,
      threshold_pii: 0.7,
      action_prompt_injection: 'block',
      action_jailbreak: 'block',
      action_pii: 'flag'
    });
    console.log('Created default firewall config');
  }

  // Create default alerts
  const alertsExist = await knex('alerts').first();

  if (!alertsExist) {
    await knex('alerts').insert([
      {
        name: 'High Block Rate',
        type: 'rate',
        config: JSON.stringify({ maxCount: 10, windowMinutes: 5 }),
        enabled: true
      },
      {
        name: 'Critical Threat Detected',
        type: 'threshold',
        config: JSON.stringify({ threatType: 'prompt_injection', threshold: 0.9 }),
        enabled: true
      }
    ]);
    console.log('Created default alert rules');
  }
};
