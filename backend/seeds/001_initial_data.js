const bcrypt = require('bcrypt');

exports.seed = async function(knex) {
  if (process.env.NODE_ENV === 'production' && !process.env.ADMIN_PASSWORD) {
    throw new Error('ADMIN_PASSWORD is required in production. Set it in your .env file.');
  }

  // Create default admin user
  const adminExists = await knex('users').where({ email: 'admin@pooguard.local' }).first();

  if (!adminExists) {
    const generatedPassword = require('crypto').randomBytes(16).toString('hex');
    const defaultPassword = process.env.ADMIN_PASSWORD || generatedPassword;
    const passwordHash = await bcrypt.hash(defaultPassword, 12);
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@pooguard.local';
    await knex('users').insert({
      email: adminEmail,
      password_hash: passwordHash,
      role: 'admin'
    });
    if (!process.env.ADMIN_PASSWORD) {
      console.log(`Created default admin user: ${adminEmail}`);
      console.log(`Generated admin password: ${generatedPassword}`);
      console.warn('WARNING: Save this password. Set ADMIN_PASSWORD env var to use a fixed password.');
    } else {
      console.log(`Created default admin user: ${adminEmail}`);
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
