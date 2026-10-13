
'use strict';

const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    'DATABASE_URL haijawekwa kwenye Render Environment.'
  );
}

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 30000
});

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err.message);
});

function convertSql(sql) {
  let query = sql.trim();

  query = query.replace(
    /^\s*INSERT\s+OR\s+IGNORE\s+INTO/i,
    'INSERT INTO'
  );

  query = query.replace(
    /datetime\s*\(\s*'now'\s*\)/gi,
    'CURRENT_TIMESTAMP'
  );

  let index = 0;
  query = query.replace(/\?/g, () => `$${++index}`);

  if (/^INSERT\s+INTO/i.test(query) &&
      !/\bRETURNING\b/i.test(query)) {
    query += ' RETURNING id';
  }

  if (/^INSERT\s+INTO/i.test(query) &&
      !/RETURNING/i.test(query) &&
      /INSERT INTO/i.test(query)) {
    // INSERT OR IGNORE hutumia ON CONFLICT.
    // Ongeza ON CONFLICT kabla ya RETURNING.
    query = query.replace(
      /\s+RETURNING\s+id$/i,
      ' ON CONFLICT DO NOTHING RETURNING id'
    );
  } else if (/^INSERT\s+INTO/i.test(query) &&
             /ON CONFLICT DO NOTHING RETURNING id$/i.test(query)) {
    // Tayari imeandaliwa.
  }

  return query;
}

function run(sql, params = [], callback = () => {}) {
  const query = convertSql(sql);

  pool.query(query, params)
    .then((result) => {
      const context = {
        lastID: result.rows?.[0]?.id ?? undefined,
        changes: result.rowCount ?? 0
      };

      callback.call(context, null);
    })
    .catch((err) => {
      callback.call(
        { lastID: undefined, changes: 0 },
        err
      );
    });
}

function get(sql, params = [], callback = () => {}) {
  pool.query(convertSql(sql), params)
    .then((result) => callback(null, result.rows[0]))
    .catch((err) => callback(err));
}

function all(sql, params = [], callback = () => {}) {
  pool.query(convertSql(sql), params)
    .then((result) => callback(null, result.rows))
    .catch((err) => callback(err));
}

const db = { run, get, all };

const schema = [
  `CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    business_name TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    subdomain TEXT UNIQUE,
    plan TEXT NOT NULL DEFAULT 'start',
    status TEXT NOT NULL DEFAULT 'active',
    max_devices INTEGER NOT NULL DEFAULT 2,
    max_clients INTEGER NOT NULL DEFAULT 50,
    trial_started_at TIMESTAMPTZ,
    trial_ends_at TIMESTAMPTZ,
    subscription_status TEXT DEFAULT 'trial',
    subscription_started_at TIMESTAMPTZ,
    subscription_ends_at TIMESTAMPTZ,
    revenue_share_rate NUMERIC(8,2) DEFAULT 3.0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS devices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    host TEXT,
    mac_address TEXT,
    vendor TEXT DEFAULT 'mikrotik',
    type TEXT DEFAULT 'mikrotik',
    model TEXT,
    wan_port TEXT DEFAULT 'ether1',
    "user" TEXT DEFAULT 'admin',
    password TEXT DEFAULT '',
    port INTEGER DEFAULT 8728,
    status TEXT DEFAULT 'Offline',
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS clients (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    phone TEXT,
    username TEXT NOT NULL,
    package_name TEXT DEFAULT 'Standard 10Mbps',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS payments (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    client_id BIGINT,
    client_username TEXT,
    amount NUMERIC(14,2) NOT NULL,
    phone TEXT,
    gateway TEXT,
    transaction_id TEXT,
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS subscription_payments (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    plan TEXT NOT NULL,
    amount NUMERIC(14,2) NOT NULL,
    currency TEXT NOT NULL DEFAULT 'TZS',
    payment_type TEXT NOT NULL,
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    gateway TEXT,
    transaction_id TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  `CREATE TABLE IF NOT EXISTS revenue_reports (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    period TEXT NOT NULL,
    gross_revenue NUMERIC(14,2) NOT NULL,
    fee_rate NUMERIC(8,2) NOT NULL DEFAULT 3.0,
    fee_due NUMERIC(14,2) NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'submitted',
    notes TEXT,
    submitted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMPTZ,
    UNIQUE (tenant_id, period)
  )`,

  `CREATE INDEX IF NOT EXISTS idx_devices_tenant
    ON devices(tenant_id)`,

  `CREATE INDEX IF NOT EXISTS idx_devices_mac
    ON devices(mac_address)`,

  `CREATE INDEX IF NOT EXISTS idx_clients_tenant
    ON clients(tenant_id)`,

  `CREATE INDEX IF NOT EXISTS idx_tenants_trial_end
    ON tenants(trial_ends_at)`,

  `CREATE INDEX IF NOT EXISTS idx_subscription_payments_tenant
    ON subscription_payments(tenant_id)`,

  `CREATE INDEX IF NOT EXISTS idx_revenue_reports_tenant_period
    ON revenue_reports(tenant_id, period)`
];

const ready = (async () => {
  for (const statement of schema) {
    await pool.query(statement);
  }

  await pool.query(`
    UPDATE tenants
    SET plan = 'start', max_devices = 2, max_clients = 50
    WHERE plan = 'free' AND id <> 'tenant_super_admin'
  `);

  await pool.query(`
    UPDATE tenants
    SET plan = 'diamond', max_devices = 7, max_clients = 500
    WHERE plan IN ('basic', 'standard')
      AND id <> 'tenant_super_admin'
  `);

  await pool.query(`
    UPDATE tenants
    SET max_devices = 2, max_clients = 50
    WHERE plan = 'start' AND id <> 'tenant_super_admin'
  `);

  await pool.query(`
    UPDATE tenants
    SET max_devices = 7, max_clients = 500
    WHERE plan = 'diamond' AND id <> 'tenant_super_admin'
  `);

  await pool.query(`
    UPDATE tenants
    SET max_devices = -1, max_clients = 5000
    WHERE plan = 'premium' AND id <> 'tenant_super_admin'
  `);

  const adminPassword = process.env.SUPER_ADMIN_PASSWORD;
  const adminEmail =
    process.env.SUPER_ADMIN_EMAIL || 'admin@mrhaas.net';

  if (adminPassword) {
    if (adminPassword.length < 12) {
      throw new Error(
        'SUPER_ADMIN_PASSWORD lazima iwe na angalau herufi 12.'
      );
    }

    const hash = await bcrypt.hash(adminPassword, 12);

    await pool.query(
      `INSERT INTO tenants (
        id, business_name, owner_name, phone, email,
        password_hash, subdomain, plan, max_devices,
        max_clients, status, subscription_status
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
      )
      ON CONFLICT (id) DO UPDATE SET
        password_hash = EXCLUDED.password_hash,
        email = EXCLUDED.email`,
      [
        'tenant_super_admin',
        'MR HAAS Super Admin',
        'Super Admin',
        '255000000000',
        adminEmail,
        hash,
        'admin',
        'premium',
        -1,
        -1,
        'active',
        'active'
      ]
    );

    console.log('Super Admin credentials configured.');
  }

  console.log('MR HAAS NET PostgreSQL connected; schema ready.');
})();

db.ready = ready;
db.pool = pool;
db.serialize = (callback) => {
  ready.then(callback).catch((err) => {
    console.error('Database initialization failed:', err.message);
  });
};

module.exports = db;
