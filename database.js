
'use strict';

const { Pool } = require('pg');

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (IS_PRODUCTION && !process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL inahitajika kwenye production.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PRODUCTION ? { rejectUnauthorized: false } : false,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', error => {
  console.error('PostgreSQL pool error:', error);
});

async function initializeDatabase() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        business_name VARCHAR(200) NOT NULL,
        owner_name VARCHAR(200) NOT NULL,
        phone VARCHAR(40) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        subdomain VARCHAR(150) NOT NULL UNIQUE,
        plan VARCHAR(40) NOT NULL DEFAULT 'START',
        max_devices INTEGER DEFAULT 2,
        max_clients INTEGER DEFAULT 50,
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        role VARCHAR(30) NOT NULL DEFAULT 'tenant',
        trial_started_at TIMESTAMPTZ,
        trial_ends_at TIMESTAMPTZ,
        subscription_status VARCHAR(30) NOT NULL DEFAULT 'trial',
        subscription_ends_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT tenants_status_check
          CHECK (status IN ('active', 'suspended', 'inactive')),
        CONSTRAINT tenants_subscription_status_check
          CHECK (subscription_status IN (
            'trial', 'active', 'expired', 'pending', 'cancelled'
          ))
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_tenants_email_lower
      ON tenants (LOWER(email));
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_tenants_status
      ON tenants (status);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_settings (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
        portal_title VARCHAR(120),
        primary_color VARCHAR(7) NOT NULL DEFAULT '#111827',
        announcement TEXT NOT NULL DEFAULT '',
        contact_phone VARCHAR(40),
        logo_url TEXT NOT NULL DEFAULT '',
        currency VARCHAR(10) NOT NULL DEFAULT 'TZS',
        language VARCHAR(10) NOT NULL DEFAULT 'sw',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payment_settings (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
        enabled_providers TEXT[] NOT NULL DEFAULT ARRAY['manual']::TEXT[],
        manual_payment_instructions TEXT NOT NULL DEFAULT '',
        payment_phone VARCHAR(40) NOT NULL DEFAULT '',
        payment_account_name VARCHAR(120) NOT NULL DEFAULT '',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS sites (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        name VARCHAR(150) NOT NULL,
        location VARCHAR(250) NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_sites_tenant
      ON sites (tenant_id);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        site_id TEXT REFERENCES sites(id) ON DELETE SET NULL,
        name VARCHAR(150) NOT NULL,
        vendor VARCHAR(80) NOT NULL,
        device_type VARCHAR(40) NOT NULL DEFAULT 'router',
        model VARCHAR(120) NOT NULL DEFAULT '',
        mac_address VARCHAR(30),
        ip_address VARCHAR(100),
        wan_port VARCHAR(50),
        connection_type VARCHAR(30) NOT NULL DEFAULT 'api',
        last_seen TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_devices_tenant
      ON devices (tenant_id);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_devices_last_seen
      ON devices (last_seen);
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_tenant_mac
      ON devices (tenant_id, mac_address)
      WHERE mac_address IS NOT NULL;
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS packages (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        name VARCHAR(150) NOT NULL,
        price NUMERIC(14,2) NOT NULL DEFAULT 0,
        duration_value INTEGER NOT NULL DEFAULT 1,
        duration_unit VARCHAR(20) NOT NULL DEFAULT 'days',
        speed_down NUMERIC(12,2) NOT NULL DEFAULT 0,
        speed_up NUMERIC(12,2) NOT NULL DEFAULT 0,
        connection_type VARCHAR(20) NOT NULL DEFAULT 'hotspot',
        description TEXT NOT NULL DEFAULT '',
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT packages_price_check CHECK (price >= 0),
        CONSTRAINT packages_duration_check CHECK (duration_value >= 1),
        CONSTRAINT packages_connection_type_check
          CHECK (connection_type IN ('hotspot', 'pppoe')),
        CONSTRAINT packages_status_check
          CHECK (status IN ('active', 'inactive'))
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_packages_tenant
      ON packages (tenant_id);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        site_id TEXT REFERENCES sites(id) ON DELETE SET NULL,
        name VARCHAR(200) NOT NULL,
        phone VARCHAR(40),
        username VARCHAR(150),
        package_name VARCHAR(150),
        connection_type VARCHAR(20) NOT NULL DEFAULT 'hotspot',
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT clients_connection_type_check
          CHECK (connection_type IN ('hotspot', 'pppoe')),
        CONSTRAINT clients_status_check
          CHECK (status IN ('active', 'suspended', 'inactive'))
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_clients_tenant
      ON clients (tenant_id);
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_tenant_username
      ON clients (tenant_id, username)
      WHERE username IS NOT NULL AND username <> '';
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS vouchers (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        package_id TEXT REFERENCES packages(id) ON DELETE SET NULL,
        code VARCHAR(40) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'unused',
        expires_at TIMESTAMPTZ,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT vouchers_status_check
          CHECK (status IN ('unused', 'used', 'blocked'))
      );
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_vouchers_tenant_code
      ON vouchers (tenant_id, code);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_vouchers_tenant_status
      ON vouchers (tenant_id, status);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        client_id TEXT,
        provider VARCHAR(40) NOT NULL DEFAULT 'manual',
        reference VARCHAR(180),
        amount NUMERIC(14,2) NOT NULL,
        currency VARCHAR(10) NOT NULL DEFAULT 'TZS',
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        description TEXT NOT NULL DEFAULT '',
        provider_transaction_id VARCHAR(200),
        verified_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT payments_amount_check CHECK (amount > 0),
        CONSTRAINT payments_status_check
          CHECK (status IN (
            'pending', 'paid', 'rejected', 'failed', 'refunded'
          ))
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payments_tenant
      ON payments (tenant_id);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payments_tenant_status
      ON payments (tenant_id, status);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL,
        actor_email VARCHAR(255),
        action VARCHAR(120) NOT NULL,
        entity_type VARCHAR(80),
        entity_id TEXT,
        details JSONB NOT NULL DEFAULT '{}'::JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant
      ON audit_logs (tenant_id, created_at DESC);
    `);

    // Migrations for databases created by earlier versions.
    await client.query(`
      ALTER TABLE tenants
        ADD COLUMN IF NOT EXISTS role VARCHAR(30) NOT NULL DEFAULT 'tenant',
        ADD COLUMN IF NOT EXISTS trial_started_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(30) NOT NULL DEFAULT 'trial',
        ADD COLUMN IF NOT EXISTS subscription_ends_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    `);

    await client.query(`
      ALTER TABLE devices
        ADD COLUMN IF NOT EXISTS site_id TEXT,
        ADD COLUMN IF NOT EXISTS device_type VARCHAR(40) NOT NULL DEFAULT 'router',
        ADD COLUMN IF NOT EXISTS model VARCHAR(120) NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS ip_address VARCHAR(100),
        ADD COLUMN IF NOT EXISTS wan_port VARCHAR(50),
        ADD COLUMN IF NOT EXISTS connection_type VARCHAR(30) NOT NULL DEFAULT 'api',
        ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
    `);

    await client.query(`
      ALTER TABLE clients
        ADD COLUMN IF NOT EXISTS site_id TEXT,
        ADD COLUMN IF NOT EXISTS phone VARCHAR(40),
        ADD COLUMN IF NOT EXISTS package_name VARCHAR(150),
        ADD COLUMN IF NOT EXISTS connection_type VARCHAR(20) NOT NULL DEFAULT 'hotspot',
        ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';
    `);

    // Ensure payment columns exist BEFORE creating their index.
    await client.query(`
      ALTER TABLE payments
        ADD COLUMN IF NOT EXISTS client_id TEXT,
        ADD COLUMN IF NOT EXISTS provider_transaction_id VARCHAR(200),
        ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
    `);

    // Add the client foreign key safely for older databases.
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'payments_client_id_fkey'
            AND conrelid = 'payments'::regclass
        ) THEN
          ALTER TABLE payments
            ADD CONSTRAINT payments_client_id_fkey
            FOREIGN KEY (client_id) REFERENCES clients(id)
            ON DELETE SET NULL;
        END IF;
      END $$;
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_provider_transaction
      ON payments (provider, provider_transaction_id)
      WHERE provider_transaction_id IS NOT NULL;
    `);

    await client.query(`
      ALTER TABLE tenant_settings
        ADD COLUMN IF NOT EXISTS logo_url TEXT NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS language VARCHAR(10) NOT NULL DEFAULT 'sw';
    `);

    await client.query('COMMIT');

    console.log('MR HAAS WISP database schema iko tayari.');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Database initialization failed:', error);
    throw error;
  } finally {
    client.release();
  }
}

const ready = initializeDatabase();

module.exports = {
  pool,
  ready,
  initializeDatabase
};
