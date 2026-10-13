
/**
 * MR HAAS NET - database.js
 * Subscription plans, 4-day Trial and Revenue Share
 * Existing tables and records are preserved.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH =
  process.env.DATABASE_URL || path.join(__dirname, 'mrhaas.db');

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('MR HAAS NET SQLite connected.');
  }
});

db.serialize(() => {
  db.run('PRAGMA busy_timeout = 5000');

  // 1. TENANTS / WISP BUSINESSES
  db.run(`
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      business_name TEXT NOT NULL,
      owner_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      subdomain TEXT,
      plan TEXT NOT NULL DEFAULT 'start',
      status TEXT DEFAULT 'active',
      max_devices INTEGER DEFAULT 2,
      max_clients INTEGER DEFAULT 50,
      trial_started_at DATETIME,
      trial_ends_at DATETIME,
      subscription_status TEXT DEFAULT 'active',
      subscription_started_at DATETIME,
      subscription_ends_at DATETIME,
      revenue_share_rate REAL DEFAULT 3.0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 2. ROUTERS AND ACCESS POINTS
  db.run(`
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      host TEXT,
      mac_address TEXT,
      vendor TEXT DEFAULT 'mikrotik',
      type TEXT DEFAULT 'mikrotik',
      model TEXT,
      wan_port TEXT DEFAULT 'ether1',
      user TEXT DEFAULT 'admin',
      password TEXT DEFAULT '',
      port INTEGER DEFAULT 8728,
      status TEXT DEFAULT 'Offline',
      last_seen DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 3. WISP CUSTOMERS
  db.run(`
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      phone TEXT,
      username TEXT NOT NULL,
      package_name TEXT DEFAULT 'Standard 10Mbps',
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 4. EXISTING CUSTOMER PAYMENTS
  db.run(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      client_id INTEGER,
      client_username TEXT,
      amount REAL NOT NULL,
      phone TEXT,
      gateway TEXT,
      transaction_id TEXT,
      status TEXT DEFAULT 'completed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 5. PAYMENTS FOR WISP SUBSCRIPTIONS
  db.run(`
    CREATE TABLE IF NOT EXISTS subscription_payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      plan TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'TZS',
      payment_type TEXT NOT NULL,
      period_start DATETIME,
      period_end DATETIME,
      gateway TEXT,
      transaction_id TEXT UNIQUE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // payment_type examples:
  // signup_fee, monthly_subscription, revenue_share_fee

  // 6. MONTHLY REVENUE DECLARATIONS
  // Revenue Share fee must be calculated by the backend.
  db.run(`
    CREATE TABLE IF NOT EXISTS revenue_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      period TEXT NOT NULL,
      gross_revenue REAL NOT NULL,
      fee_rate REAL NOT NULL DEFAULT 3.0,
      fee_due REAL NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'submitted',
      notes TEXT,
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      reviewed_at DATETIME,
      UNIQUE (tenant_id, period)
    )
  `);

  // 7. MIGRATIONS FOR EXISTING DATABASES
  // SQLite reports duplicate-column errors when a column already exists.
  // These errors are intentionally ignored; other errors are logged.
  const migrations = [
    "ALTER TABLE tenants ADD COLUMN trial_started_at DATETIME",
    "ALTER TABLE tenants ADD COLUMN trial_ends_at DATETIME",
    "ALTER TABLE tenants ADD COLUMN subscription_status TEXT DEFAULT 'active'",
    "ALTER TABLE tenants ADD COLUMN subscription_started_at DATETIME",
    "ALTER TABLE tenants ADD COLUMN subscription_ends_at DATETIME",
    "ALTER TABLE tenants ADD COLUMN revenue_share_rate REAL DEFAULT 3.0",

    "ALTER TABLE devices ADD COLUMN mac_address TEXT",
    "ALTER TABLE devices ADD COLUMN vendor TEXT DEFAULT 'mikrotik'",
    "ALTER TABLE devices ADD COLUMN model TEXT",
    "ALTER TABLE devices ADD COLUMN wan_port TEXT DEFAULT 'ether1'",
    "ALTER TABLE devices ADD COLUMN status TEXT DEFAULT 'Offline'",
    "ALTER TABLE devices ADD COLUMN last_seen DATETIME",
    "ALTER TABLE tenants ADD COLUMN subdomain TEXT",
    "ALTER TABLE tenants ADD COLUMN plan TEXT DEFAULT 'start'",
    "ALTER TABLE tenants ADD COLUMN status TEXT DEFAULT 'active'",
    "ALTER TABLE tenants ADD COLUMN max_devices INTEGER DEFAULT 2",
    "ALTER TABLE tenants ADD COLUMN max_clients INTEGER DEFAULT 50"
  ];

  migrations.forEach((sql) => {
    db.run(sql, (err) => {
      if (err && !/duplicate column name/i.test(err.message)) {
        console.error('Migration error:', err.message);
      }
    });
  });

  // 8. REMOVE OLD PLAN NAMES FROM EXISTING WISP ACCOUNTS.
  // Super Admin is excluded from customer-plan migration.
  db.run(`
    UPDATE tenants
    SET plan = 'start',
        max_devices = 2,
        max_clients = 50
    WHERE plan = 'free'
      AND id <> 'tenant_super_admin'
  `);

  db.run(`
    UPDATE tenants
    SET plan = 'diamond',
        max_devices = 7,
        max_clients = 500
    WHERE plan IN ('basic', 'standard')
      AND id <> 'tenant_super_admin'
  `);

  db.run(`
    UPDATE tenants
    SET max_devices = 2, max_clients = 50
    WHERE plan = 'start'
      AND id <> 'tenant_super_admin'
  `);

  db.run(`
    UPDATE tenants
    SET max_devices = 7, max_clients = 500
    WHERE plan = 'diamond'
      AND id <> 'tenant_super_admin'
  `);

  db.run(`
    UPDATE tenants
    SET max_devices = -1, max_clients = 5000
    WHERE plan = 'premium'
      AND id <> 'tenant_super_admin'
  `);

  // -1 means unlimited devices.
  // Server-side limit checks must explicitly support this value.

  // 9. INDEXES
  db.run(`
    CREATE INDEX IF NOT EXISTS idx_devices_tenant
    ON devices(tenant_id)
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_devices_mac
    ON devices(mac_address)
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_clients_tenant
    ON clients(tenant_id)
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_tenants_trial_end
    ON tenants(trial_ends_at)
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_subscription_payments_tenant
    ON subscription_payments(tenant_id)
  `);

  db.run(`
    CREATE INDEX IF NOT EXISTS idx_revenue_reports_tenant_period
    ON revenue_reports(tenant_id, period)
  `);

  // 10. SUPER ADMIN BOOTSTRAP
  // Configure SUPER_ADMIN_PASSWORD in your hosting environment.
  // Existing Super Admin password is updated only when this variable is set.
  const adminPassword = process.env.SUPER_ADMIN_PASSWORD;
  const adminEmail = process.env.SUPER_ADMIN_EMAIL || 'admin@mrhaas.net';

  if (adminPassword) {
    if (adminPassword.length < 12) {
      console.error(
        'SUPER_ADMIN_PASSWORD must be at least 12 characters.'
      );
    } else {
      const hash = bcrypt.hashSync(adminPassword, 12);

      db.run(
        `INSERT OR IGNORE INTO tenants
          (id, business_name, owner_name, phone, email, password_hash,
           subdomain, plan, max_devices, max_clients, status,
           subscription_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        ],
        (err) => {
          if (err) {
            console.error('Super Admin setup error:', err.message);
            return;
          }

          // Apply the configured password to the dedicated admin record.
          db.run(
            `UPDATE tenants
             SET password_hash = ?
             WHERE id = 'tenant_super_admin'`,
            [hash],
            (updateErr) => {
              if (updateErr) {
                console.error(
                  'Super Admin password update error:',
                  updateErr.message
                );
              } else {
                console.log('Super Admin credentials configured.');
              }
            }
          );
        }
      );
    }
  } else {
    console.log(
      'SUPER_ADMIN_PASSWORD is not set; existing Super Admin was not changed.'
    );
  }
});

module.exports = db;
