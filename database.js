/**
 * MR HAAS NET - database.js - FIXED - No more UNIQUE error
 * FIX: Tumia INSERT OR IGNORE badala ya INSERT
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = process.env.DATABASE_URL || path.join(__dirname, 'mrhaas.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('DB Error:', err.message);
    else console.log('✅ SQLite connected:', DB_PATH);
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        business_name TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        subdomain TEXT,
        plan TEXT DEFAULT 'free',
        status TEXT DEFAULT 'active',
        max_devices INTEGER DEFAULT 2,
        max_clients INTEGER DEFAULT 50,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS devices (
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
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        phone TEXT,
        username TEXT NOT NULL,
        package_name TEXT DEFAULT 'Standard 10Mbps',
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS payments (
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
    )`);

    // Auto migration - ignore errors
    const migrations = [
        "ALTER TABLE devices ADD COLUMN mac_address TEXT",
        "ALTER TABLE devices ADD COLUMN vendor TEXT DEFAULT 'mikrotik'",
        "ALTER TABLE devices ADD COLUMN model TEXT",
        "ALTER TABLE devices ADD COLUMN wan_port TEXT DEFAULT 'ether1'",
        "ALTER TABLE devices ADD COLUMN status TEXT DEFAULT 'Offline'",
        "ALTER TABLE devices ADD COLUMN last_seen DATETIME",
        "ALTER TABLE tenants ADD COLUMN subdomain TEXT",
        "ALTER TABLE tenants ADD COLUMN plan TEXT DEFAULT 'free'",
        "ALTER TABLE tenants ADD COLUMN status TEXT DEFAULT 'active'",
        "ALTER TABLE tenants ADD COLUMN max_devices INTEGER DEFAULT 2",
        "ALTER TABLE tenants ADD COLUMN max_clients INTEGER DEFAULT 50",
    ];
    migrations.forEach(sql => db.run(sql, ()=>{}));

    // SUPER ADMIN - FIXED: INSERT OR IGNORE ili isigonge
    const hash = bcrypt.hashSync('Admin@2024', 10);
    db.run(`INSERT OR IGNORE INTO tenants (id, business_name, owner_name, phone, email, password_hash, subdomain, plan, max_devices, max_clients, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        ['tenant_super_admin', 'MR HAAS Super Admin', 'Super Admin', '255000000000', 'admin@mrhaas.net', hash, 'admin', 'premium', 1000, 10000, 'active'],
        function(err) {
            if (err) {
                console.error('Super Admin insert error:', err.message);
            } else if (this.changes === 0) {
                console.log('✅ Super Admin already exists');
            } else {
                console.log('✅ Super Admin created: admin@mrhaas.net / Admin@2024');
            }
        });

    db.run(`CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_clients_tenant ON clients(tenant_id)`);
});

module.exports = db;
