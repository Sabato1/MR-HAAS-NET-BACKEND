/**
 * MR HAAS NET - database.js - Multi-Tenant + MAC pekee + Online/Offline
 * Weka hii kama database.js kwenye backend yako (Render)
 * Inafanya kazi na server-clean-final.js
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
    // 1. TENANTS TABLE - MPYA KWA MULTI-TENANT
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
    )`, (err) => {
        if (!err) console.log('✅ tenants table ready');
    });

    // 2. DEVICES TABLE - IMEBORESHWA: MAC PEKEE, VENDOR, STATUS, LAST_SEEN
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(tenant_id) REFERENCES tenants(id)
    )`, (err) => {
        if (!err) console.log('✅ devices table ready');
    });

    // 3. CLIENTS TABLE
    db.run(`CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        phone TEXT,
        username TEXT NOT NULL,
        package_name TEXT DEFAULT 'Standard 10Mbps',
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(tenant_id) REFERENCES tenants(id)
    )`, (err) => {
        if (!err) console.log('✅ clients table ready');
    });

    // 4. PAYMENTS TABLE - KWA WEBHOOKS 6
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(tenant_id) REFERENCES tenants(id)
    )`, (err) => {
        if (!err) console.log('✅ payments table ready');
    });

    // 5. AUTO MIGRATION - Ongeza columns kama table ya zamani
    const migrations = [
        { table: 'devices', col: 'mac_address', def: 'TEXT' },
        { table: 'devices', col: 'vendor', def: "TEXT DEFAULT 'mikrotik'" },
        { table: 'devices', col: 'model', def: 'TEXT' },
        { table: 'devices', col: 'wan_port', def: "TEXT DEFAULT 'ether1'" },
        { table: 'devices', col: 'status', def: "TEXT DEFAULT 'Offline'" },
        { table: 'devices', col: 'last_seen', def: 'DATETIME' },
        { table: 'tenants', col: 'subdomain', def: 'TEXT' },
        { table: 'tenants', col: 'plan', def: "TEXT DEFAULT 'free'" },
        { table: 'tenants', col: 'status', def: "TEXT DEFAULT 'active'" },
        { table: 'tenants', col: 'max_devices', def: 'INTEGER DEFAULT 2' },
        { table: 'tenants', col: 'max_clients', def: 'INTEGER DEFAULT 50' },
    ];

    migrations.forEach(m => {
        db.run(`ALTER TABLE ${m.table} ADD COLUMN ${m.col} ${m.def}`, (err) => {
            // Ignore if column exists
        });
    });

    // 6. SUPER ADMIN DEFAULT
    db.get("SELECT * FROM tenants WHERE email = ?", ['admin@mrhaas.net'], (err, row) => {
        if (!row) {
            const hash = bcrypt.hashSync('Admin@2024', 10);
            db.run(`INSERT INTO tenants (id, business_name, owner_name, phone, email, password_hash, subdomain, plan, max_devices, max_clients, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
                ['tenant_super_admin', 'MR HAAS Super Admin', 'Super Admin', '255000000000', 'admin@mrhaas.net', hash, 'admin', 'premium', 1000, 10000, 'active'],
                (err) => {
                    if (!err) console.log('✅ Super Admin created: admin@mrhaas.net / Admin@2024');
                });
        } else {
            console.log('✅ Super Admin exists:', row.email);
        }
    });

    // 7. INDEXES for performance
    db.run(`CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_clients_tenant ON clients(tenant_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payments(tenant_id)`);
});

module.exports = db;
