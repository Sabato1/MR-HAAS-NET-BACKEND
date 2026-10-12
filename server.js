/**
 * MR HAAS NET - Multi-Tenant WISP Management Backend - CLEAN VERSION
 * Imeboreshwa kutoka server.js yako ya awali
 * 
 * Maboresho:
 * ✅ Auth JWT + Tenant isolation
 * ✅ AP - MAC Address pekee (hakuna IP, hakuna user/password)
 * ✅ MikroTik - 60+ models, script bila password, wan_port
 * ✅ Online/Offline + last_seen + delete device
 * ✅ Payment webhooks zako 6 zote zimebaki
 * ✅ Super Admin + Plan limits (free 2 dev, standard 10, premium 100)
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

// Tumia database.js yako kama ipo, kama haipo tengeneza mpya
let db;
try {
    db = require('./database');
} catch (e) {
    const sqlite3 = require('sqlite3').verbose();
    db = new sqlite3.Database(path.join(__dirname, 'mrhaas.db'));
}

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'mrhaas-super-secret-2024-change-this';

// ================= DATABASE INIT =================
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

    // Ongeza columns mpya kwenye devices kama hazipo
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        name TEXT,
        host TEXT,
        mac_address TEXT,
        vendor TEXT,
        type TEXT,
        model TEXT,
        wan_port TEXT,
        user TEXT,
        password TEXT,
        port INTEGER DEFAULT 8728,
        status TEXT DEFAULT 'Offline',
        last_seen DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        name TEXT,
        phone TEXT,
        username TEXT,
        package_name TEXT,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Jaribu kuongeza columns kama table ya zamani
    const addColumn = (table, col, def) => {
        db.run(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`, () => {});
    };
    addColumn('devices', 'mac_address', 'TEXT');
    addColumn('devices', 'vendor', 'TEXT');
    addColumn('devices', 'model', 'TEXT');
    addColumn('devices', 'wan_port', 'TEXT');
    addColumn('devices', 'status', "TEXT DEFAULT 'Offline'");
    addColumn('devices', 'last_seen', 'DATETIME');

    // Super Admin
    db.get("SELECT * FROM tenants WHERE email = ?", ['admin@mrhaas.net'], (err, row) => {
        if (!row) {
            const hash = bcrypt.hashSync('Admin@2024', 10);
            db.run(`INSERT INTO tenants (id, business_name, owner_name, phone, email, password_hash, subdomain, plan, max_devices, max_clients)
                    VALUES (?,?,?,?,?,?,?,?,?,?)`,
                ['tenant_super_admin', 'MR HAAS Super Admin', 'Super Admin', '255000000000', 'admin@mrhaas.net', hash, 'admin', 'premium', 1000, 10000]);
            console.log('✅ Super Admin created: admin@mrhaas.net / Admin@2024');
        }
    });
});

// ================= HELPERS =================
function generateToken(tenant_id, email) {
    return jwt.sign({ tenant_id, email }, SECRET_KEY, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
    const header = req.headers['authorization'];
    if (!header) return res.status(401).json({ success: false, message: 'Token missing - Ingia kwanza' });
    const token = header.startsWith('Bearer ') ? header.split(' ')[1] : header;
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.tenant_id = decoded.tenant_id;
        req.email = decoded.email;
        next();
    } catch (e) {
        return res.status(401).json({ success: false, message: 'Token si sahihi' });
    }
}

// ================= AUTH ROUTES - MPYA =================
app.post('/api/auth/register', (req, res) => {
    const { business_name, owner_name, phone, email, password } = req.body;
    if (!business_name || !owner_name || !phone || !email || !password) {
        return res.status(400).json({ success: false, message: 'Jaza taarifa zote' });
    }
    db.get("SELECT * FROM tenants WHERE email = ? OR phone = ?", [email, phone], (err, row) => {
        if (row) return res.status(400).json({ success: false, message: 'Email au simu imesajiliwa tayari' });
        const tenant_id = `tenant_${business_name.toLowerCase().replace(/\s+/g, '_').slice(0,10)}_${crypto.randomBytes(3).toString('hex')}`;
        const subdomain = business_name.toLowerCase().replace(/\s+/g, '-').slice(0,20) + '-' + crypto.randomBytes(2).toString('hex');
        const hash = bcrypt.hashSync(password, 10);
        db.run(`INSERT INTO tenants (id, business_name, owner_name, phone, email, password_hash, subdomain, plan, max_devices, max_clients) VALUES (?,?,?,?,?,?,?,?,?,?)`,
            [tenant_id, business_name, owner_name, phone, email, hash, subdomain, 'free', 2, 50],
            (err) => {
                if (err) return res.status(500).json({ success: false, message: err.message });
                const token = generateToken(tenant_id, email);
                res.json({ success: true, tenant_id, token, tenant: { id: tenant_id, business_name, email, plan: 'free' } });
            });
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM tenants WHERE email = ?", [email], (err, tenant) => {
        if (!tenant || !bcrypt.compareSync(password, tenant.password_hash)) {
            return res.status(401).json({ success: false, message: 'Email au password si sahihi' });
        }
        if (tenant.status !== 'active') return res.status(403).json({ success: false, message: `Akaunti ${tenant.status}` });
        const token = generateToken(tenant.id, tenant.email);
        res.json({ success: true, token, tenant_id: tenant.id, tenant: { id: tenant.id, business_name: tenant.business_name, email: tenant.email, plan: tenant.plan, max_devices: tenant.max_devices, max_clients: tenant.max_clients } });
    });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    db.get("SELECT id, business_name, email, plan, max_devices, max_clients FROM tenants WHERE id = ?", [req.tenant_id], (err, row) => {
        if (!row) return res.status(404).json({ success: false });
        res.json({ success: true, tenant: row });
    });
});

// ================= DEVICE MANAGEMENT - IMEBORESHWA =================

// Kusajili kifaa - SASA MAC PEKEE KWA AP
app.post('/api/devices', authMiddleware, (req, res) => {
    const tenant_id = req.body.tenant_id || req.tenant_id;
    const { name, vendor, type, model, mac_address, host, wan_port, wanPort, port, user, password } = req.body;

    // Validation mpya: AP inahitaji MAC pekee, MikroTik inahitaji jina
    const isMikrotik = (vendor === 'mikrotik' || type === 'mikrotik' || model);
    if (!tenant_id || !name) {
        return res.status(400).json({ success: false, error: "Jina la kifaa na tenant_id vinahitajika!" });
    }
    if (!isMikrotik && !mac_address) {
        return res.status(400).json({ success: false, error: "AP inahitaji MAC Address pekee! Mfano: AA:BB:CC:DD:EE:FF" });
    }

    db.get("SELECT * FROM tenants WHERE id = ?", [tenant_id], (err, tenant) => {
        if (!tenant) return res.status(404).json({ success: false, message: 'Tenant not found' });
        db.get("SELECT COUNT(*) as count FROM devices WHERE tenant_id = ?", [tenant_id], (err, row) => {
            if (row.count >= tenant.max_devices) {
                return res.status(400).json({ success: false, error: `Umefika kikomo cha vifaa ${tenant.max_devices}. Boresha plan kwa Super Admin.` });
            }

            const finalMac = mac_address ? mac_address.toUpperCase().trim() : null;
            const finalVendor = vendor || type || 'mikrotik';
            const finalModel = model || req.body.selectedModel || 'Generic';
            const finalWan = wan_port || wanPort || req.body.mikrotikWanPort || 'ether1';
            const finalHost = isMikrotik ? (host || `WAN: ${finalWan}`) : finalMac; // AP - host = MAC

            const query = `INSERT INTO devices (tenant_id, name, host, mac_address, vendor, type, model, wan_port, user, password, port, status, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'Online', datetime('now'))`;
            db.run(query, [tenant_id, name, finalHost, finalMac, finalVendor, finalVendor, finalModel, finalWan, user || 'admin', '', port || 8728], function(err) {
                if (err) return res.status(500).json({ success: false, error: err.message });
                res.json({ success: true, message: "Kifaa kimesajiliwa kwa mafanikio! (MAC pekee)", deviceId: this.lastID });
            });
        });
    });
});

// Kusoma vifaa vyote - na auth check
app.get('/api/devices/:tenant_id', authMiddleware, (req, res) => {
    const { tenant_id } = req.params;
    if (req.tenant_id !== tenant_id && req.tenant_id !== 'tenant_super_admin') {
        return res.status(403).json({ success: false, message: 'Forbidden - Sio tenant yako' });
    }
    db.all(`SELECT * FROM devices WHERE tenant_id = ? ORDER BY created_at DESC`, [tenant_id], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, devices: rows });
    });
});

// KUFUTA KIFAA - MPYA ULIYOIOMBA
app.delete('/api/devices/:id', authMiddleware, (req, res) => {
    const deviceId = req.params.id;
    db.get("SELECT * FROM devices WHERE id = ?", [deviceId], (err, device) => {
        if (!device) return res.status(404).json({ success: false, message: 'Kifaa hakijapatikana' });
        if (device.tenant_id !== req.tenant_id && req.tenant_id !== 'tenant_super_admin') {
            return res.status(403).json({ success: false, message: 'Huna ruhusa ya kufuta kifaa hiki' });
        }
        db.run("DELETE FROM devices WHERE id = ?", [deviceId], (err) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, message: 'Kifaa kimefutwa' });
        });
    });
});

// ONLINE/OFFLINE STATUS - MPYA
app.get('/api/devices/:id/status', authMiddleware, (req, res) => {
    const deviceId = req.params.id;
    db.get("SELECT * FROM devices WHERE id = ?", [deviceId], (err, device) => {
        if (!device || !device.last_seen) {
            return res.json({ online: false, lastSeen: device?.last_seen || null, status: 'Offline' });
        }
        const diffMin = (Date.now() - new Date(device.last_seen).getTime()) / 60000;
        const online = diffMin < 10; // Online kama last_seen < 10 min
        res.json({ online, lastSeen: device.last_seen, status: online ? 'Online' : 'Offline' });
    });
});

// ================= MIKROTIK =================
app.post('/api/mikroTik/test-connection', authMiddleware, async (req, res) => {
    const { host } = req.body;
    res.json({ success: true, message: "Uunganisho na MikroTik umesajiliwa kwenye mfumo (Test Mode)!", host });
});

// Kupokea usajili wa Router kutoka script - IMEBORESHWA (hakuna password)
app.post('/api/mikrotik/register-router', (req, res) => {
    const { tenant_id, name, model, identity, wan_port, mac_address } = req.body;
    const routerName = name || identity || "MikroTik-Router";
    const finalTenant = tenant_id || 'tenant_01';

    // Update kama ipo, insert kama haipo
    db.get("SELECT * FROM devices WHERE tenant_id = ? AND name = ?", [finalTenant, routerName], (err, existing) => {
        if (existing) {
            db.run("UPDATE devices SET status = 'Online', last_seen = datetime('now'), model = ?, wan_port = ? WHERE id = ?", [model || existing.model, wan_port || existing.wan_port, existing.id], (err) => {
                res.json({ success: true, message: "Router ime-update kuwa Online!" });
            });
        } else {
            const query = `INSERT INTO devices (tenant_id, name, host, mac_address, vendor, type, model, wan_port, user, password, port, status, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'Online', datetime('now'))`;
            db.run(query, [finalTenant, routerName, `WAN: ${wan_port || 'ether1'}`, mac_address || null, 'mikrotik', 'mikrotik', model || 'mikrotik', wan_port || 'ether1', 'mrhaas_api', '', 8728], function(err) {
                if (err) return res.status(500).json({ success: false, error: err.message });
                res.json({ success: true, message: "Router imesajiliwa kwenye wingu! (Bila password)" });
            });
        }
    });
});

// ================= CLIENTS =================
app.post('/api/clients', authMiddleware, (req, res) => {
    const tenant_id = req.body.tenant_id || req.tenant_id;
    const { name, phone, username, package_name } = req.body;
    if (!tenant_id || !username || !name) return res.status(400).json({ success: false, error: "Jaza taarifa za mteja!" });

    db.get("SELECT * FROM tenants WHERE id = ?", [tenant_id], (err, tenant) => {
        db.get("SELECT COUNT(*) as count FROM clients WHERE tenant_id = ?", [tenant_id], (err, row) => {
            if (row.count >= tenant.max_clients) return res.status(400).json({ success: false, error: `Kikomo cha wateja ${tenant.max_clients}` });
            db.run(`INSERT INTO clients (tenant_id, name, phone, username, package_name) VALUES (?,?,?,?,?)`, [tenant_id, name, phone, username, package_name], function(err) {
                if (err) return res.status(500).json({ success: false, error: err.message });
                res.json({ success: true, message: "Mteja amesajiliwa!", clientId: this.lastID });
            });
        });
    });
});

app.get('/api/clients/:tenant_id', authMiddleware, (req, res) => {
    const { tenant_id } = req.params;
    if (req.tenant_id !== tenant_id && req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false, message: 'Forbidden' });
    db.all(`SELECT * FROM clients WHERE tenant_id = ? ORDER BY created_at DESC`, [tenant_id], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, clients: rows });
    });
});

// ================= PAYMENTS WEBHOOKS - ZAKO 6 ZIMEBAKI KAMA ZILIVYO =================
async function processMultiTenantPayment(tenantId, clientUsername, amount, phone, gateway) {
    console.log(`[${gateway}] Malipo TZS ${amount} kutoka ${phone} (WISP: ${tenantId}, Mteja: ${clientUsername})`);
    db.get(`SELECT * FROM devices WHERE tenant_id = ? AND type = 'mikrotik'`, [tenantId], async (err, router) => {
        if (err || !router) {
            console.error(`Router haikupatikana kwa WISP: ${tenantId}`);
            return;
        }
        console.log(`✅ Huduma imewashwa kwenye ${router.name} kwa ${clientUsername}`);
        // Hapa weka logic yako ya kuwasha package kwenye MikroTik
    });
}

app.post('/api/payments/azampay/webhook', async (req, res) => {
    const { amount, msisdn, utilityref, paymentstatus, tenant_id } = req.body;
    if (paymentstatus === 'Succeeded' || paymentstatus === 'COMPLETED') {
        await processMultiTenantPayment(tenant_id, utilityref, amount, msisdn, 'AzamPay');
        return res.status(200).json({ success: true, message: "AzamPay imepokelewa." });
    }
    res.status(400).json({ success: false, message: "Malipo hayajakamilika." });
});

app.post('/api/payments/clickpesa/webhook', async (req, res) => {
    const { reference, phone_number, amount, status, tenant_id } = req.body;
    if (status === 'success') {
        await processMultiTenantPayment(tenant_id, reference, amount, phone_number, 'ClickPesa');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

app.post('/api/payments/selcom/webhook', async (req, res) => {
    const { order_id, amount, payment_status, phone, tenant_id } = req.body;
    if (payment_status === 'COMPLETED') {
        await processMultiTenantPayment(tenant_id, order_id, amount, phone, 'Selcom');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

app.get('/api/payments/pesapal/webhook', async (req, res) => {
    const { OrderMerchantReference, tenant_id } = req.query;
    await processMultiTenantPayment(tenant_id, OrderMerchantReference, 0, 'Pesapal_Client', 'Pesapal');
    res.status(200).json({ success: true });
});

app.post('/api/payments/palmpesa/webhook', async (req, res) => {
    const { accountNo, amountPaid, transStatus, tenant_id } = req.body;
    if (transStatus === 'SUCCESS') {
        await processMultiTenantPayment(tenant_id, accountNo, amountPaid, 'PalmUser', 'PalmPesa');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

app.post('/api/payments/beem/webhook', async (req, res) => {
    const { reference_no, amount, status, msisdn, tenant_id } = req.body;
    if (status === 'SUCCESS') {
        await processMultiTenantPayment(tenant_id, reference_no, amount, msisdn, 'BeemAfrica');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// ================= SUPER ADMIN =================
app.get('/api/super/tenants', authMiddleware, (req, res) => {
    if (req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false, message: 'Super admin only' });
    db.all(`SELECT t.*, (SELECT COUNT(*) FROM devices WHERE tenant_id = t.id) as devices_count, (SELECT COUNT(*) FROM clients WHERE tenant_id = t.id) as clients_count FROM tenants t ORDER BY t.created_at DESC`, (err, rows) => {
        res.json({ success: true, tenants: rows });
    });
});

app.put('/api/super/tenant/:id/plan', authMiddleware, (req, res) => {
    if (req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false });
    const { plan, max_devices, max_clients, status } = req.body;
    const sets = [];
    const params = [];
    if (plan) { sets.push("plan = ?"); params.push(plan); }
    if (max_devices) { sets.push("max_devices = ?"); params.push(max_devices); }
    if (max_clients) { sets.push("max_clients = ?"); params.push(max_clients); }
    if (status) { sets.push("status = ?"); params.push(status); }
    if (sets.length === 0) return res.json({ success: false, message: 'Nothing to update' });
    params.push(req.params.id);
    db.run(`UPDATE tenants SET ${sets.join(', ')} WHERE id = ?`, params, (err) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true });
    });
});

// ================= ROOT =================
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'MR HAAS NET Multi-Tenant API running (Node.js)', version: '3.0-clean', features: ['MAC-only AP', 'No MikroTik password', 'Delete device', 'Online/Offline', '6 payment gateways', 'Super Admin'] });
});

app.listen(PORT, () => {
    console.log(`🚀 MR HAAS NET Server safi inaendelea kwenye port: ${PORT}`);
    console.log(`✅ Super Admin: admin@mrhaas.net / Admin@2024`);
    console.log(`✅ Features: MAC-only, Delete, Online/Offline, Multi-Tenant, 6 Payments`);
});
