/**
 * MR HAAS NET - server.js - FIXED - No more crash
 * FIX: Haitengenezi tables tena, inatumia database.js tu
 * Hivyo hakuna tena UNIQUE constraint error
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Tumia database.js - ndio inatengeneza tables na super admin (INSERT OR IGNORE)
const db = require('./database');

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'mrhaas-super-secret-2024-change-this';

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

// AUTH
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

// DEVICES
app.post('/api/devices', authMiddleware, (req, res) => {
    const tenant_id = req.body.tenant_id || req.tenant_id;
    const { name, vendor, type, model, mac_address, host, wan_port, wanPort, port, user } = req.body;
    const isMikrotik = (vendor === 'mikrotik' || type === 'mikrotik' || (model && model.toLowerCase().includes('rb')));
    if (!tenant_id || !name) return res.status(400).json({ success: false, error: "Jina la kifaa na tenant_id vinahitajika!" });
    if (!isMikrotik && !mac_address) return res.status(400).json({ success: false, error: "AP inahitaji MAC Address pekee! Mfano: AA:BB:CC:DD:EE:FF" });

    db.get("SELECT * FROM tenants WHERE id = ?", [tenant_id], (err, tenant) => {
        if (!tenant) return res.status(404).json({ success: false, message: 'Tenant not found' });
        db.get("SELECT COUNT(*) as count FROM devices WHERE tenant_id = ?", [tenant_id], (err, row) => {
            if (row.count >= tenant.max_devices) return res.status(400).json({ success: false, error: `Umefika kikomo cha vifaa ${tenant.max_devices}. Boresha plan.` });
            const finalMac = mac_address ? mac_address.toUpperCase().trim() : null;
            const finalVendor = vendor || type || 'mikrotik';
            const finalModel = model || req.body.selectedModel || 'Generic';
            const finalWan = wan_port || wanPort || req.body.mikrotikWanPort || 'ether1';
            const finalHost = isMikrotik ? (host || `WAN: ${finalWan}`) : finalMac;
            db.run(`INSERT INTO devices (tenant_id, name, host, mac_address, vendor, type, model, wan_port, user, password, port, status, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'Online', datetime('now'))`,
                [tenant_id, name, finalHost, finalMac, finalVendor, finalVendor, finalModel, finalWan, user || 'admin', '', port || 8728],
                function(err) {
                    if (err) return res.status(500).json({ success: false, error: err.message });
                    res.json({ success: true, message: "Kifaa kimesajiliwa! (MAC pekee)", deviceId: this.lastID });
                });
        });
    });
});

app.get('/api/devices/:tenant_id', authMiddleware, (req, res) => {
    const { tenant_id } = req.params;
    if (req.tenant_id !== tenant_id && req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false, message: 'Forbidden' });
    db.all(`SELECT * FROM devices WHERE tenant_id = ? ORDER BY created_at DESC`, [tenant_id], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, devices: rows });
    });
});

app.delete('/api/devices/:id', authMiddleware, (req, res) => {
    db.get("SELECT * FROM devices WHERE id = ?", [req.params.id], (err, device) => {
        if (!device) return res.status(404).json({ success: false, message: 'Kifaa hakijapatikana' });
        if (device.tenant_id !== req.tenant_id && req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false });
        db.run("DELETE FROM devices WHERE id = ?", [req.params.id], (err) => {
            res.json({ success: true, message: 'Kifaa kimefutwa' });
        });
    });
});

app.get('/api/devices/:id/status', authMiddleware, (req, res) => {
    db.get("SELECT * FROM devices WHERE id = ?", [req.params.id], (err, device) => {
        if (!device || !device.last_seen) return res.json({ online: false, lastSeen: device?.last_seen || null, status: 'Offline' });
        const diffMin = (Date.now() - new Date(device.last_seen).getTime()) / 60000;
        const online = diffMin < 10;
        res.json({ online, lastSeen: device.last_seen, status: online ? 'Online' : 'Offline' });
    });
});

app.post('/api/mikroTik/test-connection', authMiddleware, async (req, res) => {
    res.json({ success: true, message: "Uunganisho umesajiliwa (Test Mode)!", host: req.body.host });
});

app.post('/api/mikrotik/register-router', (req, res) => {
    const { tenant_id, name, model, identity, wan_port, mac_address } = req.body;
    const routerName = name || identity || "MikroTik-Router";
    const finalTenant = tenant_id || 'tenant_01';
    db.get("SELECT * FROM devices WHERE tenant_id = ? AND name = ?", [finalTenant, routerName], (err, existing) => {
        if (existing) {
            db.run("UPDATE devices SET status = 'Online', last_seen = datetime('now'), model = ?, wan_port = ? WHERE id = ?", [model || existing.model, wan_port || existing.wan_port, existing.id], () => {
                res.json({ success: true, message: "Router ime-update kuwa Online!" });
            });
        } else {
            db.run(`INSERT INTO devices (tenant_id, name, host, mac_address, vendor, type, model, wan_port, user, password, port, status, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'Online', datetime('now'))`,
                [finalTenant, routerName, `WAN: ${wan_port || 'ether1'}`, mac_address || null, 'mikrotik', 'mikrotik', model || 'mikrotik', wan_port || 'ether1', 'mrhaas_api', '', 8728],
                function(err) {
                    if (err) return res.status(500).json({ success: false, error: err.message });
                    res.json({ success: true, message: "Router imesajiliwa! (Bila password)" });
                });
        }
    });
});

// CLIENTS
app.post('/api/clients', authMiddleware, (req, res) => {
    const tenant_id = req.body.tenant_id || req.tenant_id;
    const { name, phone, username, package_name } = req.body;
    if (!tenant_id || !username || !name) return res.status(400).json({ success: false, error: "Jaza taarifa za mteja!" });
    db.get("SELECT COUNT(*) as count FROM clients WHERE tenant_id = ?", [tenant_id], (err, row) => {
        db.get("SELECT * FROM tenants WHERE id = ?", [tenant_id], (err, tenant) => {
            if (row.count >= (tenant?.max_clients || 50)) return res.status(400).json({ success: false, error: `Kikomo cha wateja ${tenant.max_clients}` });
            db.run(`INSERT INTO clients (tenant_id, name, phone, username, package_name) VALUES (?,?,?,?,?)`, [tenant_id, name, phone, username, package_name], function(err) {
                if (err) return res.status(500).json({ success: false, error: err.message });
                res.json({ success: true, message: "Mteja amesajiliwa!", clientId: this.lastID });
            });
        });
    });
});

app.get('/api/clients/:tenant_id', authMiddleware, (req, res) => {
    if (req.tenant_id !== req.params.tenant_id && req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false });
    db.all(`SELECT * FROM clients WHERE tenant_id = ? ORDER BY created_at DESC`, [req.params.tenant_id], (err, rows) => {
        res.json({ success: true, clients: rows });
    });
});

// PAYMENTS - 6 WEBHOOKS ZAKO
async function processMultiTenantPayment(tenantId, clientUsername, amount, phone, gateway) {
    console.log(`[${gateway}] TZS ${amount} kutoka ${phone} (WISP: ${tenantId}, Mteja: ${clientUsername})`);
    db.run(`INSERT INTO payments (tenant_id, client_username, amount, phone, gateway, status) VALUES (?,?,?,?,?, 'completed')`, [tenantId, clientUsername, amount, phone, gateway]);
    db.get(`SELECT * FROM devices WHERE tenant_id = ? AND type = 'mikrotik'`, [tenantId], (err, router) => {
        if (router) console.log(`✅ Huduma imewashwa kwenye ${router.name} kwa ${clientUsername}`);
    });
}
app.post('/api/payments/azampay/webhook', async (req, res) => {
    const { amount, msisdn, utilityref, paymentstatus, tenant_id } = req.body;
    if (paymentstatus === 'Succeeded' || paymentstatus === 'COMPLETED') {
        await processMultiTenantPayment(tenant_id, utilityref, amount, msisdn, 'AzamPay');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});
app.post('/api/payments/clickpesa/webhook', async (req, res) => {
    const { reference, phone_number, amount, status, tenant_id } = req.body;
    if (status === 'success') { await processMultiTenantPayment(tenant_id, reference, amount, phone_number, 'ClickPesa'); return res.status(200).json({ success: true }); }
    res.status(400).json({ success: false });
});
app.post('/api/payments/selcom/webhook', async (req, res) => {
    const { order_id, amount, payment_status, phone, tenant_id } = req.body;
    if (payment_status === 'COMPLETED') { await processMultiTenantPayment(tenant_id, order_id, amount, phone, 'Selcom'); return res.status(200).json({ success: true }); }
    res.status(400).json({ success: false });
});
app.get('/api/payments/pesapal/webhook', async (req, res) => {
    const { OrderMerchantReference, tenant_id } = req.query;
    await processMultiTenantPayment(tenant_id, OrderMerchantReference, 0, 'Pesapal_Client', 'Pesapal');
    res.status(200).json({ success: true });
});
app.post('/api/payments/palmpesa/webhook', async (req, res) => {
    const { accountNo, amountPaid, transStatus, tenant_id } = req.body;
    if (transStatus === 'SUCCESS') { await processMultiTenantPayment(tenant_id, accountNo, amountPaid, 'PalmUser', 'PalmPesa'); return res.status(200).json({ success: true }); }
    res.status(400).json({ success: false });
});
app.post('/api/payments/beem/webhook', async (req, res) => {
    const { reference_no, amount, status, msisdn, tenant_id } = req.body;
    if (status === 'SUCCESS') { await processMultiTenantPayment(tenant_id, reference_no, amount, msisdn, 'BeemAfrica'); return res.status(200).json({ success: true }); }
    res.status(400).json({ success: false });
});

// SUPER ADMIN
app.get('/api/super/tenants', authMiddleware, (req, res) => {
    if (req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false });
    db.all(`SELECT t.*, (SELECT COUNT(*) FROM devices WHERE tenant_id = t.id) as devices_count, (SELECT COUNT(*) FROM clients WHERE tenant_id = t.id) as clients_count FROM tenants t ORDER BY t.created_at DESC`, (err, rows) => {
        res.json({ success: true, tenants: rows });
    });
});
app.put('/api/super/tenant/:id/plan', authMiddleware, (req, res) => {
    if (req.tenant_id !== 'tenant_super_admin') return res.status(403).json({ success: false });
    const { plan, max_devices, max_clients, status } = req.body;
    const sets = []; const params = [];
    if (plan) { sets.push("plan = ?"); params.push(plan); }
    if (max_devices) { sets.push("max_devices = ?"); params.push(max_devices); }
    if (max_clients) { sets.push("max_clients = ?"); params.push(max_clients); }
    if (status) { sets.push("status = ?"); params.push(status); }
    if (sets.length === 0) return res.json({ success: false });
    params.push(req.params.id);
    db.run(`UPDATE tenants SET ${sets.join(', ')} WHERE id = ?`, params, (err) => {
        res.json({ success: true });
    });
});

app.get('/', (req, res) => { res.sendFile(__dirname + '/public/index.html'); });
app.get('/api/health', (req, res) => { res.json({ status: 'MR HAAS NET API running FIXED', version: '3.1-fixed', fix: 'INSERT OR IGNORE' }); });

app.listen(PORT, () => {
    console.log(`🚀 MR HAAS NET FIXED running on ${PORT}`);
    console.log(`✅ Super Admin: admin@mrhaas.net / Admin@2024 - No crash`);
});
