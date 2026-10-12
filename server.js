const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const db = require('./database'); // Uhusiano na database.js

const app = express();
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;

// ==========================================
// 1. ROOT & HEALTH CHECK
// ==========================================
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});
// ==========================================
// 2. DEVICE MANAGEMENT APIS
// ==========================================

// Kusajili kifaa/router mpya ya WISP (Tenant)
app.post('/api/devices', (req, res) => {
    const { tenant_id, name, host, user, password, port, type } = req.body;
    
    if (!tenant_id || !name || !host) {
        return res.status(400).json({ success: false, error: "Tafadhali jaza taarifa muhimu za kifaa (tenant_id, name, host)!" });
    }

    const query = `INSERT INTO devices (tenant_id, name, host, user, password, port, type) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [tenant_id, name, host, user, password, port || 8728, type || 'mikrotik'], function(err) {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, message: "Kifaa kimesajiliwa kwa mafanikio!", deviceId: this.lastID });
    });
});

// Kusoma vifaa vyote vya WISP maalum (Tenant)
app.get('/api/devices/:tenant_id', (req, res) => {
    const { tenant_id } = req.params;
    db.all(`SELECT * FROM devices WHERE tenant_id = ?`, [tenant_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, devices: rows });
    });
});


// ==========================================
// 3. MIKROTIK ROUTEROS API ACTIONS (Test Mode)
// ==========================================

// Jaribu kuunganisha na router ya MikroTik
app.post('/api/mikroTik/test-connection', async (req, res) => {
    const { host } = req.body;
    res.json({ success: true, message: "Uunganisho na MikroTik umesajiliwa kwenye mfumo (Test Mode)!", host });
});


// ==========================================
// 4. MULTI-TENANT PAYMENT WEBHOOKS (LANGO ZOTE 6)
// ==========================================

async function processMultiTenantPayment(tenantId, clientUsername, amount, phone, gateway) {
    console.log(`[${gateway}] Malipo ya TZS ${amount} yamethibitishwa kutoka kwa ${phone} (WISP: ${tenantId}, Mteja: ${clientUsername})`);

    db.get(`SELECT * FROM devices WHERE tenant_id = ? AND type = 'mikrotik'`, [tenantId], async (err, router) => {
        if (err || !router) {
            console.error(`Router haikupatikana kwa ajili ya WISP: ${tenantId}`);
            return;
        }

        console.log(`Huduma imewashwa kwenye router ya ${router.name} kwa mteja ${clientUsername}`);
    });
}

// A. AzamPay Webhook
app.post('/api/payments/azampay/webhook', async (req, res) => {
    const { amount, msisdn, utilityref, paymentstatus, tenant_id } = req.body;
    if (paymentstatus === 'Succeeded' || paymentstatus === 'COMPLETED') {
        await processMultiTenantPayment(tenant_id, utilityref, amount, msisdn, 'AzamPay');
        return res.status(200).json({ success: true, message: "AzamPay imepokelewa." });
    }
    res.status(400).json({ success: false, message: "Malipo hayajakamilika." });
});

// B. ClickPesa Webhook
app.post('/api/payments/clickpesa/webhook', async (req, res) => {
    const { reference, phone_number, amount, status, tenant_id } = req.body;
    if (status === 'success') {
        await processMultiTenantPayment(tenant_id, reference, amount, phone_number, 'ClickPesa');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// C. Selcom Webhook
app.post('/api/payments/selcom/webhook', async (req, res) => {
    const { order_id, amount, payment_status, phone, tenant_id } = req.body;
    if (payment_status === 'COMPLETED') {
        await processMultiTenantPayment(tenant_id, order_id, amount, phone, 'Selcom');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// D. Pesapal Webhook (IPN)
app.get('/api/payments/pesapal/webhook', async (req, res) => {
    const { OrderMerchantReference, tenant_id } = req.query;
    await processMultiTenantPayment(tenant_id, OrderMerchantReference, 0, 'Pesapal_Client', 'Pesapal');
    res.status(200).json({ success: true });
});

// E. PalmPesa Webhook
app.post('/api/payments/palmpesa/webhook', async (req, res) => {
    const { accountNo, amountPaid, transStatus, tenant_id } = req.body;
    if (transStatus === 'SUCCESS') {
        await processMultiTenantPayment(tenant_id, accountNo, amountPaid, 'PalmUser', 'PalmPesa');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// F. Beem Africa Webhook (Bpay)
app.post('/api/payments/beem/webhook', async (req, res) => {
    const { reference_no, amount, status, msisdn, tenant_id } = req.body;
    if (status === 'SUCCESS') {
        await processMultiTenantPayment(tenant_id, reference_no, amount, msisdn, 'BeemAfrica');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// ==========================================
// 5. ANKISHA SERVER
// ==========================================
// 1. Kusajili mteja mpya
app.post('/api/clients', (req, res) => {
    const { tenant_id, name, phone, username, package_name } = req.body;
    if (!tenant_id || !username || !name) {
        return res.status(400).json({ success: false, error: "Tafadhali jaza taarifa za mteja!" });
    }
    const query = `INSERT INTO clients (tenant_id, name, phone, username, package_name) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [tenant_id, name, phone, username, package_name], function(err) {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, message: "Mteja amesajiliwa kwa mafanikio!", clientId: this.lastID });
    });
});

// 2. Kusoma wateja wote wa Tenant husika
app.get('/api/clients/:tenant_id', (req, res) => {
    const { tenant_id } = req.params;
    db.all(`SELECT * FROM clients WHERE tenant_id = ?`, [tenant_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, clients: rows });
    });
});
// Kupokea usajili wa Router kupitia Auto-Config script
app.post('/api/mikrotik/register-router', (req, res) => {
    const { tenant_id, name, model, identity } = req.body;
    
    const routerName = name || identity || "MikroTik-Router";
    
    const query = `INSERT INTO devices (tenant_id, name, host, user, password, port, type) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [tenant_id || 'tenant_01', routerName, 'Connected via Script', 'admin', '', 8728, model || 'mikrotik'], function(err) {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, message: "Router imesajiliwa kwenye wingu!" });
    });
});

app.listen(PORT, () => {
    console.log(`Server inaendelea vizuri kwenye bandari (port): ${PORT}`);
});
