const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const db = require('./database'); // Uhusiano na database.js

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ==========================================
// 1. ROOT & HEALTH CHECK
// ==========================================
app.get('/', (req, res) => {
    res.json({ message: "Karibu kwenye MR-HAAS-NET-BACKEND WISP Billing SaaS Cloud!" });
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
// 3. MIKROTIK ROUTEROS API ACTIONS
// ==========================================

// Jaribu kuunganisha na router ya MikroTik
app.post('/api/mikroTik/test-connection', async (req, res) => {
    const { host, user, password, port } = req.body;

    const connection = new RouterOSClient({
        host: host,
        user: user,
        password: password,
        port: port || 8728,
        timeout: 5
    });

    try {
        await connection.connect();
        const resources = await connection.menu('/system/resource').get();
        await connection.close();

        res.json({ success: true, message: "Uunganisho na MikroTik umefanikiwa!", data: resources[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: "Imeshindikana kuunganisha: " + err.message });
    }
});


// ==========================================
// 4. MULTI-TENANT PAYMENT WEBHOOKS (LANGO ZOTE 6)
// ==========================================

// Kitendakazi kikuu cha kuchakata malipo na kuwasha huduma kwa mteja
async function processMultiTenantPayment(tenantId, clientUsername, amount, phone, gateway) {
    console.log(`[${gateway}] Malipo ya TZS ${amount} yamethibitishwa kutoka kwa ${phone} (WISP: ${tenantId}, Mteja: ${clientUsername})`);

    db.get(`SELECT * FROM devices WHERE tenant_id = ? AND type = 'mikrotik'`, [tenantId], async (err, router) => {
        if (err || !router) {
            console.error(`Router haikupatikana kwa ajili ya WISP: ${tenantId}`);
            return;
        }

        try {
            const connection = new RouterOSClient({
                host: router.host,
                user: router.user,
                password: router.password,
                port: router.port || 8728
            });

            await connection.connect();
            console.log(`Huduma imewashwa kwenye router ya ${router.name} kwa mteja ${clientUsername}`);
            await connection.close();
        } catch (routerErr) {
            console.error("Hitilafu wakati wa kuwasiliana na Router:", routerErr.message);
        }
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
app.listen(PORT, () => {
    console.log(`Server inaendelea vizuri kwenye bandari (port): ${PORT}`);
});
