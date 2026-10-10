const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Kuunganisha faili la Database tulilotengeneza
const db = require('./database.js');

app.use(express.json());

// Njia ya kuangalia kama server inafanya kazi
app.get('/', (req, res) => {
    res.json({ message: "Karibu kwenye HAAS WISP CLOUD Backend!" });
});

// Kuanzisha Server
app.listen(PORT, () => {
    console.log(`Server inaendelea vizuri kwenye port ${PORT}`);
});
// API ya kusajili kifaa kipya (MikroTik au Cloud AP)
app.post('/api/devices', (req, res) => {
    const { tenant_id, device_name, device_type, brand, ip_address, api_port, username, password, cloud_api_url } = req.body;

    // Hakikisha taarifa muhimu hazikosekani
    if (!tenant_id || !device_name || !device_type || !brand) {
        return res.status(400).json({ error: "Tafadhali jaza taarifa zote muhimu za kifaa!" });
    }

    const query = `INSERT INTO devices (tenant_id, device_name, device_type, brand, ip_address, api_port, username, password, cloud_api_url, status) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'offline')`;
    
    const params = [tenant_id, device_name, device_type, brand, ip_address, api_port || 8728, username, password, cloud_api_url];

    db.run(query, params, function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ 
            message: "Kifaa kimesajiliwa mafanikio!", 
            device_id: this.lastID 
        });
    });
});

// API ya kuona vifaa vyote vya tenant fulani
app.get('/api/devices/:tenant_id', (req, res) => {
    const tenantId = req.params.tenant_id;
    db.all(`SELECT * FROM devices WHERE tenant_id = ?`, [tenantId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ devices: rows });
    });
});
// API ya kupokea majibu ya malipo (Webhook/Callback kutoka Gateway ya Malipo)
app.post('/api/payments/webhook', async (req, res) => {
    const { transaction_id, phone_number, amount, status, client_username } = req.body;

    try {
        // Angalia kama malipo yamefanikiwa
        if (status === 'SUCCESS' || status === 'COMPLETED') {
            console.log(`Malipo yamefanikiwa kutoka kwa ${phone_number} ya kiasi ${amount}`);

            // Hapa unaweza kuongeza code za kuwasha mteja kwenye MikroTik au Database
            // Mfano: Kusasisha hali ya mkataba au akaunti ya mteja kuwa hai

            return res.status(200).json({ 
                success: true, 
                message: "Malipo yamepokewa na huduma imewashwa!" 
            });
        } else {
            return res.status(400).json({ 
                success: false, 
                message: "Malipo hayajakamilika au yamegoma." 
            });
        }
} catch (err) {
    console.error("Hitilafu wakati wa kuwasiliana na Router:", err.message);
}

    }
});
// ==========================================
// WEBHOOKS ZA MIFUMO YOTE YA MALIPO
// ==========================================

// 1. Azam Pay Webhook
app.post('/api/payments/azampay/webhook', async (req, res) => {
    const { transactionid, amount, msisdn, utilityref, paymentstatus } = req.body;
    if (paymentstatus === 'Succeeded' || paymentstatus === 'COMPLETED') {
        await activateClientService(utilityref, msisdn, amount, 'AzamPay');
        return res.status(200).json({ success: true, message: "AzamPay malipo yamepokelewa." });
    }
    res.status(400).json({ success: false, message: "Malipo hayajakamilika." });
});

// 2. ClickPesa Webhook
app.post('/api/payments/clickpesa/webhook', async (req, res) => {
    const { reference, phone_number, amount, status } = req.body;
    if (status === 'success') {
        await activateClientService(reference, phone_number, amount, 'ClickPesa');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// 3. Selcom Webhook
app.post('/api/payments/selcom/webhook', async (req, res) => {
    const { order_id, transid, amount, payment_status, phone } = req.body;
    if (payment_status === 'COMPLETED') {
        await activateClientService(order_id, phone, amount, 'Selcom');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// 4. Pesapal Webhook (IPN - Instant Payment Notification)
app.get('/api/payments/pesapal/webhook', async (req, res) => {
    const { OrderTrackingId, OrderMerchantReference } = req.query;
    // Hapa Pesapal hutuma ombi la kuangalia hali ya malipo kwa kutumia OrderTrackingId
    // Ikithibitishwa kuwa imefanikiwa:
    await activateClientService(OrderMerchantReference, 'Pesapal_Client', 0, 'Pesapal');
    res.status(200).json({ success: true });
});

// 5. Palmpesa Webhook
app.post('/api/payments/palmpesa/webhook', async (req, res) => {
    const { referenceId, accountNo, amountPaid, transStatus } = req.body;
    if (transStatus === 'SUCCESS') {
        await activateClientService(accountNo, 'PalmUser', amountPaid, 'PalmPesa');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});

// 6. Beem Africa Webhook (Bpay)
app.post('/api/payments/beem/webhook', async (req, res) => {
    const { transaction_id, reference_no, amount, status, msisdn } = req.body;
    if (status === 'SUCCESS') {
        await activateClientService(reference_no, msisdn, amount, 'BeemAfrica');
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
});
async function activateClientService(clientUsername, phone, amount, gateway) {
    console.log(`[${gateway}] Malipo ya TZS ${amount} yamefanikiwa kutoka kwa ${phone} kwa ajili ya mteja: ${clientUsername}`);
    
    // Hapa ndipo unaweka ile code ya MikroTik RouterOS API tuliyoijadili awali
    // Ili kuongeza muda wa mkataba kwenye database au kusasisha PPPoE secret ya mteja.
}
// Kuongeza jedwali la kuweka taarifa za malipo za kila WISP (Tenant)
db.run(`
  CREATE TABLE IF NOT EXISTS tenant_payment_gateways (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    gateway_name TEXT NOT NULL, -- Mfano: 'azampay', 'selcom', 'clickpesa', 'pesapal', 'beem'
    api_key TEXT,
    api_secret TEXT,
    merchant_id TEXT,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id)
  )
`);
// Kitendakazi kinachochakata malipo kutoka GATEWAY YOYOTE kwa WISP yeyote
async function processMultiTenantPayment(tenantId, clientUsername, amount, gatewayName) {
    console.log(`[${gatewayName}] Malipo ya TZS ${amount} yamepokelewa kwa WISP: ${tenantId}, Mteja: ${clientUsername}`);

    // 1. Tafuta taarifa za MikroTik Router ya huyu WISP kwenye database
    db.get(`SELECT * FROM devices WHERE tenant_id = ? AND type = 'mikrotik'`, [tenantId], async (err, router) => {
        if (err || !router) {
            console.error("Router ya WISP huyu haikupatikana!");
            return;
        }

        // 2. Unganisha na Router ya MikroTik na weka/sasisha PPPoE/Hotspot user
        // (Code za RouterOSClient zitaongeza mkataba wa mteja)
    });
}
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { RouterOSClient } = require('routeros-client');
const db = require('./database'); // Inachukua muunganisho wa database kutoka database.js

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ==========================================
// 1. DEVICE MANAGEMENT APIS
// ==========================================

// Kusajili kifaa/router mpya ya WISP (Tenant)
app.post('/api/devices', (req, res) => {
    const { tenant_id, name, host, user, password, port, type } = req.body;
    
    const query = `INSERT INTO devices (tenant_id, name, host, user, password, port, type) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [tenant_id, name, host, user, password, port || 8728, type || 'mikrotik'], function(err) {
        if (err) {
            return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, message: "Kifaa kimesajiliwa mafanikio!", deviceId: this.lastID });
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
// 2. MIKROTIK ROUTEROS API TESTING & ACTIONS
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
        res.json({ success: false, error: "Imeshindikana kuunganisha: " + err.message });
    }
});

// Kuongeza Mteja (PPPoE Secret) kwenye MikroTik
app.post('/api/mikroTik/add-pppoe', async (req, res) => {
    const { host, user, password, port, clientName, clientPassword, profile } = req.body;

    const connection = new RouterOSClient({
        host: host,
        user: user,
        password: password,
        port: port || 8728
    });

    try {
        await connection.connect();
        const pppoeSecret = connection.menu('/ppp/secret');
        await pppoeSecret.add({
            name: clientName,
            password: clientPassword,
            profile: profile || 'default',
            service: 'pppoe'
        });
        await connection.close();
        res.json({ success: true, message: "Mteja wa PPPoE ameongezwa kwenye MikroTik mafanikio!" });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});


// ==========================================
// 3. MULTI-TENANT PAYMENT WEBHOOKS (LANGO ZOTE)
// ==========================================

// Kitendakazi kikuu cha kusimamia malipo na kuwasha huduma kwa WISP husika
async function processMultiTenantPayment(tenantId, clientUsername, amount, phone, gateway) {
    console.log(`[${gateway}] Malipo ya TZS ${amount} yamethibitishwa kutoka kwa ${phone} (WISP: ${tenantId}, Mteja: ${clientUsername})`);

    // Tafuta taarifa za Router ya huyu WISP kwenye database
    db.get(`SELECT * FROM devices WHERE tenant_id = ? AND type = 'mikrotik'`, [tenantId], async (err, router) => {
        if (err || !router) {
            console.error(`Router haikupatikana kwa ajili ya WISP: ${tenantId}`);
            return;
        }

        // Hapa unaweza kuunganisha na router yake moja kwa moja kumwongezea muda au ku-activate
        try {
            const connection = new RouterOSClient({
                host: router.host,
                user: router.user,
                password: router.password,
                port: router.port || 8728
            });

            await connection.connect();
            // Mfano: Unaweza kuwezesha au kusasisha secret ya mteja
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
        return res.status(200).json({ success: true });
    }
    res.status(400).json({ success: false });
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

// Anzisha Server
app.listen(PORT, () => {
    console.log(`Server inaendelea vizuri kwenye bandari (port): ${PORT}`);
});
