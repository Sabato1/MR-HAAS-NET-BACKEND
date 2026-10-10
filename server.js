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
    } catc (err) {
        console.error("Hitilafu kwenye malipo webhook:", err.message);
        res.status(500).json({ error: err.message });
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
