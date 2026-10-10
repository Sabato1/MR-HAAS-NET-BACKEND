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
