
'use strict';

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const SECRET_KEY = process.env.SECRET_KEY;

if (IS_PRODUCTION && (!SECRET_KEY || SECRET_KEY.length < 32)) {
    throw new Error(
        'Set SECRET_KEY to a unique secret of at least 32 characters in Render Environment.'
    );
}

if (!SECRET_KEY) {
    console.warn('WARNING: Set a strong SECRET_KEY in Render Environment.');
}

const JWT_SECRET = SECRET_KEY || crypto.randomBytes(48).toString('hex');

app.disable('x-powered-by');
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function sendError(res, status, message) {
    return res.status(status).json({ success: false, message });
}

function authMiddleware(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ')
        ? header.slice(7)
        : '';

    if (!token) {
        return sendError(res, 401, 'Ingia kwanza.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (!decoded.tenant_id || !decoded.email) {
            return sendError(res, 401, 'Token si sahihi.');
        }

        req.tenant_id = decoded.tenant_id;
        req.email = decoded.email;
        next();
    } catch (err) {
        return sendError(res, 401, 'Token imeisha muda au si sahihi.');
    }
}

function requireSuperAdmin(req, res, next) {
    if (req.tenant_id !== 'tenant_super_admin') {
        return sendError(res, 403, 'Ruhusa ya Super Admin inahitajika.');
    }
    next();
}

function getTenantForRequest(req, requestedTenantId) {
    if (req.tenant_id === 'tenant_super_admin') {
        return requestedTenantId || null;
    }
    return req.tenant_id;
}

function isValidId(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

// --------------------------------------------------
// HEALTH
// --------------------------------------------------

app.get('/api/health', (req, res) => {
    res.json({
        status: 'MR HAAS NET API running',
        version: '3.2-secure',
        database: 'configured'
    });
});

// --------------------------------------------------
// AUTH: REGISTER
// --------------------------------------------------

app.post('/api/auth/register', (req, res) => {
    const {
        business_name,
        owner_name,
        phone,
        email,
        password
    } = req.body || {};

    if (
        !business_name || !owner_name || !phone ||
        !email || !password
    ) {
        return sendError(res, 400, 'Jaza taarifa zote.');
    }

    if (
        typeof password !== 'string' ||
        password.length < 8 ||
        password.length > 128
    ) {
        return sendError(
            res,
            400,
            'Nenosiri lazima liwe na angalau herufi 8.'
        );
    }

    const business = String(business_name).trim();
    const owner = String(owner_name).trim();
    const phoneNumber = String(phone).trim();
    const normalizedEmail = String(email).trim().toLowerCase();

    if (!business || !owner || !phoneNumber || !normalizedEmail) {
        return sendError(res, 400, 'Taarifa ulizoingiza si sahihi.');
    }

    db.get(
        'SELECT id FROM tenants WHERE email = ? OR phone = ?',
        [normalizedEmail, phoneNumber],
        (err, existing) => {
            if (err) {
                console.error('Registration lookup failed:', err.message);
                return sendError(res, 500, 'Imeshindikana kukagua usajili.');
            }

            if (existing) {
                return sendError(
                    res,
                    409,
                    'Email au namba ya simu imesajiliwa tayari.'
                );
            }

            const tenantId =
                'tenant_' +
                crypto.randomBytes(12).toString('hex');

            const subdomain =
                business.toLowerCase()
                    .replace(/[^a-z0-9]+/g, '-')
                    .replace(/^-|-$/g, '')
                    .slice(0, 20) +
                '-' +
                crypto.randomBytes(3).toString('hex');

            bcrypt.hash(password, 12, (hashErr, passwordHash) => {
                if (hashErr) {
                    console.error('Password hash failed:', hashErr.message);
                    return sendError(res, 500, 'Imeshindikana kusajili akaunti.');
                }

                db.run(
                    `INSERT INTO tenants
                    (id, business_name, owner_name, phone, email,
                     password_hash, subdomain, plan, max_devices, max_clients)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        tenantId,
                        business,
                        owner,
                        phoneNumber,
                        normalizedEmail,
                        passwordHash,
                        subdomain,
                        'free',
                        2,
                        50
                    ],
                    function (insertErr) {
                        if (insertErr) {
                            console.error('Tenant insert failed:', insertErr.message);

                            if (insertErr.message.includes('UNIQUE')) {
                                return sendError(
                                    res,
                                    409,
                                    'Email, simu au subdomain tayari inatumika.'
                                );
                            }

                            return sendError(
                                res,
                                500,
                                'Usajili umeshindikana.'
                            );
                        }

                        const token = jwt.sign(
                            {
                                tenant_id: tenantId,
                                email: normalizedEmail
                            },
                            JWT_SECRET,
                            { expiresIn: '7d' }
                        );

                        return res.status(201).json({
                            success: true,
                            tenant_id: tenantId,
                            token,
                            tenant: {
                                id: tenantId,
                                business_name: business,
                                email: normalizedEmail,
                                plan: 'free',
                                max_devices: 2,
                                max_clients: 50
                            }
                        });
                    }
                );
            });
        }
    );
});

// --------------------------------------------------
// AUTH: LOGIN
// --------------------------------------------------

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body || {};

    if (
        typeof email !== 'string' ||
        typeof password !== 'string' ||
        !email.trim() ||
        !password
    ) {
        return sendError(res, 400, 'Weka email na nenosiri.');
    }

    db.get(
        `SELECT id, business_name, email, password_hash,
                plan, max_devices, max_clients, status
         FROM tenants WHERE email = ?`,
        [email.trim().toLowerCase()],
        (err, tenant) => {
            if (err) {
                console.error('Login lookup failed:', err.message);
                return sendError(res, 500, 'Imeshindikana kuingia.');
            }

            if (!tenant || !tenant.password_hash) {
                return sendError(res, 401, 'Email au nenosiri si sahihi.');
            }

            bcrypt.compare(password, tenant.password_hash, (compareErr, matched) => {
                if (compareErr || !matched) {
                    return sendError(res, 401, 'Email au nenosiri si sahihi.');
                }

                if (tenant.status && tenant.status !== 'active') {
                    return sendError(
                        res,
                        403,
                        `Akaunti haijaruhusiwa kuingia: ${tenant.status}.`
                    );
                }

                const token = jwt.sign(
                    {
                        tenant_id: tenant.id,
                        email: tenant.email
                    },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );

                return res.json({
                    success: true,
                    token,
                    tenant_id: tenant.id,
                    tenant: {
                        id: tenant.id,
                        business_name: tenant.business_name,
                        email: tenant.email,
                        plan: tenant.plan,
                        max_devices: tenant.max_devices,
                        max_clients: tenant.max_clients
                    }
                });
            });
        }
    );
});

// --------------------------------------------------
// AUTH: CURRENT ACCOUNT
// --------------------------------------------------

app.get('/api/auth/me', authMiddleware, (req, res) => {
    db.get(
        `SELECT id, business_name, owner_name, email, phone,
                plan, max_devices, max_clients, status
         FROM tenants WHERE id = ?`,
        [req.tenant_id],
        (err, tenant) => {
            if (err) {
                return sendError(res, 500, 'Imeshindikana kupata akaunti.');
            }

            if (!tenant) {
                return sendError(res, 404, 'Akaunti haijapatikana.');
            }

            return res.json({ success: true, tenant });
        }
    );
});

// --------------------------------------------------
// DEVICES: ADD
// --------------------------------------------------

app.post('/api/devices', authMiddleware, (req, res) => {
    const body = req.body || {};
    const tenantId = getTenantForRequest(req, body.tenant_id);

    const {
        name,
        vendor,
        type,
        model,
        mac_address,
        host,
        wan_port,
        wanPort,
        port,
        user
    } = body;

    if (!tenantId || !isValidId(name)) {
        return sendError(res, 400, 'Jina la kifaa linahitajika.');
    }

    const isMikrotik =
        String(vendor || '').toLowerCase() === 'mikrotik' ||
        String(type || '').toLowerCase() === 'mikrotik' ||
        String(model || '').toLowerCase().includes('rb');

    const finalMac = mac_address
        ? String(mac_address).trim().toUpperCase()
        : null;

    if (!isMikrotik && !finalMac) {
        return sendError(
            res,
            400,
            'Access Point inahitaji MAC Address.'
        );
    }

    if (
        finalMac &&
        !/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(finalMac)
    ) {
        return sendError(res, 400, 'MAC Address si sahihi.');
    }

    db.get(
        `SELECT id, max_devices, status
         FROM tenants WHERE id = ?`,
        [tenantId],
        (tenantErr, tenant) => {
            if (tenantErr) {
                return sendError(res, 500, 'Imeshindikana kukagua akaunti.');
            }

            if (!tenant) {
                return sendError(res, 404, 'Biashara haijapatikana.');
            }

            if (tenant.status && tenant.status !== 'active') {
                return sendError(res, 403, 'Akaunti hii haijaruhusiwa.');
            }

            db.get(
                'SELECT COUNT(*) AS count FROM devices WHERE tenant_id = ?',
                [tenantId],
                (countErr, row) => {
                    if (countErr) {
                        return sendError(res, 500, 'Imeshindikana kukagua vifaa.');
                    }

                    const limit = Number(tenant.max_devices) || 2;

                    if (row.count >= limit) {
                        return sendError(
                            res,
                            400,
                            `Umefika kikomo cha vifaa ${limit}. Boresha plan.`
                        );
                    }

                    const finalVendor = vendor || type || 'mikrotik';
                    const finalModel = model || body.selectedModel || 'Generic';
                    const finalWan = wan_port || wanPort || body.mikrotikWanPort || 'ether1';
                    const finalHost = isMikrotik
                        ? (host || `WAN: ${finalWan}`)
                        : finalMac;

                    db.run(
                        `INSERT INTO devices
                        (tenant_id, name, host, mac_address, vendor, type,
                         model, wan_port, user, password, port, status, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Offline', NULL)`,
                        [
                            tenantId,
                            String(name).trim(),
                            finalHost,
                            finalMac,
                            finalVendor,
                            finalVendor,
                            finalModel,
                            finalWan,
                            user || 'admin',
                            '',
                            Number(port) || 8728
                        ],
                        function (insertErr) {
                            if (insertErr) {
                                console.error('Device insert failed:', insertErr.message);
                                return sendError(res, 500, 'Imeshindikana kusajili kifaa.');
                            }

                            return res.status(201).json({
                                success: true,
                                message: 'Kifaa kimesajiliwa.',
                                deviceId: this.lastID
                            });
                        }
                    );
                }
            );
        }
    );
});

// --------------------------------------------------
// DEVICES: LIST BY TENANT
// --------------------------------------------------

app.get('/api/devices/:tenant_id', authMiddleware, (req, res) => {
    const tenantId = req.params.tenant_id;

    if (
        req.tenant_id !== tenantId &&
        req.tenant_id !== 'tenant_super_admin'
    ) {
        return sendError(res, 403, 'Huna ruhusa ya kuona vifaa hivi.');
    }

    db.all(
        `SELECT id, tenant_id, name, host, mac_address, vendor, type,
                model, wan_port, user, port, status, last_seen, created_at
         FROM devices
         WHERE tenant_id = ?
         ORDER BY created_at DESC`,
        [tenantId],
        (err, rows) => {
            if (err) {
                return sendError(res, 500, 'Imeshindikana kupata vifaa.');
            }

            return res.json({ success: true, devices: rows });
        }
    );
});

// --------------------------------------------------
// DEVICES: DELETE
// --------------------------------------------------

app.delete('/api/devices/:id', authMiddleware, (req, res) => {
    db.get(
        'SELECT id, tenant_id FROM devices WHERE id = ?',
        [req.params.id],
        (err, device) => {
            if (err) {
                return sendError(res, 500, 'Imeshindikana kukagua kifaa.');
            }

            if (!device) {
                return sendError(res, 404, 'Kifaa hakijapatikana.');
            }

            if (
                device.tenant_id !== req.tenant_id &&
                req.tenant_id !== 'tenant_super_admin'
            ) {
                return sendError(res, 403, 'Huna ruhusa ya kufuta kifaa hiki.');
            }

            db.run(
                'DELETE FROM devices WHERE id = ?',
                [device.id],
                function (deleteErr) {
                    if (deleteErr) {
                        return sendError(res, 500, 'Kufuta kifaa kumeshindikana.');
                    }

                    return res.json({
                        success: true,
                        message: 'Kifaa kimefutwa.'
                    });
                }
            );
        }
    );
});

// --------------------------------------------------
// DEVICES: STATUS
// --------------------------------------------------

app.get('/api/devices/:id/status', authMiddleware, (req, res) => {
    db.get(
        'SELECT id, tenant_id, status, last_seen FROM devices WHERE id = ?',
        [req.params.id],
        (err, device) => {
            if (err) {
                return sendError(res, 500, 'Imeshindikana kupata hali ya kifaa.');
            }

            if (!device) {
                return sendError(res, 404, 'Kifaa hakijapatikana.');
            }

            if (
                device.tenant_id !== req.tenant_id &&
                req.tenant_id !== 'tenant_super_admin'
            ) {
                return sendError(res, 403, 'Huna ruhusa ya kuona kifaa hiki.');
            }

            const lastSeenTime = device.last_seen
                ? new Date(device.last_seen).getTime()
                : NaN;

            const ageMinutes = (Date.now() - lastSeenTime) / 60000;
            const online = Number.isFinite(ageMinutes) &&
                ageMinutes >= -1 &&
                ageMinutes < 10;

            return res.json({
                online,
                lastSeen: device.last_seen || null,
                status: online ? 'Online' : 'Offline'
            });
        }
    );
});

// --------------------------------------------------
// MIKROTIK: TEST ENDPOINT
// This is only an API test, not a real router connection.
// --------------------------------------------------

app.post('/api/mikroTik/test-connection', authMiddleware, (req, res) => {
    const { host } = req.body || {};

    if (!host) {
        return sendError(res, 400, 'Weka IP address au host ya router.');
    }

    return res.json({
        success: false,
        testMode: true,
        message: 'Endpoint imefikiwa, lakini uunganisho halisi wa MikroTik bado haujafanywa.',
        host
    });
});

// --------------------------------------------------
// MIKROTIK: REGISTER ROUTER
// Requires a shared secret configured in Render.
// Do not expose this secret in frontend code.
// --------------------------------------------------

app.post('/api/mikrotik/register-router', (req, res) => {
    const configuredKey = process.env.MIKROTIK_WEBHOOK_SECRET;
    const suppliedKey = req.get('x-mrhaas-router-key') || '';

    if (!configuredKey) {
        return sendError(
            res,
            503,
            'Usajili wa router haujasanidiwa kwenye server.'
        );
    }

    const expected = Buffer.from(configuredKey);
    const supplied = Buffer.from(suppliedKey);

    if (
        expected.length !== supplied.length ||
        !crypto.timingSafeEqual(expected, supplied)
    ) {
        return sendError(res, 401, 'Uthibitisho wa router si sahihi.');
    }

    const {
        tenant_id,
        name,
        model,
        identity,
        wan_port,
        mac_address
    } = req.body || {};

    if (!isValidId(tenant_id)) {
        return sendError(res, 400, 'tenant_id inahitajika.');
    }

    const routerName = String(name || identity || 'MikroTik-Router').trim();

    db.get(
        'SELECT id FROM tenants WHERE id = ?',
        [tenant_id],
        (tenantErr, tenant) => {
            if (tenantErr) {
                return sendError(res, 500, 'Imeshindikana kukagua biashara.');
            }

            if (!tenant) {
                return sendError(res, 404, 'Biashara haijapatikana.');
            }

            db.get(
                'SELECT id FROM devices WHERE tenant_id = ? AND name = ?',
                [tenant_id, routerName],
                (findErr, existing) => {
                    if (findErr) {
                        return sendError(res, 500, 'Imeshindikana kukagua router.');
                    }

                    if (existing) {
                        db.run(
                            `UPDATE devices
                             SET status = 'Online',
                                 last_seen = datetime('now'),
                                 model = COALESCE(?, model),
                                 wan_port = COALESCE(?, wan_port)
                             WHERE id = ? AND tenant_id = ?`,
                            [
                                model || null,
                                wan_port || null,
                                existing.id,
                                tenant_id
                            ],
                            (updateErr) => {
                                if (updateErr) {
                                    return sendError(res, 500, 'Kusasisha router kumeshindikana.');
                                }

                                return res.json({
                                    success: true,
                                    message: 'Router imesasishwa.'
                                });
                            }
                        );
                        return;
                    }

                    db.run(
                        `INSERT INTO devices
                        (tenant_id, name, host, mac_address, vendor, type,
                         model, wan_port, user, password, port, status, last_seen)
                        VALUES (?, ?, ?, ?, 'mikrotik', 'mikrotik', ?, ?, ?, '', 8728,
                                'Online', datetime('now'))`,
                        [
                            tenant_id,
                            routerName,
                            `WAN: ${wan_port || 'ether1'}`,
                            mac_address ? String(mac_address).toUpperCase() : null,
                            model || 'MikroTik',
                            wan_port || 'ether1',
                            'admin'
                        ],
                        function (insertErr) {
                            if (insertErr) {
                                return sendError(res, 500, 'Kusajili router kumeshindikana.');
                            }

                            return res.status(201).json({
                                success: true,
                                message: 'Router imesajiliwa.',
                                deviceId: this.lastID
                            });
                        }
                    );
                }
            );
        }
    );
});

// --------------------------------------------------
// CLIENTS: ADD
// --------------------------------------------------

app.post('/api/clients', authMiddleware, (req, res) => {
    const body = req.body || {};
    const tenantId = getTenantForRequest(req, body.tenant_id);

    const { name, phone, username, package_name } = body;

    if (!tenantId || !isValidId(name) || !isValidId(username)) {
        return sendError(res, 400, 'Jaza jina na username ya mteja.');
    }

    db.get(
        'SELECT id, max_clients, status FROM tenants WHERE id = ?',
        [tenantId],
        (tenantErr, tenant) => {
            if (tenantErr) {
                return sendError(res, 500, 'Imeshindikana kukagua biashara.');
            }

            if (!tenant) {
                return sendError(res, 404, 'Biashara haijapatikana.');
            }

            if (tenant.status && tenant.status !== 'active') {
                return sendError(res, 403, 'Akaunti hii haijaruhusiwa.');
            }

            db.get(
                'SELECT COUNT(*) AS count FROM clients WHERE tenant_id = ?',
                [tenantId],
                (countErr, row) => {
                    if (countErr) {
                        return sendError(res, 500, 'Imeshindikana kukagua wateja.');
                    }

                    const limit = Number(tenant.max_clients) || 50;

                    if (row.count >= limit) {
                        return sendError(
                            res,
                            400,
                            `Umefika kikomo cha wateja ${limit}. Boresha plan.`
                        );
                    }

                    db.run(
                        `INSERT INTO clients
                         (tenant_id, name, phone, username, package_name)
                         VALUES (?, ?, ?, ?, ?)`,
                        [
                            tenantId,
                            String(name).trim(),
                            phone ? String(phone).trim() : null,
                            String(username).trim(),
                            package_name ? String(package_name).trim() : null
                        ],
                        function (insertErr) {
                            if (insertErr) {
                                console.error('Client insert failed:', insertErr.message);
                                return sendError(res, 500, 'Kusajili mteja kumeshindikana.');
                            }

                            return res.status(201).json({
                                success: true,
                                message: 'Mteja amesajiliwa.',
                                clientId: this.lastID
                            });
                        }
                    );
                }
            );
        }
    );
});

// --------------------------------------------------
// CLIENTS: LIST
// --------------------------------------------------

app.get('/api/clients/:tenant_id', authMiddleware, (req, res) => {
    const tenantId = req.params.tenant_id;

    if (
        req.tenant_id !== tenantId &&
        req.tenant_id !== 'tenant_super_admin'
    ) {
        return sendError(res, 403, 'Huna ruhusa ya kuona wateja hawa.');
    }

    db.all(
        `SELECT id, tenant_id, name, phone, username,
                package_name, status, created_at
         FROM clients
         WHERE tenant_id = ?
         ORDER BY created_at DESC`,
        [tenantId],
        (err, rows) => {
            if (err) {
                return sendError(res, 500, 'Imeshindikana kupata wateja.');
            }

            return res.json({ success: true, clients: rows });
        }
    );
});

// --------------------------------------------------
// PAYMENTS
// IMPORTANT: These endpoints are disabled until each
// provider's official signature/status verification is implemented.
// Never trust a payment status or tenant_id from an unverified request.
// --------------------------------------------------

function paymentNotConfigured(req, res) {
    return res.status(501).json({
        success: false,
        message: 'Webhook ya malipo haijaunganishwa na uthibitishaji rasmi wa mtoa huduma.'
    });
}

app.post('/api/payments/azampay/webhook', paymentNotConfigured);
app.post('/api/payments/clickpesa/webhook', paymentNotConfigured);
app.post('/api/payments/selcom/webhook', paymentNotConfigured);
app.get('/api/payments/pesapal/webhook', paymentNotConfigured);
app.post('/api/payments/palmpesa/webhook', paymentNotConfigured);
app.post('/api/payments/beem/webhook', paymentNotConfigured);

// --------------------------------------------------
// SUPER ADMIN: LIST TENANTS
// Never return password hashes.
// --------------------------------------------------

app.get(
    '/api/super/tenants',
    authMiddleware,
    requireSuperAdmin,
    (req, res) => {
        db.all(
            `SELECT
                t.id,
                t.business_name,
                t.owner_name,
                t.phone,
                t.email,
                t.subdomain,
                t.plan,
                t.status,
                t.max_devices,
                t.max_clients,
                t.created_at,
                (SELECT COUNT(*) FROM devices d
                 WHERE d.tenant_id = t.id) AS devices_count,
                (SELECT COUNT(*) FROM clients c
                 WHERE c.tenant_id = t.id) AS clients_count
             FROM tenants t
             ORDER BY t.created_at DESC`,
            [],
            (err, rows) => {
                if (err) {
                    return sendError(res, 500, 'Imeshindikana kupata orodha ya WISP.');
                }

                return res.json({ success: true, tenants: rows });
            }
        );
    }
);

// --------------------------------------------------
// SUPER ADMIN: UPDATE PLAN / LIMITS / STATUS
// --------------------------------------------------

app.put(
    '/api/super/tenant/:id/plan',
    authMiddleware,
    requireSuperAdmin,
    (req, res) => {
        const { plan, max_devices, max_clients, status } = req.body || {};

        const sets = [];
        const params = [];

        if (plan !== undefined) {
            const allowedPlans = ['free', 'basic', 'standard', 'premium'];

            if (!allowedPlans.includes(plan)) {
                return sendError(res, 400, 'Plan si sahihi.');
            }

            sets.push('plan = ?');
            params.push(plan);
        }

        if (max_devices !== undefined) {
            const value = Number(max_devices);

            if (!Number.isInteger(value) || value < 1 || value > 100000) {
                return sendError(res, 400, 'max_devices si sahihi.');
            }

            sets.push('max_devices = ?');
            params.push(value);
        }

        if (max_clients !== undefined) {
            const value = Number(max_clients);

            if (!Number.isInteger(value) || value < 1 || value > 10000000) {
                return sendError(res, 400, 'max_clients si sahihi.');
            }

            sets.push('max_clients = ?');
            params.push(value);
        }

        if (status !== undefined) {
            const allowedStatuses = ['active', 'suspended', 'inactive'];

            if (!allowedStatuses.includes(status)) {
                return sendError(res, 400, 'Hali ya akaunti si sahihi.');
            }

            sets.push('status = ?');
            params.push(status);
        }

        if (sets.length === 0) {
            return sendError(res, 400, 'Hakuna taarifa za kubadilisha.');
        }

        params.push(req.params.id);

        db.run(
            `UPDATE tenants SET ${sets.join(', ')} WHERE id = ?`,
            params,
            function (err) {
                if (err) {
                    return sendError(res, 500, 'Kusasisha akaunti kumeshindikana.');
                }

                if (this.changes === 0) {
                    return sendError(res, 404, 'Akaunti haijapatikana.');
                }

                return res.json({
                    success: true,
                    message: 'Taarifa za akaunti zimesasishwa.'
                });
            }
        );
    }
);

// --------------------------------------------------
// FRONTEND
// --------------------------------------------------

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --------------------------------------------------
// UNKNOWN API ROUTES
// --------------------------------------------------

app.use('/api', (req, res) => {
    return sendError(res, 404, 'API route haijapatikana.');
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
    console.log(`MR HAAS NET API running on port ${PORT}`);
});
