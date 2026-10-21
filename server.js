'use strict';

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const db = require('./database');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

let SECRET_KEY = process.env.SECRET_KEY || '';
const SUPER_ADMIN_EMAIL = String(process.env.SUPER_ADMIN_EMAIL || 'admin@mrhaasnet.co.tz').trim().toLowerCase();
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || 'SuperAdminPassword123!';

if (!SECRET_KEY || SECRET_KEY.length < 32) {
  console.warn('⚠️ ONYO: SECRET_KEY haina herufi 32 au haijawekwa. Mfumo unatumia ufunguo wa dharura.');
  SECRET_KEY = crypto.randomBytes(48).toString('hex');
}

const JWT_SECRET = SECRET_KEY;
const SUPER_ADMIN_ID = 'tenant_super_admin';

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(value => value.trim().replace(/\/+$/, ''))
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || !IS_PRODUCTION) {
      return callback(null, true);
    }
    const normalizedOrigin = origin.trim().replace(/\/+$/, '');
    if (allowedOrigins.includes(normalizedOrigin)) {
      return callback(null, true);
    }
    console.error('[CORS BLOCKED] Origin iliyokataliwa:', origin);
    const error = new Error('Origin hii hairuhusiwi.');
    error.status = 403;
    return callback(error);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Mikrotik-Secret',
    'X-Tenant-ID'
  ],
  optionsSuccessStatus: 204
}));

app.get('/super-admin.html', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'super-admin.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

/* =========================================================
   SYSTEM PLANS DEFINITION
========================================================= */
const PLANS = {
  START: { name: 'START', monthly_price: 10000, max_devices: 2, max_clients: 50 },
  DIAMOND: { name: 'DIAMOND', monthly_price: 15000, max_devices: 7, max_clients: 500 },
  PREMIUM: { name: 'PREMIUM', monthly_price: 20000, max_devices: 999999, max_clients: 5000, device_limit: null, client_limit: 5000, billing_type: 'fixed' },
  REVENUE_SHARE: { name: 'REVENUE_SHARE', monthly_price: 20000, signup_fee: 20000, revenue_share_percent: 3, max_devices: 999999, max_clients: 999999, device_limit: null, client_limit: null, billing_type: 'revenue_share' }
};

const DEVICE_VENDORS = ['MikroTik','TP-Link Omada','Ruijie/Reyee','Cudy','Grandstream','Cambium','RADIUS'];
const DEVICE_TYPES = ['router','access_point','switch','radius_server','other'];
const PAYMENT_PROVIDERS = ['AzamPay','ClickPesa','Selcom','Pesapal','PalmPesa','Beem','manual'];

class HttpError extends Error { constructor(status, message){ super(message); this.status=status; } }
const fail = (status, message) => { throw new HttpError(status, message); };
const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
const query = async (sql, params = []) => { const result = await db.pool.query(sql, params); return result.rows || []; };
const one = async (sql, params = []) => { const rows = await query(sql, params); return rows[0] || null; };
const makeId = prefix => `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
const clean = value => typeof value === 'string' ? value.trim() : value;
const emailValue = value => String(value || '').trim().toLowerCase();
const isValidEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ''));
const isValidPhone = value => /^\+?[0-9\s()-]{9,20}$/.test(String(value || ''));
const signToken = (claims, expiresIn = '7d') => jwt.sign(claims, JWT_SECRET, { expiresIn });
const publicTenant = tenant => {
  if (!tenant) return null;
  return {
    id: tenant.id, business_name: tenant.business_name, owner_name: tenant.owner_name, phone: tenant.phone, email: tenant.email, subdomain: tenant.subdomain, plan: tenant.plan, max_devices: tenant.max_devices, max_clients: tenant.max_clients, status: tenant.status, role: tenant.role || 'tenant', trial_started_at: tenant.trial_started_at, trial_ends_at: tenant.trial_ends_at, subscription_status: tenant.subscription_status, subscription_ends_at: tenant.subscription_ends_at, free_forever: tenant.free_forever, created_at: tenant.created_at
  };
};

const authMiddleware = asyncRoute(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) fail(401, 'Ingia kwanza ili kuendelea.');
  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); } catch { fail(401, 'Token imeisha muda au si sahihi. Ingia tena.'); }
  if (!decoded.tenant_id || !decoded.email) fail(401, 'Token haina taarifa zinazohitajika.');
  req.user = decoded; req.tenant_id = decoded.tenant_id; req.email = decoded.email;
  if (decoded.role === 'super_admin' || decoded.tenant_id === SUPER_ADMIN_ID) { req.role = 'super_admin'; return next(); }
  const tenant = await one('SELECT * FROM tenants WHERE id = $1', [decoded.tenant_id]);
  if (!tenant) fail(401, 'Akaunti haijapatikana.');
  if (tenant.status !== 'active') fail(403, `Akaunti yako haipo active. Hali: ${tenant.status || 'unknown'}. Wasiliana na msimamizi.`);
  req.tenant = tenant; req.role = 'tenant'; next();
});
const requireSuperAdmin = (req, res, next) => { if (req.role !== 'super_admin') return res.status(403).json({ success: false, message: 'Super Admin pekee anaruhusiwa.' }); next(); };
const getTenantRecord = async tenantId => { const tenant = await one('SELECT * FROM tenants WHERE id = $1', [tenantId]); if (!tenant) fail(404, 'WISP haijapatikana.'); return tenant; };
const ensureTenantAccess = (req, tenantId) => { if (req.role === 'super_admin') return; if (req.tenant_id !== tenantId) fail(403, 'Huruhusiwi kufikia taarifa za WISP mwingine.'); };
const requireSubscription = asyncRoute(async (req, res, next) => {
  if (req.role === 'super_admin') return next();
  const tenant = req.tenant; if (!tenant) fail(401, 'Taarifa za Tenant hazijapatikana. Ingia tena.');
  if (tenant.free_forever === true || tenant.free_forever === 'true') return next();
  const now = Date.now(); const trialEnd = tenant.trial_ends_at ? new Date(tenant.trial_ends_at).getTime() : 0; const paidEnd = tenant.subscription_ends_at ? new Date(tenant.subscription_ends_at).getTime() : 0;
  const trialValid = tenant.subscription_status === 'trial' && trialEnd > now; const paidValid = tenant.subscription_status === 'active' && paidEnd > now;
  if (!trialValid && !paidValid) return res.status(402).json({ success: false, code: 'SUBSCRIPTION_REQUIRED', message: 'Muda wa majaribio umeisha au usajili haujalipiwa. Tafadhali chagua mpango na ukamilishe malipo.', plans: PLANS });
  return next();
});
const checkPlanLimit = async (tenant, field, table) => {
  const limit = tenant[field]; if (limit === null || limit === undefined || Number(limit) < 0) return;
  const row = await one(`SELECT COUNT(*)::int AS total FROM ${table} WHERE tenant_id = $1`, [tenant.id]);
  if (Number(row?.total || 0) >= Number(limit)) fail(403, `Umefikia kikomo cha ${table}. Boresha mpango wako.`);
};
const checkTenantLimit = async (tenant, kind) => { if (kind === 'devices') return checkPlanLimit(tenant, 'max_devices', 'devices'); if (kind === 'clients') return checkPlanLimit(tenant, 'max_clients', 'clients'); };
const createTrialDates = () => { const started = new Date(); const ends = new Date(started.getTime() + 4 * 24 * 60 * 60 * 1000); return { started, ends }; };
const getPlan = value => { const key = String(value || '').trim().toUpperCase().replace(/\s+/g, '_'); return PLANS[key] || null; };
const makeSubdomain = businessName => {
  const base = String(businessName || 'wisp').toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 35) || 'wisp';
  return `${base}-${crypto.randomBytes(3).toString('hex')}`;
};
const issueTenantToken = tenant => signToken({ tenant_id: tenant.id, email: tenant.email, role: 'tenant' });
const issueSuperAdminToken = () => signToken({ tenant_id: SUPER_ADMIN_ID, email: SUPER_ADMIN_EMAIL, role: 'super_admin' });

/* HEALTH & PLANS */
app.get('/api/health', asyncRoute(async (req, res) => {
  await db.ready; await query('SELECT 1');
  res.json({ success: true, service: 'MR HAAS MULTI-TENANT WISP MANAGEMENT', database: 'connected', timestamp: new Date().toISOString() });
}));
app.get('/api/plans', (req, res) => { res.json({ success: true, plans: PLANS, trial_days: 4 }); });

/* AUTH */
app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const businessName = clean(req.body.business_name); const ownerName = clean(req.body.owner_name); const phone = clean(req.body.phone); const email = emailValue(req.body.email); const password = String(req.body.password || '');
  if (!businessName || !ownerName || !phone || !email || !password) fail(400, 'Jaza jina la biashara, jina la mmiliki, simu, barua pepe na nenosiri.');
  if (!isValidEmail(email)) fail(400, 'Barua pepe si sahihi.'); if (!isValidPhone(phone)) fail(400, 'Namba ya simu si sahihi.'); if (password.length < 8) fail(400, 'Nenosiri lazima liwe na angalau herufi 8.');
  const existing = await one('SELECT id FROM tenants WHERE LOWER(email) = $1 OR phone = $2 LIMIT 1', [email, phone]); if (existing) fail(409, 'Barua pepe au simu tayari imesajiliwa.');
  const id = makeId('tenant'); const subdomain = makeSubdomain(businessName); const passwordHash = await bcrypt.hash(password, 12); const trial = createTrialDates(); const plan = PLANS.START;
  const tenant = await one(`INSERT INTO tenants (id, business_name, owner_name, phone, email, password_hash, subdomain, plan, max_devices, max_clients, status, role, trial_started_at, trial_ends_at, subscription_status, subscription_ends_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'START',$8,$9,'active','tenant',$10,$11,'trial',NULL,NOW()) RETURNING *`, [id, businessName, ownerName, phone, email, passwordHash, subdomain, plan.max_devices, plan.max_clients, trial.started, trial.ends]);
  await query(`INSERT INTO tenant_settings (tenant_id, portal_title, primary_color, announcement, contact_phone, currency) VALUES ($1,$2,$3,$4,$5,'TZS') ON CONFLICT (tenant_id) DO NOTHING`, [id, businessName, '#111827', '', phone]);
  const token = issueTenantToken(tenant);
  res.status(201).json({ success: true, message: 'Akaunti imeundwa. Jaribio lako la siku 4 limeanza.', token, tenant: publicTenant(tenant), trial_days: 4, plans: PLANS });
}));
app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = emailValue(req.body.email); const password = String(req.body.password || '');
  if (!email || !password) fail(400, 'Weka barua pepe na nenosiri.');
  if (SUPER_ADMIN_EMAIL && email === SUPER_ADMIN_EMAIL && password === SUPER_ADMIN_PASSWORD) {
    return res.json({ success: true, token: issueSuperAdminToken(), role: 'super_admin', tenant: { id: SUPER_ADMIN_ID, email: SUPER_ADMIN_EMAIL, role: 'super_admin', business_name: 'MR HAAS SUPER ADMIN' } });
  }
  const tenant = await one('SELECT * FROM tenants WHERE LOWER(email) = $1 LIMIT 1', [email]); if (!tenant) fail(401, 'Barua pepe au nenosiri si sahihi.');
  const valid = await bcrypt.compare(password, tenant.password_hash); if (!valid) fail(401, 'Barua pepe au nenosiri si sahihi.');
  if (tenant.status !== 'active') fail(403, `Akaunti yako imewekewa hali ya ${tenant.status}. Wasiliana na Super Admin.`);
  res.json({ success: true, token: issueTenantToken(tenant), role: 'tenant', tenant: publicTenant(tenant), plans: PLANS });
}));
app.post('/api/super-admin/login', asyncRoute(async (req, res) => {
  const email = emailValue(req.body.email); const password = String(req.body.password || '');
  if (email !== SUPER_ADMIN_EMAIL || password !== SUPER_ADMIN_PASSWORD) fail(401, 'Taarifa za Super Admin si sahihi.');
  res.json({ success: true, token: issueSuperAdminToken(), role: 'super_admin', tenant: { id: SUPER_ADMIN_ID, email: SUPER_ADMIN_EMAIL, role: 'super_admin', business_name: 'MR HAAS SUPER ADMIN' } });
}));
app.get('/api/auth/me', authMiddleware, asyncRoute(async (req, res) => {
  if (req.role === 'super_admin') return res.json({ success: true, role: 'super_admin', tenant: { id: SUPER_ADMIN_ID, email: req.email, business_name: 'MR HAAS SUPER ADMIN' } });
  const tenant = await getTenantRecord(req.tenant_id);
  res.json({ success: true, role: 'tenant', tenant: publicTenant(tenant), plans: PLANS });
}));

/* SUPER ADMIN TENANTS */
app.get('/api/super/tenants', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenants = await query(`SELECT t.id, t.business_name, t.owner_name, t.phone, t.email, t.subdomain, t.plan, t.max_devices, t.max_clients, t.status, t.role, t.trial_started_at, t.trial_ends_at, t.subscription_status, t.subscription_ends_at, t.free_forever, t.created_at, (SELECT COUNT(*)::int FROM devices d WHERE d.tenant_id = t.id) AS device_count, (SELECT COUNT(*)::int FROM clients c WHERE c.tenant_id = t.id) AS client_count, (SELECT COUNT(*)::int FROM sites s WHERE s.tenant_id = t.id) AS site_count FROM tenants t WHERE t.id <> $1 ORDER BY t.created_at DESC`, [SUPER_ADMIN_ID]);
  res.json({ success: true, tenants, total: tenants.length });
}));
app.post('/api/super/tenants', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const businessName = clean(req.body.business_name); const ownerName = clean(req.body.owner_name || businessName); const phone = clean(req.body.phone || '0000000000'); const email = emailValue(req.body.email); const password = String(req.body.password || 'Password123!'); const planKey = String(req.body.plan || 'START').toUpperCase(); const plan = getPlan(planKey) || PLANS.START;
  if (!businessName || !email) fail(400, 'Jaza jina la biashara na barua pepe.'); if (!isValidEmail(email)) fail(400, 'Barua pepe si sahihi.');
  const existing = await one('SELECT id FROM tenants WHERE LOWER(email) = $1 LIMIT 1', [email]); if (existing) fail(409, 'Barua pepe tayari imesajiliwa.');
  const trial = createTrialDates(); const id = makeId('tenant'); const hash = await bcrypt.hash(password, 12); const subdomain = makeSubdomain(businessName);
  const tenant = await one(`INSERT INTO tenants (id, business_name, owner_name, phone, email, password_hash, subdomain, plan, max_devices, max_clients, status, role, trial_started_at, trial_ends_at, subscription_status, subscription_ends_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active','tenant',$11,$12,'trial',NULL,NOW()) RETURNING *`, [id, businessName, ownerName, phone, email, hash, subdomain, plan.name, plan.max_devices, plan.max_clients, trial.started, trial.ends]);
  await query(`INSERT INTO tenant_settings (tenant_id, portal_title, primary_color, announcement, contact_phone, currency) VALUES ($1,$2,$3,$4,$5,'TZS') ON CONFLICT (tenant_id) DO NOTHING`, [id, businessName, '#111827', '', phone]);
  res.status(201).json({ success: true, message: 'WISP imesajiliwa na jaribio la siku 4 limeanza.', tenant: publicTenant(tenant), trial_days: 4 });
}));
app.put('/api/super/tenant/:id/subscription', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenantId = String(req.params.id || '').trim(); const rawPlanInput = String(req.body.plan || 'START').trim().toUpperCase().replace(/\s+/g, '_'); const plan = PLANS[rawPlanInput] || getPlan(rawPlanInput); let status = String(req.body.subscription_status || 'active').toLowerCase();
  if (!tenantId) fail(400, 'ID ya Tenant inahitajika.'); if (tenantId === SUPER_ADMIN_ID) fail(403, 'Huwezi kubadilisha mpango wa Super Admin.'); if (!plan) fail(400, 'Mpango (Plan) si sahihi.');
  const current = await one('SELECT * FROM tenants WHERE id = $1 AND id <> $2', [tenantId, SUPER_ADMIN_ID]); if (!current) fail(404, 'WISP haijapatikana.');
  const freeForever = req.body.free_forever === true || req.body.free_forever === 'true';
  let trialStarted = current.trial_started_at; let trialEnds = current.trial_ends_at;
  if (req.body.trial_days !== undefined && req.body.trial_days !== '') { const days = Number(req.body.trial_days); if (!Number.isNaN(days) && days >= 0) { const now = new Date(); trialStarted = trialStarted || now; trialEnds = new Date(now.getTime() + days * 86400000); status = 'trial'; } }
  const endsAt = req.body.subscription_ends_at ? new Date(req.body.subscription_ends_at) : null;
  const tenant = await one(`UPDATE tenants SET plan = $1, max_devices = $2, max_clients = $3, subscription_status = $4, subscription_ends_at = $5, trial_started_at = $6, trial_ends_at = $7, free_forever = $8, updated_at = NOW() WHERE id = $9 AND id <> $10 RETURNING *`, [plan.name, plan.max_devices, plan.max_clients, status, endsAt, trialStarted, trialEnds, freeForever, tenantId, SUPER_ADMIN_ID]);
  res.json({ success: true, message: freeForever ? `Free Forever imewashwa na mpango umebadilishwa kuwa ${plan.name}.` : `Plan imesasishwa na kuwa ${plan.name} kikamilifu!`, tenant: publicTenant(tenant) });
}));
app.patch('/api/super/tenant/:id/status', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenantId = String(req.params.id || '').trim(); const status = String(req.body.status || '').trim().toLowerCase();
  if (!tenantId || tenantId === SUPER_ADMIN_ID) fail(400, 'ID ya Tenant haijakubaliwa.');
  const tenant = await one(`UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, business_name, status`, [status, tenantId]);
  if (!tenant) fail(404, 'WISP haijapatikana.');
  res.json({ success: true, message: status === 'suspended' ? 'Akaunti ya Tenant imesimamishwa.' : 'Akaunti ya Tenant imerejeshwa.', tenant });
}));
app.delete('/api/super/tenant/:id', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenantId = String(req.params.id || '').trim(); if (!tenantId || tenantId === SUPER_ADMIN_ID) fail(400, 'ID ya Tenant haijakubaliwa.');
  const tenant = await one(`UPDATE tenants SET status = 'deleted', updated_at = NOW() WHERE id = $1 RETURNING id, business_name`, [tenantId]);
  res.json({ success: true, message: 'Akaunti imezimwa na kuhifadhiwa kama deleted.', tenant });
}));

/* SUBSCRIPTION & SETTINGS */
app.get('/api/subscription', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.query.tenant_id : req.tenant_id; if (!tenantId) fail(400, 'tenant_id inahitajika.'); ensureTenantAccess(req, tenantId);
  const tenant = await getTenantRecord(tenantId); const trialEnd = tenant.trial_ends_at ? new Date(tenant.trial_ends_at) : null; const paidEnd = tenant.subscription_ends_at ? new Date(tenant.subscription_ends_at) : null; const now = new Date();
  const freeForever = tenant.free_forever === true; const trialActive = tenant.subscription_status === 'trial' && trialEnd && trialEnd > now; const paidActive = tenant.subscription_status === 'active' && paidEnd && paidEnd > now;
  res.json({ success: true, subscription: { plan: tenant.plan, status: tenant.subscription_status, trial_started_at: tenant.trial_started_at, trial_ends_at: tenant.trial_ends_at, subscription_ends_at: tenant.subscription_ends_at, free_forever: freeForever, trial_active: Boolean(trialActive), paid_active: Boolean(paidActive), service_access: Boolean(freeForever || trialActive || paidActive), plans: PLANS } });
}));
app.get('/api/payment-settings', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.query.tenant_id : req.tenant_id; if (!tenantId) fail(400, 'tenant_id inahitajika.'); ensureTenantAccess(req, tenantId);
  const settings = await one(`SELECT tenant_id, enabled_providers, manual_payment_instructions, payment_phone, payment_account_name, updated_at FROM payment_settings WHERE tenant_id = $1`, [tenantId]);
  res.json({ success: true, settings: settings || { tenant_id: tenantId, enabled_providers: ['manual'], manual_payment_instructions: '', payment_phone: '', payment_account_name: '' }, available_providers: PAYMENT_PROVIDERS });
}));
app.put('/api/payment-settings', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id; if (!tenantId) fail(400, 'tenant_id inahitajika.'); ensureTenantAccess(req, tenantId);
  const providers = Array.isArray(req.body.enabled_providers) ? req.body.enabled_providers.filter(item => PAYMENT_PROVIDERS.includes(item)) : ['manual'];
  const instructions = String(req.body.manual_payment_instructions || '').slice(0, 3000); const phone = String(req.body.payment_phone || '').slice(0, 40); const accountName = String(req.body.payment_account_name || '').slice(0, 120);
  const settings = await one(`INSERT INTO payment_settings (tenant_id, enabled_providers, manual_payment_instructions, payment_phone, payment_account_name, updated_at) VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT (tenant_id) DO UPDATE SET enabled_providers = EXCLUDED.enabled_providers, manual_payment_instructions = EXCLUDED.manual_payment_instructions, payment_phone = EXCLUDED.payment_phone, payment_account_name = EXCLUDED.payment_account_name, updated_at = NOW() RETURNING tenant_id, enabled_providers, manual_payment_instructions, payment_phone, payment_account_name, updated_at`, [tenantId, providers, instructions, phone, accountName]);
  res.json({ success: true, settings });
}));

/* SITES */
app.get('/api/sites/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const sites = await query(`SELECT id, tenant_id, name, location, description, status, created_at FROM sites WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  res.json({ success: true, sites });
}));
app.post('/api/sites', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id; ensureTenantAccess(req, tenantId); if (!tenantId || !req.body.name) fail(400, 'tenant_id na jina la site vinahitajika.');
  const site = await one(`INSERT INTO sites (id, tenant_id, name, location, description, status, created_at) VALUES ($1,$2,$3,$4,$5,'active',NOW()) RETURNING *`, [makeId('site'), tenantId, clean(req.body.name), clean(req.body.location || ''), clean(req.body.description || '')]);
  res.status(201).json({ success: true, site });
}));
app.delete('/api/sites/:id', authMiddleware, asyncRoute(async (req, res) => {
  const site = await one('SELECT * FROM sites WHERE id = $1', [req.params.id]); if (!site) fail(404, 'Site haijapatikana.'); ensureTenantAccess(req, site.tenant_id);
  await query('DELETE FROM sites WHERE id = $1', [site.id]); res.json({ success: true, message: 'Site imefutwa.' });
}));

/* =========================================================
   DEVICES - MR HAAS NET LINK MIKROTIK WIZARD
========================================================= */
app.get('/api/devices/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const devices = await query(`SELECT id, tenant_id, site_id, name, vendor, device_type, model, mac_address, ip_address, wan_port, connection_type, last_seen, status, created_at FROM devices WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  res.json({ success: true, devices });
}));

app.post('/api/devices', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');

  const tenant = await getTenantRecord(tenantId);
  await checkTenantLimit(tenant, 'devices');

  // MR HAAS WIZARD FIELDS
  const locationName = clean(req.body.location_name || req.body.name || '');
  const ssid = clean(req.body.ssid || '');
  const port = clean(req.body.port || req.body.wan_port || 'Port 1');
  const model = clean(req.body.model || req.body.vendor || 'MikroTik');
  const vendor = 'MikroTik';

  const name = locationName ? `${locationName} - ${ssid || vendor}` : clean(req.body.name || `${model} ${port}`);
  const deviceType = 'router';
  const mac = clean(req.body.mac_address || '');
  const ip = clean(req.body.ip_address || port);
  const siteId = clean(req.body.site_id || '') || null;
  const wanPort = port;
  const connectionType = 'api';

  if (!name) fail(400, 'Jina la kifaa linahitajika.');

  // Try to insert with extended columns, fallback to basic
  let device;
  try {
    device = await one(
      `INSERT INTO devices
        (id, tenant_id, site_id, name, vendor, device_type, model, mac_address, ip_address, wan_port, connection_type, status, last_seen, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'offline',NOW(),NOW())
       RETURNING id, tenant_id, site_id, name, vendor, device_type, model, mac_address, ip_address, wan_port, connection_type, status, last_seen, created_at`,
      [makeId('device'), tenantId, siteId, name, vendor, deviceType, model, mac || null, ip || null, wanPort, connectionType]
    );
  } catch (e) {
    // Fallback if status column doesn't exist
    device = await one(
      `INSERT INTO devices
        (id, tenant_id, site_id, name, vendor, device_type, model, mac_address, ip_address, wan_port, connection_type, last_seen, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NOW())
       RETURNING id, tenant_id, site_id, name, vendor, device_type, model, mac_address, ip_address, wan_port, connection_type, last_seen, created_at`,
      [makeId('device'), tenantId, siteId, name, vendor, deviceType, model, mac || null, ip || null, wanPort, connectionType]
    );
  }

  res.status(201).json({ success: true, message: 'Kifaa kimehifadhiwa na MR HAAS NET inasubiri check-in.', device });
}));

app.delete('/api/devices/:id', authMiddleware, asyncRoute(async (req, res) => {
  const device = await one('SELECT * FROM devices WHERE id = $1', [req.params.id]);
  if (!device) fail(404, 'Kifaa hakijapatikana.'); ensureTenantAccess(req, device.tenant_id);
  await query('DELETE FROM devices WHERE id = $1', [device.id]);
  res.json({ success: true, message: 'Kifaa kimeondolewa.' });
}));

/* =========================================================
   MR HAAS NET - MIKROTIK LIVE CHECKIN & REGISTER
   Router inaita hizi endpoints moja kwa moja
========================================================= */

// 1. Register - Router inapodownload mrhaas.rsc
app.get('/api/mikrotik/register', asyncRoute(async (req, res) => {
  const tenantId = clean(req.query.tenant || req.query.tenant_id || '');
  const site = clean(req.query.site || '');
  const ssid = clean(req.query.ssid || '');
  const model = clean(req.query.model || '');
  const port = clean(req.query.port || '');

  if (tenantId) {
    try {
      await query(`UPDATE devices SET last_seen = NOW(), status = 'online', ip_address = COALESCE($2, ip_address) WHERE tenant_id = $1 AND name ILIKE $3`, [tenantId, port, `%${site}%`]);
    } catch (e) { console.log('register update failed', e.message); }
  }

  // Return RouterOS script that the device will import
  const rsc = `# MR HAAS NET - Provisioning payload for ${site}
# SSID: ${ssid} | Model: ${model} | Port: ${port} | Tenant: ${tenantId}
/ip hotspot profile set [find] login-by=http-chap,http-pap
/ip hotspot set [find] idle-timeout=1h keepalive-timeout=2m
/system clock set time-zone-name=Africa/Dar_es_Salaam
/system scheduler add name=mrhaas-checkin interval=2m on-event="/tool fetch url=https://mrhaas-backend.onrender.com/api/mikrotik/checkin?tenant=${encodeURIComponent(tenantId)}&site=${encodeURIComponent(site)}&model=${encodeURIComponent(model)} mode=https check-certificate=no" disabled=no
:put "MR HAAS NET: ${site} imeunganishwa!"
`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(rsc);
}));

// 2. Checkin - Router inapiga kila dakika 2 kuonyesha iko online
app.get('/api/mikrotik/checkin', asyncRoute(async (req, res) => {
  const tenantId = clean(req.query.tenant || req.query.tenant_id || '');
  const site = clean(req.query.site || '');
  const deviceId = clean(req.query.id || req.query.device_id || '');

  if (tenantId) {
    try {
      if (site) {
        await query(`UPDATE devices SET last_seen = NOW(), status = 'online' WHERE tenant_id = $1 AND (name ILIKE $2 OR id = $3)`, [tenantId, `%${site}%`, deviceId || site]);
      } else {
        await query(`UPDATE devices SET last_seen = NOW(), status = 'online' WHERE tenant_id = $1`, [tenantId]);
      }
      console.log(`[MR HAAS CHECKIN] Tenant ${tenantId} Site ${site} online`);
    } catch (e) { console.error('checkin update failed', e.message); }
  }

  res.setHeader('Content-Type', 'text/plain');
  res.send('OK - MR HAAS NET checkin received');
}));

// 3. Status endpoint for tenant frontend polling
app.get('/api/mikrotik/status/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const devices = await query(`SELECT id, name, vendor, model, ip_address, wan_port, status, last_seen FROM devices WHERE tenant_id = $1 ORDER BY last_seen DESC NULLS LAST`, [tenantId]);
  const online = devices.filter(d => d.status === 'online' || (d.last_seen && (Date.now() - new Date(d.last_seen).getTime()) < 5*60*1000)).length;
  res.json({ success: true, devices, online_count: online, total: devices.length });
}));

/* CLIENTS */
app.get('/api/clients/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const clients = await query(`SELECT id, tenant_id, site_id, name, phone, username, package_name, connection_type, status, created_at FROM clients WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  res.json({ success: true, clients });
}));
app.post('/api/clients', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id; ensureTenantAccess(req, tenantId); if (!tenantId) fail(400, 'tenant_id inahitajika.');
  const tenant = await getTenantRecord(tenantId); await checkTenantLimit(tenant, 'clients');
  const name = clean(req.body.name); const phone = clean(req.body.phone || ''); const username = clean(req.body.username || ''); const packageName = clean(req.body.package_name || ''); const siteId = clean(req.body.site_id || '') || null; const connectionType = clean(req.body.connection_type || 'hotspot');
  if (!name) fail(400, 'Jina la mteja linahitajika.');
  const client = await one(`INSERT INTO clients (id, tenant_id, site_id, name, phone, username, package_name, connection_type, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',NOW()) RETURNING id, tenant_id, site_id, name, phone, username, package_name, connection_type, status, created_at`, [makeId('client'), tenantId, siteId, name, phone || null, username || null, packageName || null, connectionType]);
  res.status(201).json({ success: true, client });
}));
app.delete('/api/clients/:id', authMiddleware, asyncRoute(async (req, res) => {
  const client = await one('SELECT * FROM clients WHERE id = $1', [req.params.id]); if (!client) fail(404, 'Mteja hajapatikana.'); ensureTenantAccess(req, client.tenant_id);
  await query('DELETE FROM clients WHERE id = $1', [client.id]); res.json({ success: true, message: 'Mteja ameondolewa.' });
}));

/* PACKAGES */
app.get('/api/packages/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const packages = await query(`SELECT id, tenant_id, name, price, duration_value, duration_unit, speed_down, speed_up, connection_type, description, status, created_at FROM packages WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  res.json({ success: true, packages });
}));
app.post('/api/packages', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id; ensureTenantAccess(req, tenantId); if (!tenantId) fail(400, 'tenant_id inahitajika.');
  const name = clean(req.body.name); const price = Number(req.body.price); if (!name || Number.isNaN(price) || price < 0) fail(400, 'Jina au bei si sahihi.');
  const pack = await one(`INSERT INTO packages (id, tenant_id, name, price, duration_value, duration_unit, speed_down, speed_up, connection_type, description, status, created_at) VALUES ($1,$2,$3,$4,1,'days',0,0,'hotspot',$5,'active',NOW()) RETURNING *`, [makeId('pkg'), tenantId, name, price, clean(req.body.description || '')]);
  res.status(201).json({ success: true, package: pack });
}));
app.delete('/api/packages/:id', authMiddleware, asyncRoute(async (req, res) => {
  const pack = await one('SELECT * FROM packages WHERE id = $1', [req.params.id]); if (!pack) fail(404, 'Kifurushi hakijapatikana.'); ensureTenantAccess(req, pack.tenant_id);
  await query('DELETE FROM packages WHERE id = $1', [pack.id]); res.json({ success: true, message: 'Kifurushi kimefutwa.' });
}));

/* VOUCHERS & PORTAL */
app.get('/api/vouchers/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const vouchers = await query(`SELECT id, tenant_id, package_id, code, status, expires_at, used_at, created_at FROM vouchers WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  res.json({ success: true, vouchers });
}));
app.post('/api/vouchers', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id; ensureTenantAccess(req, tenantId);
  const count = Math.min(Math.max(Number(req.body.quantity || req.body.count || 1), 1), 500); const packageId = clean(req.body.package_id || '') || null;
  const vouchers = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    const voucher = await one(`INSERT INTO vouchers (id, tenant_id, package_id, code, status, created_at) VALUES ($1,$2,$3,$4,'unused',NOW()) RETURNING *`, [makeId('voucher'), tenantId, packageId, code]);
    vouchers.push(voucher);
  }
  res.status(201).json({ success: true, vouchers });
}));
app.post('/api/portal/settings/:tenant_id', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const title = String(req.body.portal_title || req.body.name || '').slice(0, 120); const color = String(req.body.primary_color || '#111827'); const announcement = String(req.body.announcement || '').slice(0, 3000); const contactPhone = String(req.body.contact_phone || req.body.contact || '').slice(0, 40);
  const settings = await one(`INSERT INTO tenant_settings (tenant_id, portal_title, primary_color, announcement, contact_phone, currency) VALUES ($1,$2,$3,$4,$5,'TZS') ON CONFLICT (tenant_id) DO UPDATE SET portal_title = EXCLUDED.portal_title, primary_color = EXCLUDED.primary_color, announcement = EXCLUDED.announcement, contact_phone = EXCLUDED.contact_phone RETURNING *`, [tenantId, title, color, announcement, contactPhone]);
  res.json({ success: true, settings });
}));
app.get('/api/portal/settings/:tenant_id', asyncRoute(async (req, res) => {
  const tenantId = clean(req.params.tenant_id); const tenant = await getTenantRecord(tenantId);
  const settings = await one(`SELECT tenant_id, portal_title, primary_color, announcement, contact_phone, currency FROM tenant_settings WHERE tenant_id = $1`, [tenantId]);
  res.json({ success: true, portal: settings || { tenant_id: tenantId, portal_title: tenant.business_name, primary_color: '#111827', announcement: '', contact_phone: tenant.phone, currency: 'TZS' } });
}));

/* PAYMENTS */
app.get('/api/payments/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id; ensureTenantAccess(req, tenantId);
  const payments = await query(`SELECT id, tenant_id, client_id, provider, reference, amount, currency, status, description, created_at FROM payments WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  res.json({ success: true, payments });
}));
app.post('/api/payments/manual', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id; ensureTenantAccess(req, tenantId);
  const amount = Number(req.body.amount); if (!Number.isFinite(amount) || amount <= 0) fail(400, 'Kiasi cha malipo si sahihi.');
  const payment = await one(`INSERT INTO payments (id, tenant_id, provider, reference, amount, currency, status, description, created_at) VALUES ($1,$2,'manual',$3,$4,'TZS','pending',$5,NOW()) RETURNING *`, [makeId('payment'), tenantId, clean(req.body.reference || ''), amount, clean(req.body.customer_name || '')]);
  res.status(201).json({ success: true, payment });
}));

/* SYSTEM UPDATES */
app.get('/api/super/updates', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const updates = await query(`SELECT * FROM system_updates ORDER BY created_at DESC`); res.json({ success: true, updates });
}));
app.post('/api/super/updates', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const version = String(req.body.version || '').trim(); const title = String(req.body.title || '').trim(); if (!version || !title) fail(400, 'Version na jina vinahitajika.');
  const update = await one(`INSERT INTO system_updates (id, version, title, description, release_notes, status, created_at) VALUES ($1,$2,$3,$4,$5,'draft',NOW()) RETURNING *`, [makeId('update'), version, title, clean(req.body.description || ''), clean(req.body.release_notes || '')]);
  res.status(201).json({ success: true, update });
}));
app.patch('/api/super/updates/:id/status', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const status = String(req.body.status || '').trim().toLowerCase();
  const update = await one(`UPDATE system_updates SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *`, [status, req.params.id]);
  res.json({ success: true, update });
}));

/* SERVER */
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.get('/api/*', (req, res) => { res.status(404).json({ success: false, message: 'API endpoint haijapatikana.' }); });
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status || 500; if (status >= 500) console.error('[SERVER ERROR]', err.message);
  res.status(status).json({ success: false, message: err.message || 'Hitilafu ya ndani ya server.' });
});

async function startServer() {
  try {
    await db.ready;
    if (!db.pool || typeof db.pool.query !== 'function') throw new Error('database.js lazima itoe pool.query na ready.');
    await db.pool.query('SELECT 1');
    // MR HAAS: Ensure status column exists for devices (for online/offline)
    try { await db.pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'offline'`); } catch(e){}
    try { await db.pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ`); } catch(e){}
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 MR HAAS WISP backend inaendesha kwenye port ${PORT}`);
      console.log(`Environment: ${IS_PRODUCTION ? 'production' : 'development'}`);
      console.log(`MR HAAS MIKROTIK endpoints: /api/mikrotik/register , /api/mikrotik/checkin , /api/mikrotik/status/:tenant_id`);
    });
  } catch (error) { console.error('Server haikuweza kuanza:', error.message); process.exit(1); }
}
startServer();
module.exports = app;
