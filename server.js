
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

const SECRET_KEY = process.env.SECRET_KEY;
const SUPER_ADMIN_EMAIL = String(process.env.SUPER_ADMIN_EMAIL || '').trim().toLowerCase();
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || '';

if (IS_PRODUCTION && (!SECRET_KEY || SECRET_KEY.length < 32)) {
  throw new Error('SECRET_KEY lazima iwe na angalau herufi 32 kwenye production.');
}

if (IS_PRODUCTION && (!SUPER_ADMIN_EMAIL || SUPER_ADMIN_PASSWORD.length < 12)) {
  throw new Error('Weka SUPER_ADMIN_EMAIL na SUPER_ADMIN_PASSWORD yenye angalau herufi 12.');
}

const JWT_SECRET = SECRET_KEY || crypto.randomBytes(48).toString('hex');
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
    // Ruhusu maombi yasiyotoka kwenye browser, kama maombi ya server.
    if (!origin) {
      return callback(null, true);
    }

    // Development pekee: ruhusu origins zote.
    if (!IS_PRODUCTION) {
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
    'X-Mikrotik-Secret'
  ],
  optionsSuccessStatus: 204
}));

app.get('/super-admin.html', (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.sendFile(path.join(__dirname, 'public', 'super-admin.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

const PLANS = {
  START: {
    name: 'START',
    monthly_price: 10000,
    max_devices: 2,
    max_clients: 50,
    device_limit: 2,
    client_limit: 50,
    billing_type: 'fixed'
  },
  DIAMOND: {
    name: 'DIAMOND',
    monthly_price: 15000,
    max_devices: 7,
    max_clients: 500,
    device_limit: 7,
    client_limit: 500,
    billing_type: 'fixed'
  },
  PREMIUM: {
    name: 'PREMIUM',
    monthly_price: 20000,
    max_devices: null,
    max_clients: 5000,
    device_limit: null,
    client_limit: 5000,
    billing_type: 'fixed'
  },
  REVENUE_SHARE: {
    name: 'REVENUE_SHARE',
    monthly_price: 20000,
    signup_fee: 20000,
    revenue_share_percent: 3,
    max_devices: null,
    max_clients: null,
    device_limit: null,
    client_limit: null,
    billing_type: 'revenue_share'
  }
};

const DEVICE_VENDORS = [
  'MikroTik',
  'TP-Link Omada',
  'Ruijie/Reyee',
  'Cudy',
  'Grandstream',
  'Cambium',
  'RADIUS'
];

const DEVICE_TYPES = [
  'router',
  'access_point',
  'switch',
  'radius_server',
  'other'
];

const PAYMENT_PROVIDERS = [
  'AzamPay',
  'ClickPesa',
  'Selcom',
  'Pesapal',
  'PalmPesa',
  'Beem',
  'manual'
];

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const fail = (status, message) => {
  throw new HttpError(status, message);
};

const asyncRoute = handler => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

const query = async (sql, params = []) => {
  const result = await db.pool.query(sql, params);
  return result.rows || [];
};

const one = async (sql, params = []) => {
  const rows = await query(sql, params);
  return rows[0] || null;
};

const makeId = prefix =>
  `${prefix}_${crypto.randomBytes(12).toString('hex')}`;

const clean = value =>
  typeof value === 'string' ? value.trim() : value;

const emailValue = value =>
  String(value || '').trim().toLowerCase();

const isValidEmail = value =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ''));

const isValidPhone = value =>
  /^\+?[0-9\s()-]{9,20}$/.test(String(value || ''));

const isValidMac = value =>
  /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(String(value || ''));

const signToken = (claims, expiresIn = '7d') =>
  jwt.sign(claims, JWT_SECRET, { expiresIn });

const publicTenant = tenant => {
  if (!tenant) return null;

  return {
    id: tenant.id,
    business_name: tenant.business_name,
    owner_name: tenant.owner_name,
    phone: tenant.phone,
    email: tenant.email,
    subdomain: tenant.subdomain,
    plan: tenant.plan,
    max_devices: tenant.max_devices,
    max_clients: tenant.max_clients,
    status: tenant.status,
    role: tenant.role || 'tenant',
    trial_started_at: tenant.trial_started_at,
    trial_ends_at: tenant.trial_ends_at,
    subscription_status: tenant.subscription_status,
    subscription_ends_at: tenant.subscription_ends_at,
    created_at: tenant.created_at
  };
};

const authMiddleware = asyncRoute(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';

  if (!token) fail(401, 'Ingia kwanza ili kuendelea.');

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch {
    fail(401, 'Token imeisha muda au si sahihi. Ingia tena.');
  }

  if (!decoded.tenant_id || !decoded.email) {
    fail(401, 'Token haina taarifa zinazohitajika.');
  }

  req.user = decoded;
  req.tenant_id = decoded.tenant_id;
  req.email = decoded.email;

  if (decoded.role === 'super_admin' || decoded.tenant_id === SUPER_ADMIN_ID) {
    req.role = 'super_admin';
    return next();
  }

  const tenant = await one(
    'SELECT * FROM tenants WHERE id = $1',
    [decoded.tenant_id]
  );

  if (!tenant) fail(401, 'Akaunti haijapatikana.');

  if (tenant.status !== 'active') {
    fail(403, `Akaunti yako haipo active. Hali: ${tenant.status || 'unknown'}. Wasiliana na msimamizi.`);
  }

  req.tenant = tenant;
  req.role = 'tenant';
  next();
});

const requireSuperAdmin = (req, res, next) => {
  if (req.role !== 'super_admin') {
    return res.status(403).json({ success: false, message: 'Super Admin pekee anaruhusiwa.' });
  }
  next();
};

const getTenantId = req => {
  if (req.role === 'super_admin') {
    return req.params.tenant_id || req.body.tenant_id || req.query.tenant_id || null;
  }
  return req.tenant_id;
};

const requireTenantId = req => {
  const tenantId = getTenantId(req);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');
  return tenantId;
};

const getTenantRecord = async tenantId => {
  const tenant = await one('SELECT * FROM tenants WHERE id = $1', [tenantId]);
  if (!tenant) fail(404, 'WISP haijapatikana.');
  return tenant;
};

const ensureTenantAccess = (req, tenantId) => {
  if (req.role === 'super_admin') return;
  if (req.tenant_id !== tenantId) fail(403, 'Huruhusiwi kufikia taarifa za WISP mwingine.');
};

const requireSubscription = asyncRoute(async (req, res, next) => {
  if (req.role === 'super_admin') return next();

  const tenant = req.tenant;
  const now = Date.now();
  const trialEnd = tenant.trial_ends_at ? new Date(tenant.trial_ends_at).getTime() : 0;
  const paidEnd = tenant.subscription_ends_at
    ? new Date(tenant.subscription_ends_at).getTime()
    : 0;

  const trialValid =
    tenant.subscription_status === 'trial' &&
    trialEnd > now;

  const paidValid =
    tenant.subscription_status === 'active' &&
    paidEnd > now;

  if (!trialValid && !paidValid) {
    return res.status(402).json({
      success: false,
      code: 'SUBSCRIPTION_REQUIRED',
      message: 'Muda wa majaribio umeisha au usajili haujalipiwa. Tafadhali chagua mpango na ukamilishe malipo.',
      plans: PLANS
    });
  }

  next();
});

const checkPlanLimit = async (tenant, field, table) => {
  const limit = tenant[field];
  if (limit === null || limit === undefined || Number(limit) < 0) return;

  const row = await one(
    `SELECT COUNT(*)::int AS total FROM ${table} WHERE tenant_id = $1`,
    [tenant.id]
  );

  if (Number(row?.total || 0) >= Number(limit)) {
    fail(403, `Umefikia kikomo cha ${table}. Boresha mpango wako ili kuongeza uwezo.`);
  }
};

const checkTenantLimit = async (tenant, kind) => {
  if (kind === 'devices') return checkPlanLimit(tenant, 'max_devices', 'devices');
  if (kind === 'clients') return checkPlanLimit(tenant, 'max_clients', 'clients');
};

const createTrialDates = () => {
  const started = new Date();
  const ends = new Date(started.getTime() + 4 * 24 * 60 * 60 * 1000);
  return { started, ends };
};

const getPlan = value => {
  const key = String(value || '').trim().toUpperCase();
  return PLANS[key] || null;
};

const makeSubdomain = businessName => {
  const base = String(businessName || 'wisp')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 35) || 'wisp';

  return `${base}-${crypto.randomBytes(3).toString('hex')}`;
};

const issueTenantToken = tenant =>
  signToken({
    tenant_id: tenant.id,
    email: tenant.email,
    role: 'tenant'
  });

const issueSuperAdminToken = () =>
  signToken({
    tenant_id: SUPER_ADMIN_ID,
    email: SUPER_ADMIN_EMAIL,
    role: 'super_admin'
  });

app.get('/api/health', asyncRoute(async (req, res) => {
  await db.ready;
  await query('SELECT 1');
  res.json({
    success: true,
    service: 'MR HAAS MULTI-TENANT WISP MANAGEMENT',
    database: 'connected',
    timestamp: new Date().toISOString()
  });
}));

app.get('/api/plans', (req, res) => {
  res.json({ success: true, plans: PLANS, trial_days: 4 });
});

/* =========================
   AUTHENTICATION / REGISTER
========================= */

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const businessName = clean(req.body.business_name);
  const ownerName = clean(req.body.owner_name);
  const phone = clean(req.body.phone);
  const email = emailValue(req.body.email);
  const password = String(req.body.password || '');

  if (!businessName || !ownerName || !phone || !email || !password) {
    fail(400, 'Jaza jina la biashara, jina la mmiliki, simu, barua pepe na nenosiri.');
  }

  if (!isValidEmail(email)) fail(400, 'Barua pepe si sahihi.');
  if (!isValidPhone(phone)) fail(400, 'Namba ya simu si sahihi.');
  if (password.length < 8) fail(400, 'Nenosiri lazima liwe na angalau herufi 8.');

  const existing = await one(
    'SELECT id FROM tenants WHERE LOWER(email) = $1 OR phone = $2 LIMIT 1',
    [email, phone]
  );

  if (existing) fail(409, 'Barua pepe au simu tayari imesajiliwa.');

  const id = makeId('tenant');
  const subdomain = makeSubdomain(businessName);
  const passwordHash = await bcrypt.hash(password, 12);
  const trial = createTrialDates();
  const plan = PLANS.START;

  const tenant = await one(
    `INSERT INTO tenants
      (id, business_name, owner_name, phone, email, password_hash,
       subdomain, plan, max_devices, max_clients, status, role,
       trial_started_at, trial_ends_at, subscription_status,
       subscription_ends_at, created_at)
     VALUES
      ($1,$2,$3,$4,$5,$6,$7,'START',$8,$9,'active','tenant',
       $10,$11,'trial',NULL,NOW())
     RETURNING *`,
    [
      id, businessName, ownerName, phone, email, passwordHash,
      subdomain, plan.max_devices, plan.max_clients, trial.started, trial.ends
    ]
  );

  await query(
    `INSERT INTO tenant_settings (tenant_id, portal_title, primary_color, announcement, contact_phone, currency)
     VALUES ($1,$2,$3,$4,$5,'TZS')
     ON CONFLICT (tenant_id) DO NOTHING`,
    [id, businessName, '#111827', '', phone]
  );

  const token = issueTenantToken(tenant);

  res.status(201).json({
    success: true,
    message: 'Akaunti imeundwa. Jaribio lako la siku 4 limeanza.',
    token,
    tenant: publicTenant(tenant),
    trial_days: 4,
    plans: PLANS
  });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = emailValue(req.body.email);
  const password = String(req.body.password || '');

  if (!email || !password) fail(400, 'Weka barua pepe na nenosiri.');

  // Super Admin credentials are configured as environment variables.
  if (
    SUPER_ADMIN_EMAIL &&
    email === SUPER_ADMIN_EMAIL &&
    SUPER_ADMIN_PASSWORD &&
    await bcrypt.compare(password, await bcrypt.hash(SUPER_ADMIN_PASSWORD, 12)).catch(() => false)
  ) {
    return res.json({
      success: true,
      token: issueSuperAdminToken(),
      role: 'super_admin',
      tenant: {
        id: SUPER_ADMIN_ID,
        email: SUPER_ADMIN_EMAIL,
        role: 'super_admin',
        business_name: 'MR HAAS SUPER ADMIN'
      }
    });
  }

  // Also allow Super Admin login by exact environment password.
  if (
    SUPER_ADMIN_EMAIL &&
    email === SUPER_ADMIN_EMAIL &&
    SUPER_ADMIN_PASSWORD &&
    password === SUPER_ADMIN_PASSWORD
  ) {
    return res.json({
      success: true,
      token: issueSuperAdminToken(),
      role: 'super_admin',
      tenant: {
        id: SUPER_ADMIN_ID,
        email: SUPER_ADMIN_EMAIL,
        role: 'super_admin',
        business_name: 'MR HAAS SUPER ADMIN'
      }
    });
  }

  const tenant = await one(
    'SELECT * FROM tenants WHERE LOWER(email) = $1 LIMIT 1',
    [email]
  );

  if (!tenant) fail(401, 'Barua pepe au nenosiri si sahihi.');

  const valid = await bcrypt.compare(password, tenant.password_hash);
  if (!valid) fail(401, 'Barua pepe au nenosiri si sahihi.');

  if (tenant.status !== 'active') {
    fail(403, `Akaunti yako imewekewa hali ya ${tenant.status}. Wasiliana na Super Admin.`);
  }

  res.json({
    success: true,
    token: issueTenantToken(tenant),
    role: 'tenant',
    tenant: publicTenant(tenant),
    plans: PLANS
  });
}));

app.post('/api/super-admin/login', asyncRoute(async (req, res) => {
  const email = emailValue(req.body.email);
  const password = String(req.body.password || '');

  if (!SUPER_ADMIN_EMAIL || !SUPER_ADMIN_PASSWORD) {
    fail(503, 'Super Admin hajasanidiwa. Weka SUPER_ADMIN_EMAIL na SUPER_ADMIN_PASSWORD kwenye environment variables.');
  }

  if (email !== SUPER_ADMIN_EMAIL || password !== SUPER_ADMIN_PASSWORD) {
    fail(401, 'Taarifa za Super Admin si sahihi.');
  }

  res.json({
    success: true,
    token: issueSuperAdminToken(),
    role: 'super_admin',
    tenant: {
      id: SUPER_ADMIN_ID,
      email: SUPER_ADMIN_EMAIL,
      role: 'super_admin',
      business_name: 'MR HAAS SUPER ADMIN'
    }
  });
}));

app.get('/api/auth/me', authMiddleware, asyncRoute(async (req, res) => {
  if (req.role === 'super_admin') {
    return res.json({
      success: true,
      role: 'super_admin',
      tenant: {
        id: SUPER_ADMIN_ID,
        email: req.email,
        business_name: 'MR HAAS SUPER ADMIN'
      }
    });
  }

  const tenant = await getTenantRecord(req.tenant_id);

  res.json({
    success: true,
    role: 'tenant',
    tenant: publicTenant(tenant),
    plans: PLANS
  });
}));

/* =========================
   TENANT SUBSCRIPTION
========================= */

app.get('/api/subscription', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin'
    ? req.query.tenant_id
    : req.tenant_id;

  if (!tenantId) fail(400, 'tenant_id inahitajika kwa Super Admin.');
  ensureTenantAccess(req, tenantId);

  const tenant = await getTenantRecord(tenantId);
  const trialEnd = tenant.trial_ends_at ? new Date(tenant.trial_ends_at) : null;
  const paidEnd = tenant.subscription_ends_at ? new Date(tenant.subscription_ends_at) : null;
  const now = new Date();

  const trialActive =
    tenant.subscription_status === 'trial' &&
    trialEnd &&
    trialEnd > now;

  const paidActive =
    tenant.subscription_status === 'active' &&
    paidEnd &&
    paidEnd > now;

  res.json({
    success: true,
    subscription: {
      plan: tenant.plan,
      status: tenant.subscription_status,
      trial_started_at: tenant.trial_started_at,
      trial_ends_at: tenant.trial_ends_at,
      subscription_ends_at: tenant.subscription_ends_at,
      trial_active: Boolean(trialActive),
      paid_active: Boolean(paidActive),
      service_access: Boolean(trialActive || paidActive),
      plans: PLANS
    }
  });
}));

app.get('/api/payment-settings', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin'
    ? req.query.tenant_id
    : req.tenant_id;

  if (!tenantId) fail(400, 'tenant_id inahitajika kwa Super Admin.');
  ensureTenantAccess(req, tenantId);

  const settings = await one(
    `SELECT tenant_id, enabled_providers, manual_payment_instructions,
            payment_phone, payment_account_name, updated_at
     FROM payment_settings WHERE tenant_id = $1`,
    [tenantId]
  );

  res.json({
    success: true,
    settings: settings || {
      tenant_id: tenantId,
      enabled_providers: ['manual'],
      manual_payment_instructions: '',
      payment_phone: '',
      payment_account_name: ''
    },
    available_providers: PAYMENT_PROVIDERS
  });
}));

app.put('/api/payment-settings', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin'
    ? req.body.tenant_id
    : req.tenant_id;

  if (!tenantId) fail(400, 'tenant_id inahitajika.');
  ensureTenantAccess(req, tenantId);

  const providers = Array.isArray(req.body.enabled_providers)
    ? req.body.enabled_providers.filter(item => PAYMENT_PROVIDERS.includes(item))
    : ['manual'];

  const instructions = String(req.body.manual_payment_instructions || '').slice(0, 3000);
  const phone = String(req.body.payment_phone || '').slice(0, 40);
  const accountName = String(req.body.payment_account_name || '').slice(0, 120);

  const settings = await one(
    `INSERT INTO payment_settings
      (tenant_id, enabled_providers, manual_payment_instructions, payment_phone, payment_account_name, updated_at)
     VALUES ($1,$2,$3,$4,$5,NOW())
     ON CONFLICT (tenant_id) DO UPDATE SET
       enabled_providers = EXCLUDED.enabled_providers,
       manual_payment_instructions = EXCLUDED.manual_payment_instructions,
       payment_phone = EXCLUDED.payment_phone,
       payment_account_name = EXCLUDED.payment_account_name,
       updated_at = NOW()
     RETURNING tenant_id, enabled_providers, manual_payment_instructions,
               payment_phone, payment_account_name, updated_at`,
    [tenantId, providers, instructions, phone, accountName]
  );

  res.json({ success: true, settings });
}));

/* =========================
   SUPER ADMIN: WISPs
========================= */

app.get('/api/super/tenants', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenants = await query(
    `SELECT t.id, t.business_name, t.owner_name, t.phone, t.email, t.subdomain,
            t.plan, t.max_devices, t.max_clients, t.status, t.role,
            t.trial_started_at, t.trial_ends_at, t.subscription_status,
            t.subscription_ends_at, t.created_at,
            (SELECT COUNT(*)::int FROM devices d WHERE d.tenant_id = t.id) AS device_count,
            (SELECT COUNT(*)::int FROM clients c WHERE c.tenant_id = t.id) AS client_count,
            (SELECT COUNT(*)::int FROM sites s WHERE s.tenant_id = t.id) AS site_count
     FROM tenants t
     WHERE t.id <> $1
     ORDER BY t.created_at DESC`,
    [SUPER_ADMIN_ID]
  );

  res.json({ success: true, tenants, total: tenants.length });
}));

app.post('/api/super/tenants', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const businessName = clean(req.body.business_name);
  const ownerName = clean(req.body.owner_name);
  const phone = clean(req.body.phone);
  const email = emailValue(req.body.email);
  const password = String(req.body.password || '');
  const planKey = String(req.body.plan || 'START').toUpperCase();
  const plan = getPlan(planKey);

  if (!businessName || !ownerName || !phone || !email || !password) {
    fail(400, 'Jaza taarifa zote zinazohitajika za WISP.');
  }

  if (!isValidEmail(email)) fail(400, 'Barua pepe si sahihi.');
  if (!isValidPhone(phone)) fail(400, 'Namba ya simu si sahihi.');
  if (password.length < 8) fail(400, 'Nenosiri lazima liwe na angalau herufi 8.');
  if (!plan) fail(400, 'Mpango si sahihi.');

  const existing = await one(
    'SELECT id FROM tenants WHERE LOWER(email) = $1 OR phone = $2 LIMIT 1',
    [email, phone]
  );
  if (existing) fail(409, 'Barua pepe au simu tayari imesajiliwa.');

  const trial = createTrialDates();
  const id = makeId('tenant');
  const hash = await bcrypt.hash(password, 12);
  const subdomain = makeSubdomain(businessName);

  const tenant = await one(
    `INSERT INTO tenants
      (id, business_name, owner_name, phone, email, password_hash, subdomain,
       plan, max_devices, max_clients, status, role, trial_started_at,
       trial_ends_at, subscription_status, subscription_ends_at, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active','tenant',$11,$12,'trial',NULL,NOW())
     RETURNING *`,
    [
      id, businessName, ownerName, phone, email, hash, subdomain, plan.name,
      plan.max_devices, plan.max_clients, trial.started, trial.ends
    ]
  );

  await query(
    `INSERT INTO tenant_settings (tenant_id, portal_title, primary_color, announcement, contact_phone, currency)
     VALUES ($1,$2,$3,$4,$5,'TZS')
     ON CONFLICT (tenant_id) DO NOTHING`,
    [id, businessName, '#111827', '', phone]
  );

  res.status(201).json({
    success: true,
    message: 'WISP imesajiliwa na jaribio la siku 4 limeanza.',
    tenant: publicTenant(tenant),
    trial_days: 4
  });
}));

app.put('/api/super/tenant/:id/plan', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const plan = getPlan(req.body.plan);
  if (!plan) fail(400, 'Mpango haupo kwenye orodha.');

  const tenant = await one(
    `UPDATE tenants
     SET plan = $1, max_devices = $2, max_clients = $3
     WHERE id = $4 AND id <> $5
     RETURNING *`,
    [plan.name, plan.max_devices, plan.max_clients, req.params.id, SUPER_ADMIN_ID]
  );

  if (!tenant) fail(404, 'WISP haijapatikana.');

  res.json({ success: true, message: 'Mpango umebadilishwa.', tenant: publicTenant(tenant) });
}));


app.patch('/api/super/tenant/:id/status', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenantId = String(req.params.id || '').trim();
  const status = String(req.body.status || '').trim().toLowerCase();

  if (!tenantId) {
    fail(400, 'ID ya Tenant inahitajika.');
  }

  if (tenantId === String(SUPER_ADMIN_ID)) {
    fail(403, 'Huwezi kubadilisha hali ya akaunti ya Super Admin.');
  }

  if (!['active', 'suspended'].includes(status)) {
    fail(400, 'Hali inaruhusiwa ni active au suspended.');
  }

  const tenant = await one(
    `UPDATE tenants
     SET status = $1
     WHERE id = $2
       AND id <> $3
     RETURNING id, business_name, email, status`,
    [status, tenantId, SUPER_ADMIN_ID]
  );

  if (!tenant) {
    fail(404, 'WISP haijapatikana.');
  }

  res.json({
    success: true,
    message: status === 'suspended'
      ? 'Akaunti ya Tenant imesimamishwa.'
      : 'Akaunti ya Tenant imerejeshwa.',
    tenant
  });
}));


app.put('/api/super/tenant/:id/subscription', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const tenantId = req.params.id;
  const plan = getPlan(req.body.plan);
  const status = String(req.body.subscription_status || '').toLowerCase();

  if (!plan) fail(400, 'Mpango si sahihi.');
  if (!['trial', 'active', 'expired', 'pending', 'cancelled'].includes(status)) {
    fail(400, 'subscription_status si sahihi.');
  }

  const endsAt = req.body.subscription_ends_at
    ? new Date(req.body.subscription_ends_at)
    : null;

  if (endsAt && Number.isNaN(endsAt.getTime())) fail(400, 'Tarehe ya mwisho si sahihi.');

  const tenant = await one(
    `UPDATE tenants
     SET plan = $1, max_devices = $2, max_clients = $3,
         subscription_status = $4,
         subscription_ends_at = $5
     WHERE id = $6 AND id <> $7
     RETURNING *`,
    [plan.name, plan.max_devices, plan.max_clients, status, endsAt, tenantId, SUPER_ADMIN_ID]
  );

  if (!tenant) fail(404, 'WISP haijapatikana.');

  res.json({ success: true, tenant: publicTenant(tenant) });
}));

app.delete('/api/super/tenant/:id', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  if (req.params.id === SUPER_ADMIN_ID) fail(400, 'Huwezi kufuta Super Admin.');

  const tenant = await one(
    'SELECT id FROM tenants WHERE id = $1',
    [req.params.id]
  );
  if (!tenant) fail(404, 'WISP haijapatikana.');

  // Suspend instead of destructive deletion to preserve accounting/audit data.
  await query(
    `UPDATE tenants SET status = 'inactive' WHERE id = $1`,
    [req.params.id]
  );

  res.json({ success: true, message: 'WISP imewekwa inactive; taarifa zake zimehifadhiwa.' });
}));

/* =========================
   SITES
========================= */

app.get('/api/sites/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const sites = await query(
    `SELECT id, tenant_id, name, location, description, status, created_at
     FROM sites WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );

  res.json({ success: true, sites });
}));

app.post('/api/sites', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId || !req.body.name) fail(400, 'tenant_id na jina la site vinahitajika.');

  const tenant = await getTenantRecord(tenantId);
  const site = await one(
    `INSERT INTO sites (id, tenant_id, name, location, description, status, created_at)
     VALUES ($1,$2,$3,$4,$5,'active',NOW())
     RETURNING *`,
    [
      makeId('site'), tenantId, clean(req.body.name),
      clean(req.body.location || ''), clean(req.body.description || '')
    ]
  );

  res.status(201).json({ success: true, site });
}));

app.delete('/api/sites/:id', authMiddleware, asyncRoute(async (req, res) => {
  const site = await one('SELECT * FROM sites WHERE id = $1', [req.params.id]);
  if (!site) fail(404, 'Site haijapatikana.');
  ensureTenantAccess(req, site.tenant_id);

  await query('DELETE FROM sites WHERE id = $1', [site.id]);
  res.json({ success: true, message: 'Site imefutwa.' });
}));

/* =========================
   DEVICES
========================= */

app.get('/api/devices/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const devices = await query(
    `SELECT id, tenant_id, site_id, name, vendor, device_type, model,
            mac_address, ip_address, wan_port, connection_type,
            last_seen, created_at
     FROM devices WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );

  res.json({ success: true, devices });
}));

app.post('/api/devices', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');

  const tenant = await getTenantRecord(tenantId);
  await checkTenantLimit(tenant, 'devices');

  const name = clean(req.body.name);
  const vendor = clean(req.body.vendor);
  const deviceType = clean(req.body.device_type || req.body.type || 'router');
  const model = clean(req.body.model || '');
  const mac = clean(req.body.mac_address || '');
  const ip = clean(req.body.ip_address || '');
  const siteId = clean(req.body.site_id || '') || null;
  const wanPort = clean(req.body.wan_port || '');
  const connectionType = clean(req.body.connection_type || 'api');

  if (!name || !vendor) fail(400, 'Jina la kifaa na mtengenezaji vinahitajika.');
  if (!DEVICE_VENDORS.includes(vendor)) fail(400, 'Mtengenezaji wa kifaa hajaruhusiwa.');
  if (!DEVICE_TYPES.includes(deviceType)) fail(400, 'Aina ya kifaa si sahihi.');
  if (mac && !isValidMac(mac)) fail(400, 'MAC address si sahihi.');

  if (siteId) {
    const site = await one(
      'SELECT id FROM sites WHERE id = $1 AND tenant_id = $2',
      [siteId, tenantId]
    );
    if (!site) fail(400, 'Site haipo kwenye WISP hii.');
  }

  // Never store router passwords as plaintext.
  const credentialPassword = String(req.body.password || '');
  const credentialUser = String(req.body.username || req.body.user || '');
  if (credentialPassword) {
    fail(400, 'Kuhifadhi nenosiri la kifaa hakujawashwa bado. Usitume password kwenye API hii.');
  }

  const device = await one(
    `INSERT INTO devices
      (id, tenant_id, site_id, name, vendor, device_type, model,
       mac_address, ip_address, wan_port, connection_type, last_seen, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NOW())
     RETURNING id, tenant_id, site_id, name, vendor, device_type, model,
               mac_address, ip_address, wan_port, connection_type, last_seen, created_at`,
    [
      makeId('device'), tenantId, siteId, name, vendor, deviceType, model,
      mac || null, ip || null, wanPort || null, connectionType
    ]
  );

  res.status(201).json({
    success: true,
    message: 'Kifaa kimesajiliwa. Muunganisho wa moja kwa moja wa vendor lazima usanidiwe tofauti.',
    device
  });
}));

app.delete('/api/devices/:id', authMiddleware, asyncRoute(async (req, res) => {
  const device = await one('SELECT * FROM devices WHERE id = $1', [req.params.id]);
  if (!device) fail(404, 'Kifaa hakijapatikana.');
  ensureTenantAccess(req, device.tenant_id);

  await query('DELETE FROM devices WHERE id = $1', [device.id]);
  res.json({ success: true, message: 'Kifaa kimeondolewa.' });
}));

app.get('/api/devices/:id/status', authMiddleware, asyncRoute(async (req, res) => {
  const device = await one(
    'SELECT id, tenant_id, name, vendor, last_seen FROM devices WHERE id = $1',
    [req.params.id]
  );

  if (!device) fail(404, 'Kifaa hakijapatikana.');
  ensureTenantAccess(req, device.tenant_id);

  const lastSeen = device.last_seen ? new Date(device.last_seen).getTime() : 0;
  const online = Boolean(lastSeen && Date.now() - lastSeen < 10 * 60 * 1000);

  res.json({
    success: true,
    device_id: device.id,
    status: online ? 'online' : 'unknown_or_offline',
    last_seen: device.last_seen,
    note: 'Hali hii inategemea heartbeat ya mwisho; si kipimo cha moja kwa moja cha RouterOS.'
  });
}));

app.post('/api/mikrotik/test-connection', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);

  res.status(501).json({
    success: false,
    code: 'MIKROTIK_API_NOT_CONFIGURED',
    message: 'RouterOS API bado haijaunganishwa. Endpoint hii haitoi madai ya uunganisho wa kweli. Hatua inayofuata ni kuunganisha RouterOS API kwa credentials salama.'
  });
}));

app.post('/api/mikrotik/register-router', asyncRoute(async (req, res) => {
  const configuredSecret = process.env.MIKROTIK_WEBHOOK_SECRET;
  const providedSecret = String(req.headers['x-mikrotik-secret'] || '');

  if (!configuredSecret || !providedSecret) fail(401, 'Webhook haijaidhinishwa.');

  const a = Buffer.from(configuredSecret);
  const b = Buffer.from(providedSecret);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    fail(401, 'Webhook haijaidhinishwa.');
  }

  const tenantId = String(req.body.tenant_id || '');
  const name = clean(req.body.name || 'MikroTik Router');
  const mac = clean(req.body.mac_address || '');
  const ip = clean(req.body.ip_address || '');

  if (!tenantId) fail(400, 'tenant_id inahitajika.');
  if (mac && !isValidMac(mac)) fail(400, 'MAC address si sahihi.');

  const tenant = await getTenantRecord(tenantId);
  if (tenant.status !== 'active') fail(403, 'WISP haipo active.');

  let device;

  if (mac) {
    device = await one(
      `UPDATE devices
       SET name = $1, ip_address = $2, last_seen = NOW()
       WHERE tenant_id = $3 AND mac_address = $4 AND vendor = 'MikroTik'
       RETURNING id, tenant_id, name, vendor, mac_address, ip_address, last_seen`,
      [name, ip || null, tenantId, mac]
    );
  }

  if (!device) {
    device = await one(
      `INSERT INTO devices
       (id, tenant_id, name, vendor, device_type, mac_address, ip_address,
        connection_type, last_seen, created_at)
       VALUES ($1,$2,$3,'MikroTik','router',$4,$5,'webhook',NOW(),NOW())
       RETURNING id, tenant_id, name, vendor, mac_address, ip_address, last_seen`,
      [makeId('device'), tenantId, name, mac || null, ip || null]
    );
  }

  res.json({ success: true, device });
}));

/* =========================
   CLIENTS
========================= */

app.get('/api/clients/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const clients = await query(
    `SELECT id, tenant_id, site_id, name, phone, username, package_name,
            connection_type, status, created_at
     FROM clients WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );

  res.json({ success: true, clients });
}));

app.post('/api/clients', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');

  const tenant = await getTenantRecord(tenantId);
  await checkTenantLimit(tenant, 'clients');

  const name = clean(req.body.name);
  const phone = clean(req.body.phone || '');
  const username = clean(req.body.username || '');
  const packageName = clean(req.body.package_name || '');
  const siteId = clean(req.body.site_id || '') || null;
  const connectionType = clean(req.body.connection_type || 'hotspot');

  if (!name) fail(400, 'Jina la mteja linahitajika.');
  if (!['hotspot', 'pppoe'].includes(connectionType)) {
    fail(400, 'connection_type lazima iwe hotspot au pppoe.');
  }

  if (siteId) {
    const site = await one('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [siteId, tenantId]);
    if (!site) fail(400, 'Site haipo kwenye WISP hii.');
  }

  if (username) {
    const duplicate = await one(
      'SELECT id FROM clients WHERE tenant_id = $1 AND username = $2 LIMIT 1',
      [tenantId, username]
    );
    if (duplicate) fail(409, 'Username hii tayari inatumika kwenye WISP hii.');
  }

  const client = await one(
    `INSERT INTO clients
      (id, tenant_id, site_id, name, phone, username, package_name,
       connection_type, status, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',NOW())
     RETURNING id, tenant_id, site_id, name, phone, username, package_name,
               connection_type, status, created_at`,
    [
      makeId('client'), tenantId, siteId, name, phone || null,
      username || null, packageName || null, connectionType
    ]
  );

  res.status(201).json({ success: true, client });
}));

app.put('/api/clients/:id', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const client = await one('SELECT * FROM clients WHERE id = $1', [req.params.id]);
  if (!client) fail(404, 'Mteja hajapatikana.');
  ensureTenantAccess(req, client.tenant_id);

  const name = clean(req.body.name ?? client.name);
  const phone = clean(req.body.phone ?? client.phone);
  const packageName = clean(req.body.package_name ?? client.package_name);
  const status = String(req.body.status ?? client.status).toLowerCase();

  if (!['active', 'suspended', 'inactive'].includes(status)) {
    fail(400, 'Hali ya mteja si sahihi.');
  }

  const updated = await one(
    `UPDATE clients
     SET name = $1, phone = $2, package_name = $3, status = $4
     WHERE id = $5
     RETURNING id, tenant_id, site_id, name, phone, username, package_name,
               connection_type, status, created_at`,
    [name, phone || null, packageName || null, status, client.id]
  );

  res.json({ success: true, client: updated });
}));

app.delete('/api/clients/:id', authMiddleware, asyncRoute(async (req, res) => {
  const client = await one('SELECT * FROM clients WHERE id = $1', [req.params.id]);
  if (!client) fail(404, 'Mteja hajapatikana.');
  ensureTenantAccess(req, client.tenant_id);

  await query('DELETE FROM clients WHERE id = $1', [client.id]);
  res.json({ success: true, message: 'Mteja ameondolewa.' });
}));

/* =========================
   PACKAGES
========================= */

app.get('/api/packages/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const packages = await query(
    `SELECT id, tenant_id, name, price, duration_value, duration_unit,
            speed_down, speed_up, connection_type, description, status, created_at
     FROM packages WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );

  res.json({ success: true, packages });
}));

app.post('/api/packages', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');

  const name = clean(req.body.name);
  const price = Number(req.body.price);
  const durationValue = Number(req.body.duration_value || 1);
  const durationUnit = String(req.body.duration_unit || 'days').toLowerCase();
  const speedDown = Number(req.body.speed_down || 0);
  const speedUp = Number(req.body.speed_up || 0);
  const connectionType = String(req.body.connection_type || 'hotspot').toLowerCase();

  if (!name) fail(400, 'Jina la kifurushi linahitajika.');
  if (!Number.isFinite(price) || price < 0) fail(400, 'Bei si sahihi.');
  if (!Number.isInteger(durationValue) || durationValue < 1) fail(400, 'Muda wa kifurushi si sahihi.');
  if (!['minutes', 'hours', 'days', 'weeks', 'months'].includes(durationUnit)) {
    fail(400, 'duration_unit si sahihi.');
  }
  if (!['hotspot', 'pppoe'].includes(connectionType)) fail(400, 'connection_type si sahihi.');

  const pack = await one(
    `INSERT INTO packages
      (id, tenant_id, name, price, duration_value, duration_unit,
       speed_down, speed_up, connection_type, description, status, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',NOW())
     RETURNING *`,
    [
      makeId('pkg'), tenantId, name, price, durationValue, durationUnit,
      speedDown, speedUp, connectionType, clean(req.body.description || '')
    ]
  );

  res.status(201).json({ success: true, package: pack });
}));

app.put('/api/packages/:id', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const pack = await one('SELECT * FROM packages WHERE id = $1', [req.params.id]);
  if (!pack) fail(404, 'Kifurushi hakijapatikana.');
  ensureTenantAccess(req, pack.tenant_id);

  const name = clean(req.body.name ?? pack.name);
  const price = Number(req.body.price ?? pack.price);
  const status = String(req.body.status ?? pack.status).toLowerCase();

  if (!name || !Number.isFinite(price) || price < 0) fail(400, 'Jina au bei si sahihi.');
  if (!['active', 'inactive'].includes(status)) fail(400, 'Hali ya kifurushi si sahihi.');

  const updated = await one(
    `UPDATE packages SET name = $1, price = $2, status = $3
     WHERE id = $4 RETURNING *`,
    [name, price, status, pack.id]
  );

  res.json({ success: true, package: updated });
}));

app.delete('/api/packages/:id', authMiddleware, asyncRoute(async (req, res) => {
  const pack = await one('SELECT * FROM packages WHERE id = $1', [req.params.id]);
  if (!pack) fail(404, 'Kifurushi hakijapatikana.');
  ensureTenantAccess(req, pack.tenant_id);

  await query('DELETE FROM packages WHERE id = $1', [pack.id]);
  res.json({ success: true, message: 'Kifurushi kimefutwa.' });
}));

/* =========================
   VOUCHERS / CAPTIVE PORTAL
========================= */

app.get('/api/vouchers/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const vouchers = await query(
    `SELECT id, tenant_id, package_id, code, status, expires_at, used_at, created_at
     FROM vouchers WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );

  res.json({ success: true, vouchers });
}));

app.post('/api/vouchers', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');

  const count = Math.min(Math.max(Number(req.body.count || 1), 1), 500);
  const packageId = clean(req.body.package_id || '') || null;
  const expiresAt = req.body.expires_at ? new Date(req.body.expires_at) : null;

  if (expiresAt && Number.isNaN(expiresAt.getTime())) fail(400, 'Tarehe ya kuisha si sahihi.');

  if (packageId) {
    const pack = await one(
      `SELECT id FROM packages WHERE id = $1 AND tenant_id = $2 AND status = 'active'`,
      [packageId, tenantId]
    );
    if (!pack) fail(400, 'Kifurushi hakipo au hakitumiki.');
  }

  const vouchers = [];

  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(5).toString('hex').toUpperCase();
    const voucher = await one(
      `INSERT INTO vouchers
        (id, tenant_id, package_id, code, status, expires_at, created_at)
       VALUES ($1,$2,$3,$4,'unused',$5,NOW())
       RETURNING id, tenant_id, package_id, code, status, expires_at, created_at`,
      [makeId('voucher'), tenantId, packageId, code, expiresAt]
    );
    vouchers.push(voucher);
  }

  res.status(201).json({ success: true, vouchers });
}));

app.post('/api/portal/voucher/validate', asyncRoute(async (req, res) => {
  const tenantId = clean(req.body.tenant_id);
  const code = String(req.body.code || '').trim().toUpperCase();

  if (!tenantId || !code) fail(400, 'tenant_id na vocha vinahitajika.');

  const tenant = await getTenantRecord(tenantId);

  if (tenant.status !== 'active') fail(403, 'Huduma ya WISP hii haipatikani kwa sasa.');

  const trialEnd = tenant.trial_ends_at ? new Date(tenant.trial_ends_at).getTime() : 0;
  const paidEnd = tenant.subscription_ends_at ? new Date(tenant.subscription_ends_at).getTime() : 0;
  const subscriptionValid =
    (tenant.subscription_status === 'trial' && trialEnd > Date.now()) ||
    (tenant.subscription_status === 'active' && paidEnd > Date.now());

  if (!subscriptionValid) fail(402, 'Huduma ya WISP imesitishwa. Wasiliana na mtoa huduma.');

  const voucher = await one(
    `SELECT v.id, v.tenant_id, v.package_id, v.code, v.status, v.expires_at,
            p.name AS package_name, p.duration_value, p.duration_unit,
            p.speed_down, p.speed_up
     FROM vouchers v
     LEFT JOIN packages p ON p.id = v.package_id AND p.tenant_id = v.tenant_id
     WHERE v.tenant_id = $1 AND UPPER(v.code) = $2
     LIMIT 1`,
    [tenantId, code]
  );

  if (!voucher) fail(404, 'Vocha haijapatikana.');
  if (voucher.status !== 'unused') fail(409, 'Vocha hii tayari imetumika au imezuiwa.');
  if (voucher.expires_at && new Date(voucher.expires_at).getTime() < Date.now()) {
    fail(410, 'Vocha imeisha muda.');
  }

  res.json({
    success: true,
    valid: true,
    voucher: {
      id: voucher.id,
      code: voucher.code,
      package_id: voucher.package_id,
      package_name: voucher.package_name,
      duration_value: voucher.duration_value,
      duration_unit: voucher.duration_unit,
      speed_down: voucher.speed_down,
      speed_up: voucher.speed_up
    },
    message: 'Vocha ni sahihi. Hii ni validation tu; kuunganisha mteja kunahitaji RouterOS/RADIUS integration.'
  });
}));

app.post('/api/portal/settings/:tenant_id', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const title = String(req.body.portal_title || '').slice(0, 120);
  const color = String(req.body.primary_color || '#111827');
  const announcement = String(req.body.announcement || '').slice(0, 3000);
  const contactPhone = String(req.body.contact_phone || '').slice(0, 40);
  const logoUrl = String(req.body.logo_url || '').slice(0, 1000);

  if (color && !/^#[0-9a-fA-F]{6}$/.test(color)) fail(400, 'Rangi lazima iwe HEX, mfano #111827.');

  const settings = await one(
    `INSERT INTO tenant_settings
      (tenant_id, portal_title, primary_color, announcement, contact_phone, logo_url, currency)
     VALUES ($1,$2,$3,$4,$5,$6,'TZS')
     ON CONFLICT (tenant_id) DO UPDATE SET
       portal_title = EXCLUDED.portal_title,
       primary_color = EXCLUDED.primary_color,
       announcement = EXCLUDED.announcement,
       contact_phone = EXCLUDED.contact_phone,
       logo_url = EXCLUDED.logo_url
     RETURNING tenant_id, portal_title, primary_color, announcement,
               contact_phone, logo_url, currency`,
    [tenantId, title, color, announcement, contactPhone, logoUrl]
  );

  res.json({ success: true, settings });
}));

app.get('/api/portal/settings/:tenant_id', asyncRoute(async (req, res) => {
  const tenantId = clean(req.params.tenant_id);
  const tenant = await getTenantRecord(tenantId);

  if (tenant.status !== 'active') fail(403, 'Portal haipatikani kwa sasa.');

  const settings = await one(
    `SELECT tenant_id, portal_title, primary_color, announcement,
            contact_phone, logo_url, currency
     FROM tenant_settings WHERE tenant_id = $1`,
    [tenantId]
  );

  const packages = await query(
    `SELECT id, name, price, duration_value, duration_unit,
            speed_down, speed_up, connection_type
     FROM packages
     WHERE tenant_id = $1 AND status = 'active'
     ORDER BY price ASC`,
    [tenantId]
  );

  res.json({
    success: true,
    portal: settings || {
      tenant_id: tenantId,
      portal_title: tenant.business_name,
      primary_color: '#111827',
      announcement: '',
      contact_phone: tenant.phone,
      logo_url: '',
      currency: 'TZS'
    },
    packages
  });
}));

/* =========================
   PAYMENTS
========================= */

app.get('/api/payments/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const payments = await query(
    `SELECT id, tenant_id, client_id, provider, reference, amount, currency,
            status, description, created_at, verified_at
     FROM payments WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );

  res.json({ success: true, payments });
}));

app.post('/api/payments/manual', authMiddleware, requireSubscription, asyncRoute(async (req, res) => {
  const tenantId = req.role === 'super_admin' ? req.body.tenant_id : req.tenant_id;
  ensureTenantAccess(req, tenantId);
  if (!tenantId) fail(400, 'tenant_id inahitajika.');

  const amount = Number(req.body.amount);
  const description = String(req.body.description || '').slice(0, 1000);
  const reference = String(req.body.reference || '').slice(0, 150);

  if (!Number.isFinite(amount) || amount <= 0) fail(400, 'Kiasi cha malipo si sahihi.');

  const payment = await one(
    `INSERT INTO payments
      (id, tenant_id, provider, reference, amount, currency, status, description, created_at)
     VALUES ($1,$2,'manual',$3,$4,'TZS','pending',$5,NOW())
     RETURNING id, tenant_id, provider, reference, amount, currency, status, description, created_at`,
    [makeId('payment'), tenantId, reference || null, amount, description]
  );

  res.status(201).json({
    success: true,
    message: 'Malipo yamehifadhiwa kama pending. Super Admin lazima athibitishe kabla ya kuweka subscription active.',
    payment
  });
}));

app.post('/api/super/payments/:id/verify', authMiddleware, requireSuperAdmin, asyncRoute(async (req, res) => {
  const status = String(req.body.status || '').toLowerCase();

  if (!['paid', 'rejected'].includes(status)) {
    fail(400, 'status lazima iwe paid au rejected.');
  }

  const payment = await one(
    `UPDATE payments
     SET status = $1, verified_at = CASE WHEN $1 = 'paid' THEN NOW() ELSE NULL END
     WHERE id = $2
     RETURNING *`,
    [status, req.params.id]
  );

  if (!payment) fail(404, 'Malipo hayajapatikana.');

  res.json({
    success: true,
    payment,
    message: 'Hali ya malipo imesasishwa. Subscription haibadilishwi moja kwa moja na endpoint hii.'
  });
}));

const unverifiedGatewayWebhook = provider => asyncRoute(async (req, res) => {
  res.status(501).json({
    success: false,
    code: 'GATEWAY_NOT_CONFIGURED',
    provider,
    message: `Webhook ya ${provider} bado haijaunganishwa na uthibitishaji rasmi wa signature na transaction. Hakuna malipo yaliyothibitishwa.`
  });
});

app.post('/api/payments/azampay/webhook', unverifiedGatewayWebhook('AzamPay'));
app.post('/api/payments/clickpesa/webhook', unverifiedGatewayWebhook('ClickPesa'));
app.post('/api/payments/selcom/webhook', unverifiedGatewayWebhook('Selcom'));
app.post('/api/payments/pesapal/webhook', unverifiedGatewayWebhook('Pesapal'));
app.post('/api/payments/palmpesa/webhook', unverifiedGatewayWebhook('PalmPesa'));
app.post('/api/payments/beem/webhook', unverifiedGatewayWebhook('Beem'));

/* =========================
   DASHBOARD SUMMARY
========================= */

app.get('/api/dashboard/:tenant_id', authMiddleware, asyncRoute(async (req, res) => {
  const tenantId = req.params.tenant_id;
  ensureTenantAccess(req, tenantId);

  const tenant = await getTenantRecord(tenantId);

  const counts = await one(
    `SELECT
      (SELECT COUNT(*)::int FROM clients WHERE tenant_id = $1) AS clients,
      (SELECT COUNT(*)::int FROM devices WHERE tenant_id = $1) AS devices,
      (SELECT COUNT(*)::int FROM sites WHERE tenant_id = $1) AS sites,
      (SELECT COUNT(*)::int FROM packages WHERE tenant_id = $1) AS packages,
      (SELECT COUNT(*)::int FROM vouchers WHERE tenant_id = $1) AS vouchers`,
    [tenantId]
  );

  const paymentTotals = await one(
    `SELECT
       COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END),0)::numeric AS paid_total,
       COALESCE(SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END),0)::numeric AS pending_total
     FROM payments WHERE tenant_id = $1`,
    [tenantId]
  );

  res.json({
    success: true,
    tenant: publicTenant(tenant),
    counts,
    payments: paymentTotals,
    plans: PLANS
  });
}));

/* =========================
   FRONTEND / ERROR HANDLING
========================= */

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/*', (req, res) => {
  res.status(404).json({ success: false, message: 'API endpoint haijapatikana.' });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  const status = err.status || 500;

  if (status >= 500) {
    console.error('[SERVER ERROR]', err.message);
  }

  res.status(status).json({
    success: false,
    message: status >= 500
      ? 'Hitilafu ya ndani ya server. Kagua logs na database configuration.'
      : err.message
  });
});

async function startServer() {
  try {
    await db.ready;

    if (!db.pool || typeof db.pool.query !== 'function') {
      throw new Error('database.js lazima itoe pool.query na ready.');
    }

    await db.pool.query('SELECT 1');

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`MR HAAS WISP backend inaendesha kwenye port ${PORT}`);
      console.log(`Environment: ${IS_PRODUCTION ? 'production' : 'development'}`);
    });
  } catch (error) {
    console.error('Server haikuweza kuanza:', error.message);
    process.exit(1);
  }
}

startServer();

module.exports = app;
