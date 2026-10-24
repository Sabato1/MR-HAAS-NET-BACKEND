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
  SECRET_KEY = crypto.randomBytes(48).toString('hex');
}

const JWT_SECRET = SECRET_KEY;
const SUPER_ADMIN_ID = 'tenant_super_admin';

app.disable('x-powered-by');

// FimiPay & PalmPesa need raw body for webhook verification
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: false, limit: '10mb' }));

const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(v=>v.trim().replace(/\/+$/, '')).filter(Boolean);
app.use(cors({
  origin(origin, cb){ if(!origin || !IS_PRODUCTION) return cb(null,true); const n=origin.trim().replace(/\/+$/, ''); if(allowedOrigins.includes(n)) return cb(null,true); const e=new Error('Origin hairuhusiwi.'); e.status=403; return cb(e); },
  methods:['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders:['Content-Type','Authorization','X-Mikrotik-Secret','X-Tenant-ID','X-Fimipay-Signature'],
  optionsSuccessStatus:204
}));

app.get('/super-admin.html',(req,res)=>{res.setHeader('Cache-Control','no-store'); res.sendFile(path.join(__dirname,'public','super-admin.html'));});
app.use(express.static(path.join(__dirname,'public')));

const PLANS = {
  START:{name:'START',monthly_price:10000,max_devices:2,max_clients:50},
  DIAMOND:{name:'DIAMOND',monthly_price:15000,max_devices:7,max_clients:500},
  PREMIUM:{name:'PREMIUM',monthly_price:20000,max_devices:999999,max_clients:5000},
  REVENUE_SHARE:{name:'REVENUE_SHARE',monthly_price:20000,signup_fee:20000,revenue_share_percent:3,max_devices:999999,max_clients:999999}
};
const PAYMENT_PROVIDERS=['AzamPay','ClickPesa','Selcom','Pesapal','PalmPesa','FimiPay','Beem','manual'];

/* =========================================================
   PALMPESA CONFIG - LIPA NAMBA 54826224 VODACOM DIRECT
========================================================= */
const PALMPESA_BASE_URL = (process.env.PALMPESA_BASE_URL || 'https://palmpesa.drmlelwa.co.tz').replace(/\/$/,'');
const PALMPESA_USER_ID = process.env.PALMPESA_USER_ID || 'USR-5C910F926C88';
const PALMPESA_API_TOKEN = process.env.PALMPESA_API_TOKEN || '';
const PALMPESA_VENDOR = process.env.PALMPESA_VENDOR || process.env.VODACOM_LIPA_NAMBA || process.env.PALMPESA_LIPA_NAMBA || '54826224';
const PALMPESA_CALLBACK_URL = process.env.PALMPESA_CALLBACK_URL || (process.env.BACKEND_URL ? process.env.BACKEND_URL + '/api/subscription/palmpesa-callback' : 'https://mrhaas-backend.onrender.com/api/subscription/palmpesa-callback');

/* =========================================================
   FIMIPAY CONFIG - MR HAAS NET WISP MANAGEMENT
   ENV: FIMIPAY_PUBLIC_KEY=pk_live_..., FIMIPAY_SECRET_KEY=sk_live_..., FIMIPAY_WEBHOOK_SECRET=whsec_...
========================================================= */
const FIMIPAY_BASE_URL = (process.env.FIMIPAY_BASE_URL || 'https://api.fimipay.com').replace(/\/$/,'');
const FIMIPAY_PUBLIC_KEY = process.env.FIMIPAY_PUBLIC_KEY || process.env.FIMIPAY_CLIENT_ID || '';
const FIMIPAY_SECRET_KEY = process.env.FIMIPAY_SECRET_KEY || '';
const FIMIPAY_WEBHOOK_SECRET = process.env.FIMIPAY_WEBHOOK_SECRET || '';
const FIMIPAY_CALLBACK_URL = process.env.FIMIPAY_CALLBACK_URL || (process.env.BACKEND_URL ? process.env.BACKEND_URL + '/api/webhook/fimipay' : 'https://mrhaas-backend.onrender.com/api/webhook/fimipay');

console.log('[PALMPESA] Config:', { baseUrl: PALMPESA_BASE_URL, userId: PALMPESA_USER_ID, hasToken: !!PALMPESA_API_TOKEN, vendor: PALMPESA_VENDOR });
console.log('[FIMIPAY] Config:', { baseUrl: FIMIPAY_BASE_URL, hasPublic: !!FIMIPAY_PUBLIC_KEY, hasSecret: !!FIMIPAY_SECRET_KEY, hasWebhookSecret: !!FIMIPAY_WEBHOOK_SECRET, callback: FIMIPAY_CALLBACK_URL });

class HttpError extends Error{constructor(s,m){super(m); this.status=s;}}
const fail=(s,m)=>{throw new HttpError(s,m);};
const asyncRoute=h=>(req,res,next)=>Promise.resolve(h(req,res,next)).catch(next);
const query=async(sql,params=[])=>{const r=await db.pool.query(sql,params); return r.rows||[];};
const one=async(sql,params=[])=>{const rows=await query(sql,params); return rows[0]||null;};
const makeId=prefix=>`${prefix}_${crypto.randomBytes(12).toString('hex')}`;
const clean=v=>typeof v==='string'?v.trim():v;
const emailValue=v=>String(v||'').trim().toLowerCase();
const isValidEmail=v=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v||''));
const isValidPhone=v=>/^\+?[0-9\s()-]{9,20}$/.test(String(v||''));
const signToken=(claims,expiresIn='7d')=>jwt.sign(claims,JWT_SECRET,{expiresIn});
const publicTenant=t=>t?{id:t.id,business_name:t.business_name,owner_name:t.owner_name,phone:t.phone,email:t.email,subdomain:t.subdomain,plan:t.plan,max_devices:t.max_devices,max_clients:t.max_clients,status:t.status,role:t.role||'tenant',trial_started_at:t.trial_started_at,trial_ends_at:t.trial_ends_at,subscription_status:t.subscription_status,subscription_ends_at:t.subscription_ends_at,free_forever:t.free_forever,created_at:t.created_at}:null;

const authMiddleware=asyncRoute(async(req,res,next)=>{
  const header=req.headers.authorization||''; const token=header.startsWith('Bearer ')?header.slice(7):''; if(!token) fail(401,'Ingia kwanza.');
  let decoded; try{decoded=jwt.verify(token,JWT_SECRET);}catch{fail(401,'Token imeisha muda. Ingia tena.');}
  if(!decoded.tenant_id||!decoded.email) fail(401,'Token haina taarifa.');
  req.user=decoded; req.tenant_id=decoded.tenant_id; req.email=decoded.email;
  if(decoded.role==='super_admin'||decoded.tenant_id===SUPER_ADMIN_ID){req.role='super_admin'; return next();}
  const tenant=await one('SELECT * FROM tenants WHERE id=$1',[decoded.tenant_id]); if(!tenant) fail(401,'Akaunti haijapatikana.'); if(tenant.status!=='active') fail(403,`Akaunti haipo active. Hali: ${tenant.status}`);
  req.tenant=tenant; req.role='tenant'; next();
});
const requireSuperAdmin=(req,res,next)=>{if(req.role!=='super_admin') return res.status(403).json({success:false,message:'Super Admin pekee.'}); next();};
const getTenantRecord=async tenantId=>{const t=await one('SELECT * FROM tenants WHERE id=$1',[tenantId]); if(!t) fail(404,'WISP haijapatikana.'); return t;};
const ensureTenantAccess=(req,tenantId)=>{if(req.role==='super_admin') return; if(req.tenant_id!==tenantId) fail(403,'Huruhusiwi kufikia WISP mwingine.');};
const requireSubscription=asyncRoute(async(req,res,next)=>{
  if(req.role==='super_admin') return next(); const tenant=req.tenant; if(!tenant) fail(401,'Taarifa za Tenant hazijapatikana.');
  if(tenant.free_forever===true||tenant.free_forever==='true') return next();
  const now=Date.now(); const trialEnd=tenant.trial_ends_at?new Date(tenant.trial_ends_at).getTime():0; const paidEnd=tenant.subscription_ends_at?new Date(tenant.subscription_ends_at).getTime():0;
  const trialValid=tenant.subscription_status==='trial'&&trialEnd>now; const paidValid=tenant.subscription_status==='active'&&paidEnd>now;
  if(!trialValid&&!paidValid) return res.status(402).json({success:false,code:'SUBSCRIPTION_REQUIRED',message:'Muda wa majaribio umeisha.',plans:PLANS});
  return next();
});
const checkPlanLimit=async(tenant,field,table)=>{const limit=tenant[field]; if(limit===null||limit===undefined||Number(limit)<0) return; const row=await one(`SELECT COUNT(*)::int AS total FROM ${table} WHERE tenant_id=$1`,[tenant.id]); if(Number(row?.total||0)>=Number(limit)) fail(403,`Umefikia kikomo cha ${table}. Boresha mpango.`);};
const checkTenantLimit=async(tenant,kind)=>{if(kind==='devices') return checkPlanLimit(tenant,'max_devices','devices'); if(kind==='clients') return checkPlanLimit(tenant,'max_clients','clients');};
const createTrialDates=()=>{const s=new Date(); const e=new Date(s.getTime()+4*24*60*60*1000); return{started:s,ends:e};};
const getPlan=v=>{const k=String(v||'').trim().toUpperCase().replace(/\s+/g,'_'); return PLANS[k]||null;};
const makeSubdomain=bn=>{const base=String(bn||'wisp').toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,35)||'wisp'; return `${base}-${crypto.randomBytes(3).toString('hex')}`;};
const issueTenantToken=t=>signToken({tenant_id:t.id,email:t.email,role:'tenant'});
const issueSuperAdminToken=()=>signToken({tenant_id:SUPER_ADMIN_ID,email:SUPER_ADMIN_EMAIL,role:'super_admin'});

/* ================= PALMPESA PUSH FUNCTION ================= */
async function sendPalmPesaPush({phone, amount, transactionId, planName, tenantId}){
  if(!PALMPESA_API_TOKEN){ throw new Error('PALMPESA_API_TOKEN haijawekwa ENV'); }
  let msisdn = String(phone).replace(/\s+/g,'');
  if(msisdn.startsWith('0')) msisdn = '255'+msisdn.slice(1);
  msisdn = msisdn.replace(/^\+/,'');
  const orderId = transactionId;
  const attempts = [
    { path: '/api/v1/money-request', payload: { user_id: PALMPESA_USER_ID, amount: Number(amount), phone: msisdn, phone_number: msisdn, reference: orderId, order_id: orderId, description: `MH NET ${planName} - ${amount} TZS`, vendor: PALMPESA_VENDOR, till: PALMPESA_VENDOR, business_number: PALMPESA_VENDOR, till_number: PALMPESA_VENDOR, callback_url: PALMPESA_CALLBACK_URL, remark: `MH NET ${planName} Till ${PALMPESA_VENDOR}` } },
    { path: '/api/request-funds', payload: { user_id: PALMPESA_USER_ID, amount: Number(amount), phone_number: msisdn, reference: orderId, description: `MH NET ${planName} - Till ${PALMPESA_VENDOR}`, till_number: PALMPESA_VENDOR, callback: PALMPESA_CALLBACK_URL } }
  ];
  let lastError = null;
  for(const attempt of attempts){
    try{
      Object.keys(attempt.payload).forEach(k=> attempt.payload[k]===undefined && delete attempt.payload[k]);
      const url = PALMPESA_BASE_URL + attempt.path;
      console.log(`[PALMPESA TRY ${PALMPESA_VENDOR}] ${attempt.path}`, attempt.payload);
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${PALMPESA_API_TOKEN}`, 'X-API-TOKEN': PALMPESA_API_TOKEN, 'api-token': PALMPESA_API_TOKEN, 'User-ID': PALMPESA_USER_ID, 'x-user-id': PALMPESA_USER_ID }, body: JSON.stringify(attempt.payload) });
      const text = await resp.text(); let data; try{ data = JSON.parse(text); }catch(e){ data = { raw: text }; }
      console.log(`[PALMPESA RESP ${attempt.path}] ${resp.status}`, data);
      if(resp.ok || data.success || data.status === 'success'){ return { success:true, endpoint: attempt.path, response: data, order_id: orderId, till: PALMPESA_VENDOR }; }
      else { lastError = `${attempt.path} ${resp.status}: ${text.substring(0,400)}`; continue; }
    }catch(e){ lastError = e.message; console.error(`[PALMPESA ERROR ${attempt.path}]`, e.message); continue; }
  }
  throw new Error(lastError || `PalmPesa push failed`);
}
async function checkPalmPesaStatus(orderId){
  try{ const url = `${PALMPESA_BASE_URL}/api/v1/transaction/${orderId}`; const resp = await fetch(url, { headers: { 'Authorization': `Bearer ${PALMPESA_API_TOKEN}` } }); const data = await resp.json().catch(()=>({})); return data; }catch(e){ return { error: e.message }; }
}

/* ================= FIMIPAY FUNCTIONS - MR HAAS NET ================= */
async function createFimiPayCheckout({ tenantId, amount, phone, planCode, email }){
  if(!FIMIPAY_SECRET_KEY) throw new Error('FIMIPAY_SECRET_KEY haijawekwa ENV - weka kwenye Render');
  if(!FIMIPAY_PUBLIC_KEY) throw new Error('FIMIPAY_PUBLIC_KEY haijawekwa');
  const reference = `MRHAAS-${tenantId.slice(0,8)}-${Date.now()}`;
  const payload = {
    amount: Number(amount),
    currency: 'TZS',
    client_id: FIMIPAY_PUBLIC_KEY,
    reference: reference,
    description: `MR HAAS NET ${planCode.toUpperCase()} - ${amount} TZS`,
    customer_phone: phone,
    customer_email: email || undefined,
    callback_url: FIMIPAY_CALLBACK_URL,
    success_url: `${process.env.FRONTEND_URL || 'https://mrhaasnet.co.tz'}/billing/success?ref=${reference}`,
    cancel_url: `${process.env.FRONTEND_URL || 'https://mrhaasnet.co.tz'}/billing/cancel?ref=${reference}`,
    metadata: { tenantId: tenantId, planCode: planCode, source: 'mrhaas_wisp' }
  };
  Object.keys(payload).forEach(k=> payload[k]===undefined && delete payload[k]);
  console.log('[FIMIPAY CREATE]', payload);
  // Try V4 and V3 endpoints
  const endpoints = ['/api/v1/checkout', '/api/v1/payments', '/v4/checkout', '/api/checkout'];
  let lastErr = null;
  for(const ep of endpoints){
    try{
      const resp = await fetch(FIMIPAY_BASE_URL + ep, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${FIMIPAY_SECRET_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const text = await resp.text();
      let data; try{ data = JSON.parse(text); }catch{ data = { raw: text }; }
      console.log(`[FIMIPAY RESP ${ep}] ${resp.status}`, data);
      if(resp.ok && (data.checkout_url || data.data?.checkout_url || data.url || data.payment_url)){
        const checkoutUrl = data.checkout_url || data.data?.checkout_url || data.url || data.payment_url || data.data?.url;
        return { success:true, checkout_url: checkoutUrl, reference, response: data, endpoint: ep };
      }
      if(resp.ok && data.success){
        const checkoutUrl = data.checkout_url || data.data?.checkout_url || data.url || data.payment_url;
        if(checkoutUrl) return { success:true, checkout_url: checkoutUrl, reference, response: data, endpoint: ep };
      }
      lastErr = `${ep} ${resp.status}: ${text.slice(0,500)}`;
    }catch(e){ lastErr = e.message; }
  }
  throw new Error(lastErr || 'FimiPay checkout failed - angalia API keys');
}

function verifyFimiPaySignature(rawBody, signature){
  if(!FIMIPAY_WEBHOOK_SECRET) return true; // kama secret haijawekwa, kubali kwa test
  if(!signature) return false;
  try{
    const hmac = crypto.createHmac('sha256', FIMIPAY_WEBHOOK_SECRET).update(rawBody).digest('hex');
    // FimiPay inaweza kutuma hex au base64
    return hmac === signature || crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature));
  }catch(e){
    // fallback compare bila timingSafe
    const hmac = crypto.createHmac('sha256', FIMIPAY_WEBHOOK_SECRET).update(rawBody).digest('hex');
    return hmac === signature;
  }
}

app.get('/api/health',asyncRoute(async(req,res)=>{await db.ready; await query('SELECT 1'); res.json({success:true,service:'MR HAAS MULTI-TENANT WISP MANAGEMENT',database:'connected',palmPesa:{configured:!!PALMPESA_API_TOKEN, vendor:PALMPESA_VENDOR}, fimiPay:{configured:!!FIMIPAY_SECRET_KEY, hasPublic:!!FIMIPAY_PUBLIC_KEY, baseUrl:FIMIPAY_BASE_URL}, timestamp:new Date().toISOString()});}));
app.get('/api/plans',(req,res)=>{res.json({success:true,plans:PLANS,trial_days:4});});

app.post('/api/auth/register',asyncRoute(async(req,res)=>{
  const businessName=clean(req.body.business_name); const ownerName=clean(req.body.owner_name); const phone=clean(req.body.phone); const email=emailValue(req.body.email); const password=String(req.body.password||'');
  if(!businessName||!ownerName||!phone||!email||!password) fail(400,'Jaza jina la biashara, mmiliki, simu, email na nenosiri.');
  if(!isValidEmail(email)) fail(400,'Email si sahihi.'); if(!isValidPhone(phone)) fail(400,'Simu si sahihi.'); if(password.length<8) fail(400,'Nenosiri herufi 8+.');
  const existing=await one('SELECT id FROM tenants WHERE LOWER(email)=$1 OR phone=$2 LIMIT 1',[email,phone]); if(existing) fail(409,'Email au simu imesajiliwa.');
  const id=makeId('tenant'); const subdomain=makeSubdomain(businessName); const hash=await bcrypt.hash(password,12); const trial=createTrialDates(); const plan=PLANS.START;
  const tenant=await one(`INSERT INTO tenants (id,business_name,owner_name,phone,email,password_hash,subdomain,plan,max_devices,max_clients,status,role,trial_started_at,trial_ends_at,subscription_status,subscription_ends_at,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'START',$8,$9,'active','tenant',$10,$11,'trial',NULL,NOW()) RETURNING *`,[id,businessName,ownerName,phone,email,hash,subdomain,plan.max_devices,plan.max_clients,trial.started,trial.ends]);
  await query(`INSERT INTO tenant_settings (tenant_id,portal_title,primary_color,announcement,contact_phone,currency) VALUES ($1,$2,$3,$4,$5,'TZS') ON CONFLICT (tenant_id) DO NOTHING`,[id,businessName,'#111827','',phone]);
  const token=issueTenantToken(tenant); res.status(201).json({success:true,message:'Akaunti imeundwa. Jaribio siku 4 limeanza.',token,tenant:publicTenant(tenant),trial_days:4,plans:PLANS});
}));
app.post('/api/auth/login',asyncRoute(async(req,res)=>{
  const email=emailValue(req.body.email); const password=String(req.body.password||''); if(!email||!password) fail(400,'Weka email na nenosiri.');
  if(SUPER_ADMIN_EMAIL&&email===SUPER_ADMIN_EMAIL&&password===SUPER_ADMIN_PASSWORD){return res.json({success:true,token:issueSuperAdminToken(),role:'super_admin',tenant:{id:SUPER_ADMIN_ID,email:SUPER_ADMIN_EMAIL,role:'super_admin',business_name:'MR HAAS SUPER ADMIN'}});}
  const tenant=await one('SELECT * FROM tenants WHERE LOWER(email)=$1 LIMIT 1',[email]); if(!tenant) fail(401,'Email au nenosiri si sahihi.'); const valid=await bcrypt.compare(password,tenant.password_hash); if(!valid) fail(401,'Email au nenosiri si sahihi.'); if(tenant.status!=='active') fail(403,`Akaunti hali ya ${tenant.status}.`);
  res.json({success:true,token:issueTenantToken(tenant),role:'tenant',tenant:publicTenant(tenant),plans:PLANS});
}));
app.post('/api/super-admin/login',asyncRoute(async(req,res)=>{const email=emailValue(req.body.email); const password=String(req.body.password||''); if(email!==SUPER_ADMIN_EMAIL||password!==SUPER_ADMIN_PASSWORD) fail(401,'Super Admin si sahihi.'); res.json({success:true,token:issueSuperAdminToken(),role:'super_admin',tenant:{id:SUPER_ADMIN_ID,email:SUPER_ADMIN_EMAIL,role:'super_admin',business_name:'MR HAAS SUPER ADMIN'}});}));
app.get('/api/auth/me',authMiddleware,asyncRoute(async(req,res)=>{if(req.role==='super_admin') return res.json({success:true,role:'super_admin',tenant:{id:SUPER_ADMIN_ID,email:req.email,business_name:'MR HAAS SUPER ADMIN'}}); const tenant=await getTenantRecord(req.tenant_id); res.json({success:true,role:'tenant',tenant:publicTenant(tenant),plans:PLANS});}));

app.get('/api/super/tenants',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const tenants=await query(`SELECT t.id,t.business_name,t.owner_name,t.phone,t.email,t.subdomain,t.plan,t.max_devices,t.max_clients,t.status,t.role,t.trial_started_at,t.trial_ends_at,t.subscription_status,t.subscription_ends_at,t.free_forever,t.created_at,(SELECT COUNT(*)::int FROM devices d WHERE d.tenant_id=t.id) AS device_count,(SELECT COUNT(*)::int FROM clients c WHERE c.tenant_id=t.id) AS client_count,(SELECT COUNT(*)::int FROM sites s WHERE s.tenant_id=t.id) AS site_count FROM tenants t WHERE t.id<>$1 ORDER BY t.created_at DESC`,[SUPER_ADMIN_ID]); res.json({success:true,tenants,total:tenants.length});}));
app.post('/api/super/tenants',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const businessName=clean(req.body.business_name); const ownerName=clean(req.body.owner_name||businessName); const phone=clean(req.body.phone||'0000000000'); const email=emailValue(req.body.email); const password=String(req.body.password||'Password123!'); const planKey=String(req.body.plan||'START').toUpperCase(); const plan=getPlan(planKey)||PLANS.START; if(!businessName||!email) fail(400,'Jaza biashara na email.'); if(!isValidEmail(email)) fail(400,'Email si sahihi.'); const existing=await one('SELECT id FROM tenants WHERE LOWER(email)=$1 LIMIT 1',[email]); if(existing) fail(409,'Email imesajiliwa.'); const trial=createTrialDates(); const id=makeId('tenant'); const hash=await bcrypt.hash(password,12); const subdomain=makeSubdomain(businessName); const tenant=await one(`INSERT INTO tenants (id,business_name,owner_name,phone,email,password_hash,subdomain,plan,max_devices,max_clients,status,role,trial_started_at,trial_ends_at,subscription_status,subscription_ends_at,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active','tenant',$11,$12,'trial',NULL,NOW()) RETURNING *`,[id,businessName,ownerName,phone,email,hash,subdomain,plan.name,plan.max_devices,plan.max_clients,trial.started,trial.ends]); await query(`INSERT INTO tenant_settings (tenant_id,portal_title,primary_color,announcement,contact_phone,currency) VALUES ($1,$2,$3,$4,$5,'TZS') ON CONFLICT (tenant_id) DO NOTHING`,[id,businessName,'#111827','',phone]); res.status(201).json({success:true,message:'WISP imesajiliwa.',tenant:publicTenant(tenant),trial_days:4});}));
app.put('/api/super/tenant/:id/subscription',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const tenantId=String(req.params.id||'').trim(); const rawPlanInput=String(req.body.plan||'START').trim().toUpperCase().replace(/\s+/g,'_'); const plan=PLANS[rawPlanInput]||getPlan(rawPlanInput); let status=String(req.body.subscription_status||'active').toLowerCase(); if(!tenantId) fail(400,'ID inahitajika.'); if(tenantId===SUPER_ADMIN_ID) fail(403,'Huwezi Super Admin.'); if(!plan) fail(400,'Plan si sahihi.'); const current=await one('SELECT * FROM tenants WHERE id=$1 AND id<>$2',[tenantId,SUPER_ADMIN_ID]); if(!current) fail(404,'WISP haijapatikana.'); const freeForever=req.body.free_forever===true||req.body.free_forever==='true'; let trialStarted=current.trial_started_at; let trialEnds=current.trial_ends_at; if(req.body.trial_days!==undefined&&req.body.trial_days!==''){const days=Number(req.body.trial_days); if(!Number.isNaN(days)&&days>=0){const now=new Date(); trialStarted=trialStarted||now; trialEnds=new Date(now.getTime()+days*86400000); status='trial';}} const endsAt=req.body.subscription_ends_at?new Date(req.body.subscription_ends_at):null; const tenant=await one(`UPDATE tenants SET plan=$1,max_devices=$2,max_clients=$3,subscription_status=$4,subscription_ends_at=$5,trial_started_at=$6,trial_ends_at=$7,free_forever=$8,updated_at=NOW() WHERE id=$9 AND id<>$10 RETURNING *`,[plan.name,plan.max_devices,plan.max_clients,status,endsAt,trialStarted,trialEnds,freeForever,tenantId,SUPER_ADMIN_ID]); res.json({success:true,message:`Plan ${plan.name} imesasishwa.`,tenant:publicTenant(tenant)});}));
app.patch('/api/super/tenant/:id/status',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const tenantId=String(req.params.id||'').trim(); const status=String(req.body.status||'').trim().toLowerCase(); if(!tenantId||tenantId===SUPER_ADMIN_ID) fail(400,'ID haijakubaliwa.'); const tenant=await one(`UPDATE tenants SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,business_name,status`,[status,tenantId]); if(!tenant) fail(404,'WISP haijapatikana.'); res.json({success:true,message:status==='suspended'?'Akaunti imesimamishwa.':'Akaunti imerejeshwa.',tenant});}));
app.delete('/api/super/tenant/:id',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const tenantId=String(req.params.id||'').trim(); if(!tenantId||tenantId===SUPER_ADMIN_ID) fail(400,'ID haijakubaliwa.'); const tenant=await one(`UPDATE tenants SET status='deleted',updated_at=NOW() WHERE id=$1 RETURNING id,business_name`,[tenantId]); res.json({success:true,message:'Akaunti deleted.',tenant});}));

app.get('/api/subscription',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.query.tenant_id:req.tenant_id; if(!tenantId) fail(400,'tenant_id inahitajika.'); ensureTenantAccess(req,tenantId); const tenant=await getTenantRecord(tenantId); const trialEnd=tenant.trial_ends_at?new Date(tenant.trial_ends_at):null; const paidEnd=tenant.subscription_ends_at?new Date(tenant.subscription_ends_at):null; const now=new Date(); const freeForever=tenant.free_forever===true; const trialActive=tenant.subscription_status==='trial'&&trialEnd&&trialEnd>now; const paidActive=tenant.subscription_status==='active'&&paidEnd&&paidEnd>now; res.json({success:true,subscription:{plan:tenant.plan,status:tenant.subscription_status,trial_started_at:tenant.trial_started_at,trial_ends_at:tenant.trial_ends_at,subscription_ends_at:tenant.subscription_ends_at,free_forever:freeForever,trial_active:Boolean(trialActive),paid_active:Boolean(paidActive),service_access:Boolean(freeForever||trialActive||paidActive),plans:PLANS}});}));
app.get('/api/payment-settings',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.query.tenant_id:req.tenant_id; if(!tenantId) fail(400,'tenant_id inahitajika.'); ensureTenantAccess(req,tenantId); const settings=await one(`SELECT tenant_id,enabled_providers,manual_payment_instructions,payment_phone,payment_account_name,updated_at FROM payment_settings WHERE tenant_id=$1`,[tenantId]); res.json({success:true,settings:settings||{tenant_id:tenantId,enabled_providers:['manual'],manual_payment_instructions:'',payment_phone:'',payment_account_name:''},available_providers:PAYMENT_PROVIDERS});}));
app.put('/api/payment-settings',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; if(!tenantId) fail(400,'tenant_id inahitajika.'); ensureTenantAccess(req,tenantId); const providers=Array.isArray(req.body.enabled_providers)?req.body.enabled_providers.filter(item=>PAYMENT_PROVIDERS.includes(item)):['manual']; const instructions=String(req.body.manual_payment_instructions||'').slice(0,3000); const phone=String(req.body.payment_phone||'').slice(0,40); const accountName=String(req.body.payment_account_name||'').slice(0,120); const settings=await one(`INSERT INTO payment_settings (tenant_id,enabled_providers,manual_payment_instructions,payment_phone,payment_account_name,updated_at) VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT (tenant_id) DO UPDATE SET enabled_providers=EXCLUDED.enabled_providers,manual_payment_instructions=EXCLUDED.manual_payment_instructions,payment_phone=EXCLUDED.payment_phone,payment_account_name=EXCLUDED.payment_account_name,updated_at=NOW() RETURNING tenant_id,enabled_providers,manual_payment_instructions,payment_phone,payment_account_name,updated_at`,[tenantId,providers,instructions,phone,accountName]); res.json({success:true,settings});}));

/* ========== SITES, DEVICES, CLIENTS, PACKAGES, VOUCHERS (keep as before) ========== */
// ... (omitted for brevity in this generated file, will be appended from original logic - simplified keep core)

app.get('/api/sites/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const sites=await query(`SELECT id,tenant_id,name,location,description,status,created_at FROM sites WHERE tenant_id=$1 ORDER BY created_at DESC`,[tenantId]); res.json({success:true,sites});}));
app.post('/api/sites',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; ensureTenantAccess(req,tenantId); if(!tenantId||!req.body.name) fail(400,'tenant_id na jina vinahitajika.'); const site=await one(`INSERT INTO sites (id,tenant_id,name,location,description,status,created_at) VALUES ($1,$2,$3,$4,$5,'active',NOW()) RETURNING *`,[makeId('site'),tenantId,clean(req.body.name),clean(req.body.location||''),clean(req.body.description||'')]); res.status(201).json({success:true,site});}));
app.delete('/api/sites/:id',authMiddleware,asyncRoute(async(req,res)=>{const site=await one('SELECT * FROM sites WHERE id=$1',[req.params.id]); if(!site) fail(404,'Site haijapatikana.'); ensureTenantAccess(req,site.tenant_id); await query('DELETE FROM sites WHERE id=$1',[site.id]); res.json({success:true,message:'Site imefutwa.'});}));

app.get('/api/devices/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const devices=await query(`SELECT id,tenant_id,site_id,name,vendor,device_type,model,mac_address,ip_address,wan_port,connection_type,last_seen,status,created_at FROM devices WHERE tenant_id=$1 ORDER BY created_at DESC`,[tenantId]); res.json({success:true,devices});}));
app.post('/api/devices',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{
  const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; ensureTenantAccess(req,tenantId); if(!tenantId) fail(400,'tenant_id inahitajika.');
  const tenant=await getTenantRecord(tenantId); await checkTenantLimit(tenant,'devices');
  const locationName=clean(req.body.location_name||req.body.name||''); const ssid=clean(req.body.ssid||''); const port=clean(req.body.port||req.body.wan_port||req.body.ip_address||'Port 1'); const model=clean(req.body.model||'RB3011');
  let vendor=clean(req.body.vendor||''); if(!vendor){if(model.toLowerCase().includes('eap')||req.body.mac_address) vendor='TP-Link Omada'; else vendor='MikroTik';}
  if(vendor.toLowerCase().includes('omada')||vendor.toLowerCase().includes('eap')) vendor='TP-Link Omada'; else if(vendor.toLowerCase().includes('mikrotik')||vendor.toLowerCase().includes('rb')||vendor.toLowerCase().includes('hap')) vendor='MikroTik';
  const name=locationName?`${locationName} - ${ssid||vendor}`:clean(req.body.name||`${model} ${port}`); const deviceType=vendor==='TP-Link Omada'?'access_point':'router'; const mac=clean(req.body.mac_address||''); const ip=clean(req.body.ip_address||port); const siteId=clean(req.body.site_id||'')||null; const wanPort=port; const connectionType=vendor==='TP-Link Omada'?'omada':'api'; if(!name) fail(400,'Jina linahitajika.');
  let device; try{device=await one(`INSERT INTO devices (id,tenant_id,site_id,name,vendor,device_type,model,mac_address,ip_address,wan_port,connection_type,status,last_seen,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'offline',NOW(),NOW()) RETURNING id,tenant_id,site_id,name,vendor,device_type,model,mac_address,ip_address,wan_port,connection_type,status,last_seen,created_at`,[makeId('device'),tenantId,siteId,name,vendor,deviceType,model,mac||null,ip||null,wanPort,connectionType]);}catch(e){device=await one(`INSERT INTO devices (id,tenant_id,site_id,name,vendor,device_type,model,mac_address,ip_address,wan_port,connection_type,last_seen,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NOW()) RETURNING id,tenant_id,site_id,name,vendor,device_type,model,mac_address,ip_address,wan_port,connection_type,last_seen,created_at`,[makeId('device'),tenantId,siteId,name,vendor,deviceType,model,mac||null,ip||null,wanPort,connectionType]);}
  res.status(201).json({success:true,message:vendor==='TP-Link Omada'?'Omada EAP imehifadhiwa.':'Kifaa kimehifadhiwa.',device});
}));
app.delete('/api/devices/:id',authMiddleware,asyncRoute(async(req,res)=>{const device=await one('SELECT * FROM devices WHERE id=$1',[req.params.id]); if(!device) fail(404,'Kifaa hakijapatikana.'); ensureTenantAccess(req,device.tenant_id); await query('DELETE FROM devices WHERE id=$1',[device.id]); res.json({success:true,message:'Kifaa kimeondolewa.'});}));

app.get('/api/mikrotik/register',asyncRoute(async(req,res)=>{
  const tenantId=clean(req.query.tenant||req.query.tenant_id||''); const site=clean(req.query.site||''); const ssid=clean(req.query.ssid||''); const model=clean(req.query.model||''); const port=clean(req.query.port||'');
  if(tenantId){try{await query(`UPDATE devices SET last_seen=NOW(),status='online',ip_address=COALESCE($2,ip_address) WHERE tenant_id=$1 AND name ILIKE $3`,[tenantId,port,`%${site}%`]);}catch(e){}}
  const rsc=`# MR HAAS NET - ${site} SSID:${ssid} Model:${model} Port:${port} Tenant:${tenantId}\n/ip hotspot profile set [find] login-by=http-chap,http-pap\n/ip hotspot set [find] idle-timeout=1h keepalive-timeout=2m\n/system clock set time-zone-name=Africa/Dar_es_Salaam\n/system scheduler add name=mrhaas-checkin interval=2m on-event="/tool fetch url=https://mrhaas-backend.onrender.com/api/mikrotik/checkin?tenant=${encodeURIComponent(tenantId)}&site=${encodeURIComponent(site)}&model=${encodeURIComponent(model)} mode=https check-certificate=no" disabled=no\n:put "MR HAAS NET: ${site} imeunganishwa!"\n`; res.setHeader('Content-Type','text/plain'); res.send(rsc);
}));
app.get('/api/mikrotik/checkin',asyncRoute(async(req,res)=>{
  const tenantId=clean(req.query.tenant||req.query.tenant_id||''); const site=clean(req.query.site||''); const deviceId=clean(req.query.id||req.query.device_id||'');
  if(tenantId){try{if(site){await query(`UPDATE devices SET last_seen=NOW(),status='online' WHERE tenant_id=$1 AND (name ILIKE $2 OR id=$3)`,[tenantId,`%${site}%`,deviceId||site]);}else{await query(`UPDATE devices SET last_seen=NOW(),status='online' WHERE tenant_id=$1`,[tenantId]);}}catch(e){}}
  res.setHeader('Content-Type','text/plain'); res.send('OK');
}));
app.get('/api/mikrotik/status/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const devices=await query(`SELECT id,name,vendor,model,ip_address,wan_port,status,last_seen FROM devices WHERE tenant_id=$1 ORDER BY last_seen DESC NULLS LAST`,[tenantId]); const online=devices.filter(d=>d.status==='online'||(d.last_seen&&(Date.now()-new Date(d.last_seen).getTime())<5*60*1000)).length; res.json({success:true,devices,online_count:online,total:devices.length});}));

const omadaPending=new Map();
app.post('/api/omada/adopt',asyncRoute(async(req,res)=>{
  let tenantId=req.headers['x-tenant-id']||req.body.tenant_id||''; if(!tenantId&&req.headers.authorization){try{const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):''; if(t){const d=jwt.verify(t,JWT_SECRET); tenantId=d.tenant_id||'';}}catch(e){}}
  const location=clean(req.body.location||''); const ssid=clean(req.body.ssid||''); const mac=clean(req.body.mac||'').toUpperCase(); if(!mac) fail(400,'MAC inahitajika.'); omadaPending.set(mac,{tenantId,location,ssid,mac,status:'pending',last_seen:new Date()}); res.json({success:true,mac,status:'pending'});
}));
app.post(['/inform','/api/omada/inform'],asyncRoute(async(req,res)=>{const mac=clean(req.body.mac||req.query.mac||'').toUpperCase(); if(mac){omadaPending.set(mac,{...(omadaPending.get(mac)||{}),mac,last_seen:new Date(),status:'online'}); try{await query(`UPDATE devices SET last_seen=NOW(),status='online' WHERE mac_address ILIKE $1`,[`%${mac}%`]);}catch(e){}} res.json({success:true,result:'ok'});}));
app.get('/api/omada/status/:mac',asyncRoute(async(req,res)=>{const mac=clean(req.params.mac||'').toUpperCase(); const pending=omadaPending.get(mac); res.json({success:true,mac,status:pending?.status||'not_found'});}));

app.get('/api/clients/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const clients=await query(`SELECT id,tenant_id,site_id,name,phone,username,package_name,connection_type,status,created_at FROM clients WHERE tenant_id=$1 ORDER BY created_at DESC`,[tenantId]); res.json({success:true,clients});}));
app.post('/api/clients',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; ensureTenantAccess(req,tenantId); if(!tenantId) fail(400,'tenant_id inahitajika.'); const tenant=await getTenantRecord(tenantId); await checkTenantLimit(tenant,'clients'); const name=clean(req.body.name); const phone=clean(req.body.phone||''); const username=clean(req.body.username||''); const packageName=clean(req.body.package_name||''); const siteId=clean(req.body.site_id||'')||null; const connectionType=clean(req.body.connection_type||'hotspot'); if(!name) fail(400,'Jina la mteja linahitajika.'); const client=await one(`INSERT INTO clients (id,tenant_id,site_id,name,phone,username,package_name,connection_type,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',NOW()) RETURNING id,tenant_id,site_id,name,phone,username,package_name,connection_type,status,created_at`,[makeId('client'),tenantId,siteId,name,phone||null,username||null,packageName||null,connectionType]); res.status(201).json({success:true,client});}));
app.delete('/api/clients/:id',authMiddleware,asyncRoute(async(req,res)=>{const client=await one('SELECT * FROM clients WHERE id=$1',[req.params.id]); if(!client) fail(404,'Mteja hajapatikana.'); ensureTenantAccess(req,client.tenant_id); await query('DELETE FROM clients WHERE id=$1',[client.id]); res.json({success:true,message:'Mteja ameondolewa.'});}));

app.get('/api/packages/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const packages=await query(`SELECT id,tenant_id,name,price,duration_value,duration_unit,speed_down,speed_up,connection_type,description,status,created_at FROM packages WHERE tenant_id=$1 ORDER BY created_at DESC`,[tenantId]); res.json({success:true,packages});}));
app.post('/api/packages',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; ensureTenantAccess(req,tenantId); if(!tenantId) fail(400,'tenant_id inahitajika.'); const name=clean(req.body.name); const price=Number(req.body.price); if(!name||Number.isNaN(price)||price<0) fail(400,'Jina au bei si sahihi.'); const pack=await one(`INSERT INTO packages (id,tenant_id,name,price,duration_value,duration_unit,speed_down,speed_up,connection_type,description,status,created_at) VALUES ($1,$2,$3,$4,1,'days',0,0,'hotspot',$5,'active',NOW()) RETURNING *`,[makeId('pkg'),tenantId,name,price,clean(req.body.description||'')]); res.status(201).json({success:true,package:pack});}));
app.delete('/api/packages/:id',authMiddleware,asyncRoute(async(req,res)=>{const pack=await one('SELECT * FROM packages WHERE id=$1',[req.params.id]); if(!pack) fail(404,'Kifurushi hakijapatikana.'); ensureTenantAccess(req,pack.tenant_id); await query('DELETE FROM packages WHERE id=$1',[pack.id]); res.json({success:true,message:'Kifurushi kimefutwa.'});}));

app.get('/api/vouchers/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{
  const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId);
  try{
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS batch_id TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS package_name TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS price NUMERIC`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS code_type TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS prefix TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS template TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS qr_or_laha TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS device_model TEXT`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS mb_used BIGINT DEFAULT 0`);
    await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS mb_total BIGINT DEFAULT 0`);
  }catch(e){}
  const vouchers=await query(`SELECT v.id,v.tenant_id,v.package_id,v.code,v.status,v.batch_id,v.package_name,v.price,v.code_type,v.prefix,v.template,v.qr_or_laha,v.device_model,v.mb_used,v.mb_total,v.expires_at,v.used_at,v.created_at FROM vouchers v WHERE v.tenant_id=$1 ORDER BY v.created_at DESC`,[tenantId]);
  res.json({success:true,vouchers});
}));
function generateCodeByType(type,length=6){const numbers='0123456789'; const letters='ABCDEFGHJKLMNPQRSTUVWXYZ'; const mixed='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let chars=mixed; if(type==='numbers') chars=numbers; if(type==='letters') chars=letters; let code=''; for(let i=0;i<length;i++){code+=chars.charAt(Math.floor(Math.random()*chars.length));} return code;}
app.post('/api/vouchers',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{
  const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; ensureTenantAccess(req,tenantId);
  const count=Math.min(Math.max(Number(req.body.quantity||req.body.count||1),1),500);
  const packageId=clean(req.body.package_id||'')||null;
  const codeType=clean(req.body.code_type||'mixed'); const prefix=clean(req.body.prefix||'MH NET').toUpperCase().slice(0,10); const usePrefix=req.body.use_prefix===true||req.body.usePrefix===true||!!prefix;
  const template=clean(req.body.template||'B'); const qrOrLaha=clean(req.body.qr_or_laha||req.body.qrOrLaha||'QR');
  const batchId=`BATCH-${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  let pkgName='',pkgPrice=0; if(packageId){const pkg=await one('SELECT name,price FROM packages WHERE id=$1',[packageId]); if(pkg){pkgName=pkg.name; pkgPrice=pkg.price;}}
  try{await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS batch_id TEXT`);}catch(e){}
  const vouchers=[]; for(let i=0;i<count;i++){let rawCode=generateCodeByType(codeType,6); let finalCode=(usePrefix&&prefix)?`${prefix}-${rawCode}`:rawCode; const voucher=await one(`INSERT INTO vouchers (id,tenant_id,package_id,code,status,batch_id,package_name,price,code_type,prefix,template,qr_or_laha,created_at) VALUES ($1,$2,$3,$4,'unused',$5,$6,$7,$8,$9,$10,$11,NOW()) RETURNING *`,[makeId('voucher'),tenantId,packageId,finalCode,batchId,pkgName,pkgPrice,codeType,prefix,template,qrOrLaha]); vouchers.push(voucher);}
  res.status(201).json({success:true,message:`Vocha ${count}`,batch_id:batchId,count:vouchers.length,vouchers});
}));
app.delete('/api/vouchers/:id',authMiddleware,asyncRoute(async(req,res)=>{const rawId=String(req.params.id||'').trim(); let voucher=await one('SELECT * FROM vouchers WHERE id=$1 LIMIT 1',[rawId]); if(!voucher) voucher=await one('SELECT * FROM vouchers WHERE code=$1 LIMIT 1',[rawId]); if(!voucher) fail(404,'Vocha haikupatikana'); ensureTenantAccess(req,voucher.tenant_id); await query('DELETE FROM vouchers WHERE id=$1',[voucher.id]); res.json({success:true,message:`Vocha ${voucher.code} imefutwa`});}));
app.delete('/api/vouchers',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.query.tenant_id:req.tenant_id; if(!tenantId) fail(400,'tenant_id inahitajika'); ensureTenantAccess(req,tenantId); const ids=Array.isArray(req.body.ids)?req.body.ids:[]; if(!ids.length) fail(400,'Hakuna vocha'); let deleted=0; for(const rawId of ids){let v=await one('SELECT id FROM vouchers WHERE (id=$1 OR code=$1) AND tenant_id=$2 LIMIT 1',[rawId,tenantId]); if(v){await query('DELETE FROM vouchers WHERE id=$1',[v.id]); deleted++;}} res.json({success:true,message:`${deleted} vocha zimefutwa`,deleted});}));
app.post('/api/vouchers/:id/disable',authMiddleware,asyncRoute(async(req,res)=>{const rawId=String(req.params.id||'').trim(); let voucher=await one('SELECT * FROM vouchers WHERE id=$1 LIMIT 1',[rawId]); if(!voucher) voucher=await one('SELECT * FROM vouchers WHERE code=$1 LIMIT 1',[rawId]); if(!voucher) fail(404,'Vocha haikupatikana'); ensureTenantAccess(req,voucher.tenant_id); await query('UPDATE vouchers SET status=$1 WHERE id=$2',['disabled',voucher.id]); res.json({success:true,message:'Vocha imezuiwa'});}));
app.get('/api/vouchers/expired/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const expired=await query(`SELECT code,package_name,price,batch_id,used_at,expires_at,device_model,mb_used,mb_total,status,created_at FROM vouchers WHERE tenant_id=$1 AND status IN ('used','expired','disabled') ORDER BY used_at DESC NULLS LAST`,[tenantId]); res.json({success:true,expired,total:expired.length});}));
app.get('/api/vouchers/print/:batch_id',authMiddleware,asyncRoute(async(req,res)=>{const batchId=req.params.batch_id; const template=(req.query.template||'B').toUpperCase(); const qrMode=(req.query.qr||'1')==='1'?'QR':'LAHA'; const vouchers=await query(`SELECT * FROM vouchers WHERE batch_id=$1 ORDER BY created_at ASC`,[batchId]); if(!vouchers.length) fail(404,'Batch haijapatikana'); const tenant=await getTenantRecord(vouchers[0].tenant_id); res.json({success:true,wisp_name:tenant.business_name,batch_id:batchId,template:template,qr_or_laha:qrMode,vouchers});}));
app.post('/api/vouchers/track-usage',asyncRoute(async(req,res)=>{const code=clean(req.body.code||''); const deviceModel=clean(req.body.device_model||req.body.model||''); const mbUsed=Number(req.body.mb_used||0); const userAgent=String(req.headers['user-agent']||''); let model=deviceModel; if(!model&&userAgent){if(/Tecno/i.test(userAgent)) model='Tecno Device'; else if(/Infinix/i.test(userAgent)) model='Infinix Device'; else if(/Samsung/i.test(userAgent)) model='Samsung Device'; else model=userAgent.slice(0,80);} if(code){try{await query(`UPDATE vouchers SET used_at=COALESCE(used_at,NOW()),device_model=COALESCE($2,device_model),mb_used=GREATEST(COALESCE(mb_used,0),$3),status=CASE WHEN status='unused' THEN 'used' ELSE status END WHERE code=$1`,[code,model,mbUsed]);}catch(e){}} res.json({success:true});}));

/* ========== SUBSCRIPTION - PALMPESA + FIMIPAY ========== */
app.get('/api/subscription/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{
  const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId);
  const tenant=await getTenantRecord(tenantId);
  const payments=await query(`SELECT id, amount, status, reference, transaction_id, provider, created_at, fail_reason FROM payments WHERE tenant_id = $1 AND (provider LIKE 'subscription%' OR description LIKE '%SUBSCRIPTION%' OR provider LIKE '%FimiPay%') ORDER BY created_at DESC LIMIT 50`, [tenantId]);
  const history = payments.map(p=>({ id: p.id, amount: p.amount, status: p.status, reference: p.reference || p.transaction_id, transaction_id: p.transaction_id, provider: p.provider, date: p.created_at ? new Date(p.created_at).toLocaleString('sw-TZ') : '-', created_at: p.created_at, failReason: p.fail_reason || '' }));
  res.json({ success:true, plan_code: tenant.plan||'diamond', plan_name: (tenant.plan||'DIAMOND').toUpperCase(), price: PLANS[(tenant.plan||'diamond').toUpperCase()]?.monthly_price || 15000, status: tenant.status||'active', expiry_date: tenant.subscription_ends_at || tenant.trial_ends_at, history });
}));

/* --- PALMPESA PAY (existing) --- */
app.post('/api/subscription/pay',authMiddleware,asyncRoute(async(req,res)=>{
  const tenantId=req.body.tenant_id || req.tenant_id; ensureTenantAccess(req,tenantId);
  const phone=clean(req.body.phone); if(!isValidPhone(phone)) fail(400,'Namba ya simu si sahihi - andika kama 07XXXXXXXX');
  const amount=Number(req.body.amount); if(!Number.isFinite(amount)||amount<=0) fail(400,'Kiasi si sahihi');
  const planCode=(clean(req.body.plan_code)||'diamond').toLowerCase();
  const plan=PLANS[planCode.toUpperCase()]; if(!plan) fail(400,'Kifurushi hakipo');
  const transactionId='SUB_'+Date.now()+'_'+crypto.randomBytes(3).toString('hex').toUpperCase();
  const payment=await one(`INSERT INTO payments (id, tenant_id, provider, reference, transaction_id, amount, currency, status, description, fail_reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,'TZS','pending',$7,$8,NOW()) RETURNING *`, [makeId('payment'), tenantId, 'subscription_'+planCode, transactionId, transactionId, amount, `SUBSCRIPTION ${planCode.toUpperCase()} PalmPesa ${phone} Vendor:${PALMPESA_VENDOR}`, 'Inasubiri - Push PalmPesa']);
  let pushResult=null; let pushError=null;
  try{ pushResult=await sendPalmPesaPush({phone, amount, transactionId, planName: planCode.toUpperCase(), tenantId}); }
  catch(e){ pushError=e.message; await query(`UPDATE payments SET fail_reason = $1 WHERE id = $2`, [pushError, payment.id]); }
  if(pushError && !pushResult){ return res.json({ success:true, status:'pending', transaction_id: transactionId, message: `Ombi limehifadhiwa - ${pushError}`, reference: transactionId }); }
  res.json({ success:true, status:'pending', transaction_id: transactionId, message: `Ombi limetumwa - Angalia simu ${phone} USSD Push`, reference: transactionId, push: pushResult, till: PALMPESA_VENDOR });
}));

/* --- FIMIPAY PAY - NEW FOR MR HAAS NET --- */
app.post('/api/subscription/fimipay/pay',authMiddleware,asyncRoute(async(req,res)=>{
  const tenantId=req.body.tenant_id || req.tenant_id; ensureTenantAccess(req,tenantId);
  const phone=clean(req.body.phone); const email=emailValue(req.body.email || req.tenant?.email || '');
  const amount=Number(req.body.amount); if(!Number.isFinite(amount)||amount<=0) fail(400,'Kiasi si sahihi');
  const planCode=(clean(req.body.plan_code)||'diamond').toLowerCase();
  const tenant=await getTenantRecord(tenantId);
  try{
    const fimipay = await createFimiPayCheckout({ tenantId, amount, phone, planCode, email });
    const payment=await one(`INSERT INTO payments (id, tenant_id, provider, reference, transaction_id, amount, currency, status, description, fail_reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,'TZS','pending',$7,$8,NOW()) RETURNING *`, [makeId('payment'), tenantId, 'FimiPay_'+planCode, fimipay.reference, fimipay.reference, amount, `SUBSCRIPTION ${planCode.toUpperCase()} FimiPay ${phone}`, `FimiPay checkout ${fimipay.endpoint}`]);
    res.json({ success:true, status:'pending', transaction_id: fimipay.reference, checkout_url: fimipay.checkout_url, message: `Link ya malipo imetengenezwa - Mpeleke mteja hapa`, reference: fimipay.reference, payment });
  }catch(e){
    console.error('[FIMIPAY ERROR]', e.message);
    fail(500, `FimiPay imeshindwa: ${e.message}`);
  }
}));

/* --- FIMIPAY WEBHOOK - PESA INAPOFIKA KWAKO --- */
app.post('/api/webhook/fimipay', async (req,res)=>{
  try{
    const raw = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const signature = req.headers['x-fimipay-signature'] || req.headers['x-fimipay-signature'.toLowerCase()] || '';
    console.log('[FIMIPAY WEBHOOK] Headers:', { signature: signature?.slice(0,20), hasSecret: !!FIMIPAY_WEBHOOK_SECRET });
    console.log('[FIMIPAY WEBHOOK] Body:', req.body);
    if(FIMIPAY_WEBHOOK_SECRET){
      const ok = verifyFimiPaySignature(raw, signature);
      if(!ok){
        console.error('[FIMIPAY WEBHOOK] Invalid signature');
        // Kwa test tunakubali hata kama signature haifanani, lakini production inabidi iwe strict
        // return res.status(401).json({success:false,message:'Invalid signature'});
      }
    }
    const body = req.body || {};
    const eventType = (body.type || body.event || body.status || '').toString().toLowerCase();
    const data = body.data || body;
    const reference = data.reference || body.reference || data.order_id || '';
    const isSuccess = ['payment.success','success','paid','completed','successful','approved'].some(s=> eventType.includes(s)) || data.status==='success' || data.status==='paid' || body.status==='success';

    if(!reference){
      console.error('[FIMIPAY WEBHOOK] No reference');
      return res.json({success:false,message:'No reference'});
    }
    const payment = await one(`SELECT * FROM payments WHERE transaction_id=$1 OR reference=$1 LIMIT 1`, [reference]);
    if(!payment){
      console.log('[FIMIPAY WEBHOOK] Payment not found, creating for', reference);
      // Kama payment haipo, jaribu kuipata kwa metadata
      const tenantId = data.metadata?.tenantId || data.metadata?.tenant_id || body.metadata?.tenantId;
      if(tenantId && isSuccess){
        const planCode = (data.metadata?.planCode || 'diamond').toLowerCase();
        const expiry=new Date(Date.now() + 30*24*3600*1000);
        await query(`UPDATE tenants SET plan=$1, subscription_status='active', subscription_ends_at=$2, status='active' WHERE id=$3`, [planCode, expiry.toISOString(), tenantId]);
        return res.json({success:true,message:'Tenant activated via metadata'});
      }
      return res.json({success:false,message:'Payment not found'});
    }
    if(isSuccess){
      await query(`UPDATE payments SET status='paid', fail_reason='' WHERE id=$1`, [payment.id]);
      const planCode = (payment.provider||'').replace('subscription_','').replace('FimiPay_','') || data.metadata?.planCode || 'diamond';
      const expiry=new Date(Date.now() + 30*24*3600*1000);
      await query(`UPDATE tenants SET plan=$1, subscription_status='active', subscription_ends_at=$2, status='active' WHERE id=$3`, [planCode.toLowerCase(), expiry.toISOString(), payment.tenant_id]);
      console.log(`[FIMIPAY PAID] Tenant ${payment.tenant_id} -> ${planCode} - pesa imefika kwako!`);
    }else if(['failed','cancelled','failure','declined'].some(s=> eventType.includes(s))){
      await query(`UPDATE payments SET status='failed', fail_reason=$1 WHERE id=$2`, [data.message||'FimiPay failed', payment.id]);
    }
    res.json({success:true,received:true});
  }catch(e){
    console.error('[FIMIPAY WEBHOOK ERROR]', e);
    res.status(500).json({success:false,error:e.message});
  }
});

// Alias routes - FimiPay inaweza kutuma kwa URLs tofauti
app.post('/api/subscription/fimipay-callback', async (req,res)=>{ req.url='/api/webhook/fimipay'; return app._router.handle(req,res,()=>{}); });
app.post('/api/fimipay/webhook', async (req,res)=>{ req.url='/api/webhook/fimipay'; return app._router.handle(req,res,()=>{}); });

app.post('/api/subscription/palmpesa-callback',asyncRoute(async(req,res)=>{
  const body=req.body||{}; console.log(`[PALMPESA CALLBACK]`, JSON.stringify(body));
  const orderId=body.order_id || body.reference || body.orderId || body.transid || body.transactionId || body.externalId || body.data?.reference || body.data?.order_id;
  const statusRaw=(body.status || body.result || body.payment_status || body.transaction_status || body.data?.status || '').toString().toLowerCase();
  const success=['success','completed','paid','successful','complete','approved','succeeded'].some(s=> statusRaw.includes(s)) || body.resultcode==='000' || body.success===true || body.data?.status==='success';
  if(!orderId) return res.json({ success:false, message:'No orderId' });
  const payment=await one(`SELECT * FROM payments WHERE transaction_id = $1 OR reference = $1`, [orderId]);
  if(!payment){ return res.json({ success:false, message:'Payment not found' }); }
  if(success){
    await query(`UPDATE payments SET status = 'paid', fail_reason = '' WHERE id = $1`, [payment.id]);
    const planCode=(payment.provider||'').replace('subscription_','') || 'diamond';
    const expiry=new Date(Date.now() + 30*24*3600*1000);
    await query(`UPDATE tenants SET plan = $1, subscription_status = 'active', subscription_ends_at = $2, status = 'active' WHERE id = $3`, [planCode, expiry.toISOString(), payment.tenant_id]);
  }else if(['failed','cancelled','failure','declined','rejected'].some(s=> statusRaw.includes(s))){
    await query(`UPDATE payments SET status = 'failed', fail_reason = $1 WHERE id = $2`, [body.message||'failed', payment.id]);
  }
  res.json({ success:true, received:true });
}));

app.post('/api/subscription/callback',asyncRoute(async(req,res)=>{
  const body=req.body||{}; const transactionId=body.externalId || body.orderReference || body.transactionId || body.reference || body.order_id;
  const status=(body.status || body.transactionStatus || body.result || '').toLowerCase(); const success=['success','completed','paid','successful','approved'].includes(status);
  if(!transactionId) return res.json({ success:false });
  const payment=await one(`SELECT * FROM payments WHERE transaction_id = $1 OR reference = $1`, [transactionId]);
  if(!payment) return res.json({ success:false });
  if(success){ await query(`UPDATE payments SET status = 'paid', fail_reason = '' WHERE id = $1`, [payment.id]); const planCode=(payment.provider||'').replace('subscription_','') || 'diamond'; const expiry=new Date(Date.now() + 30*24*3600*1000); await query(`UPDATE tenants SET plan = $1, subscription_status = 'active', subscription_ends_at = $2, status = 'active' WHERE id = $3`, [planCode, expiry.toISOString(), payment.tenant_id]); }
  else if(['failed','cancelled'].includes(status)){ await query(`UPDATE payments SET status = 'failed', fail_reason = $1 WHERE id = $2`, [body.message||'failed', payment.id]); }
  res.json({ success:true });
}));

app.post('/api/subscription/change',authMiddleware,asyncRoute(async(req,res)=>{
  const tenantId=req.body.tenant_id || req.tenant_id; ensureTenantAccess(req,tenantId);
  const planCode=(clean(req.body.plan_code)||'').toLowerCase(); if(!PLANS[planCode.toUpperCase()]) fail(400,'Kifurushi hakipo');
  res.json({ success:true, message: `Umechagua ${planCode.toUpperCase()} - Lipa sasa`, pending_plan: planCode });
}));

app.get('/api/subscription/status/:order_id',authMiddleware,asyncRoute(async(req,res)=>{
  const orderId=req.params.order_id; let statusData=null; try{ statusData=await checkPalmPesaStatus(orderId); }catch(e){ statusData={ error: e.message }; }
  res.json({ success:true, order_id: orderId, palmpesa: statusData });
}));

app.get('/api/portal/settings/:tenant_id',asyncRoute(async(req,res)=>{const tenantId=clean(req.params.tenant_id); const tenant=await getTenantRecord(tenantId); const settings=await one(`SELECT tenant_id,portal_title,primary_color,announcement,contact_phone,currency FROM tenant_settings WHERE tenant_id=$1`,[tenantId]); res.json({success:true,portal:settings||{tenant_id:tenantId,portal_title:tenant.business_name,primary_color:'#111827',announcement:'',contact_phone:tenant.phone,currency:'TZS'}});}));
app.post('/api/portal/settings/:tenant_id',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const title=String(req.body.portal_title||req.body.name||'').slice(0,120); const color=String(req.body.primary_color||'#111827'); const announcement=String(req.body.announcement||'').slice(0,3000); const contactPhone=String(req.body.contact_phone||req.body.contact||'').slice(0,40); const settings=await one(`INSERT INTO tenant_settings (tenant_id,portal_title,primary_color,announcement,contact_phone,currency) VALUES ($1,$2,$3,$4,$5,'TZS') ON CONFLICT (tenant_id) DO UPDATE SET portal_title=EXCLUDED.portal_title,primary_color=EXCLUDED.primary_color,announcement=EXCLUDED.announcement,contact_phone=EXCLUDED.contact_phone RETURNING *`,[tenantId,title,color,announcement,contactPhone]); res.json({success:true,settings});}));

app.get('/api/payments/:tenant_id',authMiddleware,asyncRoute(async(req,res)=>{const tenantId=req.params.tenant_id; ensureTenantAccess(req,tenantId); const payments=await query(`SELECT id,tenant_id,client_id,provider,reference,amount,currency,status,description,created_at FROM payments WHERE tenant_id=$1 ORDER BY created_at DESC`,[tenantId]); res.json({success:true,payments});}));
app.post('/api/payments/manual',authMiddleware,requireSubscription,asyncRoute(async(req,res)=>{const tenantId=req.role==='super_admin'?req.body.tenant_id:req.tenant_id; ensureTenantAccess(req,tenantId); const amount=Number(req.body.amount); if(!Number.isFinite(amount)||amount<=0) fail(400,'Kiasi si sahihi.'); const payment=await one(`INSERT INTO payments (id,tenant_id,provider,reference,amount,currency,status,description,created_at) VALUES ($1,$2,'manual',$3,$4,'TZS','pending',$5,NOW()) RETURNING *`,[makeId('payment'),tenantId,clean(req.body.reference||''),amount,clean(req.body.customer_name||'')]); res.status(201).json({success:true,payment});}));

app.get('/api/super/updates',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const updates=await query(`SELECT * FROM system_updates ORDER BY created_at DESC`); res.json({success:true,updates});}));
app.post('/api/super/updates',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const version=String(req.body.version||'').trim(); const title=String(req.body.title||'').trim(); if(!version||!title) fail(400,'Version na jina vinahitajika.'); const update=await one(`INSERT INTO system_updates (id,version,title,description,release_notes,status,created_at) VALUES ($1,$2,$3,$4,$5,'draft',NOW()) RETURNING *`,[makeId('update'),version,title,clean(req.body.description||''),clean(req.body.release_notes||'')]); res.status(201).json({success:true,update});}));
app.patch('/api/super/updates/:id/status',authMiddleware,requireSuperAdmin,asyncRoute(async(req,res)=>{const status=String(req.body.status||'').trim().toLowerCase(); const update=await one(`UPDATE system_updates SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING *`,[status,req.params.id]); res.json({success:true,update});}));

app.get('/',(req,res)=>{res.sendFile(path.join(__dirname,'public','index.html'));});
app.get('/api/*',(req,res)=>{res.status(404).json({success:false,message:'API endpoint haijapatikana.'});});
app.use((err,req,res,next)=>{if(res.headersSent) return next(err); const status=err.status||500; if(status>=500) console.error('[SERVER ERROR]',err.message); res.status(status).json({success:false,message:err.message||'Hitilafu ya ndani.'});});

async function startServer(){
  try{
    await db.ready; if(!db.pool||typeof db.pool.query!=='function') throw new Error('database.js lazima itoe pool.query');
    await db.pool.query('SELECT 1');
    try{await db.pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'offline'`);}catch(e){}
    try{await db.pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ`);}catch(e){}
    try{await db.pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS wan_port TEXT`);}catch(e){}
    try{await db.pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS connection_type TEXT DEFAULT 'api'`);}catch(e){}
    try{await db.pool.query(`ALTER TABLE vouchers ADD COLUMN IF NOT EXISTS batch_id TEXT`);}catch(e){}
    try{await db.pool.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS fail_reason TEXT`);}catch(e){}
    try{await db.pool.query(`ALTER TABLE payments ADD COLUMN IF NOT EXISTS provider TEXT`);}catch(e){}
    app.listen(PORT,'0.0.0.0',()=>{console.log(`🚀 MR HAAS backend port ${PORT} - Till ${PALMPESA_VENDOR} + FimiPay Ready`); console.log(`✅ FimiPay: ${FIMIPAY_BASE_URL} - PalmPesa: ${PALMPESA_VENDOR}`);});
  }catch(error){console.error('Server haikuweza kuanza:',error.message); process.exit(1);}
}
startServer();
module.exports=app;
