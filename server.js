require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 10000);
const SITE_NAME = process.env.SITE_NAME || 'Ruby Parker';
const BTC_ADDRESS = process.env.BTC_ADDRESS || '';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || '';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_CURRENCY = String(process.env.PAYSTACK_CURRENCY || 'USD').toUpperCase();
const PAYSTACK_AMOUNT = Number(process.env.PAYSTACK_AMOUNT || 1000);
const PAYSTACK_DISPLAY_PRICE = process.env.PAYSTACK_DISPLAY_PRICE || '$10';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || '';
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'ruby-content';
const BASE_URL = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || '';
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 100);

const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const mailer = smtpConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || 'false') === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;
const MAIL_FROM = process.env.MAIL_FROM || process.env.SMTP_USER || '';

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SECRET_KEY. Set them in Render Environment Variables.');
}

const supabase = (SUPABASE_URL && SUPABASE_SECRET_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  : null;

app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieSession({
  name: 'ruby_parker_session',
  keys: [process.env.SESSION_SECRET || 'dev-only-change-this-secret'],
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 1000 * 60 * 60 * 24 * 30
}));
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '7d' }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: 'Too many login attempts. Please wait a few minutes and try again.' });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: 'Too many registration attempts. Please wait and try again.' });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = /^(image|video)\/(jpeg|png|gif|webp|mp4|webm|quicktime)$/i.test(file.mimetype);
    cb(allowed ? null : new Error('Only image and video files are allowed.'), allowed);
  }
});

function esc(v = '') {
  return String(v).replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
}

function csrfToken(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  return req.session.csrf;
}

function csrfField(req) {
  return `<input type="hidden" name="_csrf" value="${esc(csrfToken(req))}">`;
}

function verifyCsrf(req, res, next) {
  const expected = req.session?.csrf;
  const received = String(req.body?._csrf || req.get('x-csrf-token') || '');
  if (!expected || !received || expected.length !== received.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received))) {
    return res.status(403).send(page('Security check', flash('Your form expired. Please go back and try again.'), req));
  }
  next();
}

function page(title, body, req) {
  const u = req?.currentUser || null;
  const nav = u
    ? `<a href="/feed">Feed</a><a href="/account">Account</a>${u.is_admin ? '<a href="/admin">Admin</a>' : ''}<form method="post" action="/logout" class="inline">${csrfField(req)}<button>Log out</button></form>`
    : `<a href="/login">Log in</a><a class="pill" href="/join">Join</a>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#0d0b10">
  <meta name="description" content="Private Ruby Parker creator membership.">
  <title>${esc(title)} · ${esc(SITE_NAME)}</title>
  <link rel="stylesheet" href="/public/style.css">
</head>
<body>
  <header>
    <a class="brand" href="/"><img src="/public/ruby-parker-logo.jpeg" alt="Ruby Parker"></a>
    <button class="menu-toggle" type="button" aria-label="Open menu" onclick="document.body.classList.toggle('menu-open')">☰</button>
    <nav>${nav}</nav>
  </header>
  <main>${body}</main>
  <footer><strong>${esc(SITE_NAME)}</strong><span>Private creator membership</span><span>© ${new Date().getFullYear()}</span></footer>
  <script>
    document.addEventListener('click', function(e){
      const img = e.target.closest('.lightbox-trigger');
      if (!img) return;
      const overlay = document.createElement('div');
      overlay.className = 'lightbox';
      overlay.innerHTML = '<button aria-label="Close">×</button><img src="' + img.src + '" alt="">';
      overlay.addEventListener('click', function(){ overlay.remove(); });
      document.body.appendChild(overlay);
    });
  </script>
</body>
</html>`;
}

function flash(msg) { return `<div class="notice">${esc(msg)}</div>`; }
function money(amount, currency) {
  try { return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(Number(amount) / 100); }
  catch (_) { return `${Number(amount) / 100} ${currency}`; }
}
function formatDate(value) { return value ? new Date(value).toLocaleString() : '—'; }
function activeMember(u) { return Boolean(u && (u.is_admin || (u.membership_expires_at && new Date(u.membership_expires_at) > new Date()))); }
function membershipLabel(u) { return u?.is_admin ? 'Admin access' : activeMember(u) ? `Active until ${new Date(u.membership_expires_at).toLocaleDateString()}` : 'Membership inactive'; }
function publicBaseUrl(req) { return BASE_URL || `${req.protocol}://${req.get('host')}`; }
function makeObjectPath(file) { const ext = path.extname(file.originalname || '').toLowerCase() || ''; return `posts/${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`; }

async function sendEmail(to, subject, html) {
  if (!mailer || !to) return false;
  try {
    await mailer.sendMail({ from: MAIL_FROM, to, subject, html });
    return true;
  } catch (error) {
    console.error('Email error:', error.message);
    return false;
  }
}

async function getUserById(id) {
  if (!supabase || !id) return null;
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data || null;
}
async function getUserByEmail(email) {
  if (!supabase) return null;
  const { data, error } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
  if (error) throw error;
  return data || null;
}
async function attachCurrentUser(req) {
  if (!req.session?.userId) return null;
  try { req.currentUser = await getUserById(req.session.userId); }
  catch (error) { console.error('User lookup failed:', error); req.currentUser = null; }
  return req.currentUser;
}

async function requireLogin(req, res, next) {
  try { const u = await attachCurrentUser(req); if (!u) return res.redirect('/login'); next(); }
  catch (error) { next(error); }
}
async function requireMember(req, res, next) {
  try { const u = await attachCurrentUser(req); if (!activeMember(u)) return res.redirect('/join'); next(); }
  catch (error) { next(error); }
}
async function requireAdmin(req, res, next) {
  try {
    const u = await attachCurrentUser(req);
    if (!u || !u.is_admin) return res.status(403).send(page('Forbidden', '<div class="card narrow"><h1>403</h1><p>Admin access only.</p></div>', req));
    next();
  } catch (error) { next(error); }
}

async function ensureAdmin() {
  if (!supabase) return;
  const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');
  if (!adminEmail || !adminPassword) return;
  const existing = await getUserByEmail(adminEmail);
  if (!existing) {
    const { error } = await supabase.from('users').insert({ email: adminEmail, password_hash: bcrypt.hashSync(adminPassword, 12), is_admin: true, created_at: new Date().toISOString() });
    if (error) throw error;
  } else if (!existing.is_admin) {
    const { error } = await supabase.from('users').update({ is_admin: true }).eq('id', existing.id);
    if (error) throw error;
  }
}

async function extendMembership(userId, days = 30) {
  const user = await getUserById(userId);
  const now = new Date();
  const base = user?.membership_expires_at && new Date(user.membership_expires_at) > now ? new Date(user.membership_expires_at) : now;
  base.setDate(base.getDate() + days);
  const { error } = await supabase.from('users').update({ membership_expires_at: base.toISOString() }).eq('id', userId);
  if (error) throw error;
  return base;
}

app.get('/health', async (_req, res) => {
  if (!supabase) return res.status(503).json({ ok: false, error: 'Supabase is not configured' });
  const { error } = await supabase.from('users').select('id').limit(1);
  if (error) return res.status(503).json({ ok: false, error: error.message });
  res.json({ ok: true, database: 'supabase', email: smtpConfigured ? 'configured' : 'optional-not-configured' });
});

app.get('/', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    const u = req.currentUser;
    const accountButton = u ? `<a class="button ghost" href="/account">My account</a>` : `<a class="button ghost" href="/login">Member login</a>`;
    const body = `<section class="hero">
      <div>
        <span class="eyebrow">PRIVATE CREATOR MEMBERSHIP</span>
        <h1>Welcome to ${esc(SITE_NAME)}.</h1>
        <p class="lead">A private space for exclusive photos, videos, updates and members-only content.</p>
        <div class="actions"><a class="button" href="/join">Join for ${esc(PAYSTACK_DISPLAY_PRICE)}</a>${accountButton}</div>
        <div class="trust-row"><span>🔒 Private members area</span><span>📱 Mobile friendly</span><span>💳 Secure checkout</span></div>
      </div>
      <div class="hero-card"><img class="hero-logo" src="/public/ruby-parker-logo.jpeg" alt="Ruby Parker logo"><p>30 days of private access</p><strong>${esc(PAYSTACK_DISPLAY_PRICE)}</strong></div>
    </section>
    <section class="feature-grid">
      <div class="feature"><span>📸</span><h3>Exclusive content</h3><p>Private posts available to active members.</p></div>
      <div class="feature"><span>💗</span><h3>Member community</h3><p>Like and comment on posts inside your private feed.</p></div>
      <div class="feature"><span>🔐</span><h3>Protected access</h3><p>Your membership and content are checked on the server.</p></div>
    </section>`;
    res.send(page('Home', body, req));
  } catch (e) { next(e); }
});

app.get('/register', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    res.send(page('Register', `<div class="card narrow"><span class="eyebrow">JOIN RUBY PARKER</span><h1>Create your account</h1><p>Your account is free to create. Membership is activated after payment.</p><form method="post">${csrfField(req)}<label>Email<input name="email" type="email" autocomplete="email" required></label><label>Password<input name="password" type="password" minlength="8" autocomplete="new-password" required><small>Use at least 8 characters.</small></label><button class="button">Create account</button></form><p>Already a member? <a href="/login">Log in</a></p></div>`, req));
  } catch (e) { next(e); }
});

app.post('/register', registerLimiter, verifyCsrf, async (req, res, next) => {
  try {
    if (!supabase) return res.status(503).send(page('Register', flash('Database is not configured yet.'), req));
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || password.length < 8) return res.status(400).send(page('Register', flash('Use a valid email and a password of at least 8 characters.') + '<a href="/register">Try again</a>', req));
    const existing = await getUserByEmail(email);
    if (existing) return res.status(409).send(page('Register', flash('That email is already registered.') + '<a href="/login">Log in</a>', req));
    const { data, error } = await supabase.from('users').insert({ email, password_hash: bcrypt.hashSync(password, 12), is_admin: false, created_at: new Date().toISOString() }).select('id').single();
    if (error) throw error;
    req.session.userId = data.id;
    await sendEmail(email, `${SITE_NAME} — welcome`, `<h2>Welcome to ${esc(SITE_NAME)} 💗</h2><p>Your account has been created. Complete your membership payment to unlock the private feed.</p><p><a href="${esc(publicBaseUrl(req))}/join">Complete membership</a></p>`);
    res.redirect('/welcome');
  } catch (e) { next(e); }
});

app.get('/welcome', requireLogin, async (req, res) => {
  res.send(page('Welcome', `<div class="card narrow center"><div class="welcome-logo"><img src="/public/ruby-parker-logo.jpeg" alt="Ruby Parker"></div><span class="eyebrow">WELCOME</span><h1>Welcome to ${esc(SITE_NAME)} 💗</h1><p>Your account is ready. Choose your payment method to activate 30 days of private access.</p><a class="button" href="/join">Activate membership</a></div>`, req));
});

app.get('/login', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    const paid = req.query.paid ? flash('Payment verified. Your membership is active for 30 days.') : '';
    res.send(page('Login', `<div class="card narrow"><span class="eyebrow">MEMBERS</span><h1>Welcome back</h1>${paid}<form method="post">${csrfField(req)}<label>Email<input name="email" type="email" autocomplete="email" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="button">Log in</button></form><p>New here? <a href="/register">Create an account</a></p></div>`, req));
  } catch (e) { next(e); }
});

app.post('/login', loginLimiter, verifyCsrf, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const u = await getUserByEmail(email);
    if (!u || !bcrypt.compareSync(password, u.password_hash)) return res.status(401).send(page('Login', flash('Invalid email or password.') + '<a href="/login">Try again</a>', req));
    req.session.userId = u.id;
    res.redirect(u.is_admin ? '/admin' : activeMember(u) ? '/feed' : '/account');
  } catch (e) { next(e); }
});

app.post('/logout', verifyCsrf, (req, res) => { req.session = null; res.redirect('/'); });

app.get('/account', requireLogin, async (req, res, next) => {
  try {
    const [{ data: payments, error: paymentError }, { data: btc, error: btcError }] = await Promise.all([
      supabase.from('payments').select('provider,reference,amount,currency,status,created_at').eq('user_id', req.currentUser.id).order('created_at', { ascending: false }).limit(20),
      supabase.from('btc_submissions').select('tx_hash,amount_note,status,created_at').eq('user_id', req.currentUser.id).order('created_at', { ascending: false }).limit(20)
    ]);
    if (paymentError) throw paymentError;
    if (btcError) throw btcError;
    const paymentsHtml = (payments || []).map(p => `<div class="row"><span><strong>${esc(p.provider === 'paystack' ? 'Paystack' : p.provider)}</strong><br><small>${formatDate(p.created_at)}</small></span><span>${esc(money(p.amount, p.currency))}<br><small>${esc(p.status)}</small></span></div>`).join('') || '<p>No payment records yet.</p>';
    const btcHtml = (btc || []).map(p => `<div class="row"><span><strong>Bitcoin</strong><br><small>${esc(p.tx_hash.slice(0, 16))}… · ${formatDate(p.created_at)}</small></span><span>${esc(p.status)}</span></div>`).join('') || '<p>No Bitcoin submissions yet.</p>';
    const memberAction = activeMember(req.currentUser) ? `<a class="button" href="/feed">Open private feed</a>` : `<a class="button" href="/join">Activate membership</a>`;
    const expiry = req.currentUser.membership_expires_at ? new Date(req.currentUser.membership_expires_at).toLocaleString() : 'Not active';
    res.send(page('My Account', `<div class="account-grid"><section class="card"><span class="eyebrow">MY ACCOUNT</span><h1>Hi, ${esc(req.currentUser.email.split('@')[0])} 💗</h1><div class="status ${activeMember(req.currentUser) ? 'active' : ''}">${esc(membershipLabel(req.currentUser))}</div><p><strong>Email</strong><br>${esc(req.currentUser.email)}</p><p><strong>Membership</strong><br>${esc(expiry)}</p><div class="actions">${memberAction}<a class="button ghost" href="/join">Renew</a></div></section><section class="card"><h2>Change password</h2><form method="post" action="/account/password">${csrfField(req)}<label>Current password<input name="current_password" type="password" required></label><label>New password<input name="new_password" type="password" minlength="8" required></label><button class="button">Update password</button></form></section></div><div class="card"><h2>Payment history</h2>${paymentsHtml}</div><div class="card"><h2>Bitcoin submissions</h2>${btcHtml}</div>`, req));
  } catch (e) { next(e); }
});

app.post('/account/password', requireLogin, verifyCsrf, async (req, res, next) => {
  try {
    const current = String(req.body.current_password || '');
    const nextPassword = String(req.body.new_password || '');
    if (nextPassword.length < 8 || !bcrypt.compareSync(current, req.currentUser.password_hash)) return res.status(400).send(page('Password', flash('The current password is incorrect or the new password is too short.'), req));
    const { error } = await supabase.from('users').update({ password_hash: bcrypt.hashSync(nextPassword, 12) }).eq('id', req.currentUser.id);
    if (error) throw error;
    res.send(page('Password updated', `<div class="card narrow center"><h1>Password updated</h1><p>Your password has been changed successfully.</p><a class="button" href="/account">Back to account</a></div>`, req));
  } catch (e) { next(e); }
});

app.get('/join', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    const u = req.currentUser;
    const payButton = u ? `<button class="button" onclick="pay(this)">Pay ${esc(PAYSTACK_DISPLAY_PRICE)} with Paystack</button>` : '<a class="button" href="/login">Log in to pay</a>';
    const btcForm = u ? `<form method="post" action="/btc-submit">${csrfField(req)}<input name="tx_hash" placeholder="Bitcoin transaction hash" required><input name="amount_note" placeholder="Amount sent (optional)"><button class="button">Submit BTC payment</button></form>` : '<a href="/login">Log in to submit payment</a>';
    const body = `<div class="card"><span class="eyebrow">MEMBERSHIP</span><h1>${esc(PAYSTACK_DISPLAY_PRICE)} for 30 days</h1><p>Choose a payment method below. Your membership is activated only after successful verification.</p><div class="pay-grid"><section><div class="payment-icon">💳</div><h2>Pay with Paystack</h2><p>Secure online checkout using the payment methods available to you.</p>${payButton}</section><section><div class="payment-icon">₿</div><h2>Pay with Bitcoin</h2><p>Send the $10 equivalent in BTC to this address, then submit the transaction hash.</p><code>${esc(BTC_ADDRESS)}</code><p class="small">Bitcoin payments are manually verified by the site admin.</p>${btcForm}</section></div></div><div class="card info-card"><h2>What you get</h2><div class="check-grid"><span>✓ 30 days of private access</span><span>✓ Exclusive photos and videos</span><span>✓ Private member feed</span><span>✓ Likes and comments</span></div></div><script>async function pay(button){button.disabled=true;button.textContent='Connecting to Paystack…';try{const r=await fetch('/api/paystack/init',{method:'POST',headers:{'x-csrf-token':${JSON.stringify(csrfToken(req))}}});const j=await r.json();if(j.authorization_url)location.href=j.authorization_url;else alert(j.error||'Paystack is not configured yet.');}catch(e){alert('Could not connect to the payment service.');}finally{button.disabled=false;button.textContent='Pay ${esc(PAYSTACK_DISPLAY_PRICE)} with Paystack';}}</script>`;
    res.send(page('Join', body, req));
  } catch (e) { next(e); }
});

app.post('/btc-submit', requireLogin, verifyCsrf, async (req, res, next) => {
  try {
    const tx = String(req.body.tx_hash || '').trim();
    if (tx.length < 20) return res.status(400).send(page('Bitcoin', flash('Please enter the transaction hash.'), req));
    const { error } = await supabase.from('btc_submissions').insert({ user_id: req.currentUser.id, tx_hash: tx, amount_note: String(req.body.amount_note || '').slice(0, 200), status: 'pending', created_at: new Date().toISOString() });
    if (error) throw error;
    res.send(page('Bitcoin submitted', `<div class="card narrow center"><div class="success-icon">✓</div><h1>Payment submitted</h1><p>Your Bitcoin transaction was submitted for review. Membership will activate after verification.</p><a class="button" href="/account">View my account</a></div>`, req));
  } catch (e) { next(e); }
});

app.post('/api/paystack/init', requireLogin, verifyCsrf, async (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return res.status(503).json({ error: 'Paystack secret key has not been configured on the server yet.' });
  if (!supabase) return res.status(503).json({ error: 'Database is not configured yet.' });
  const reference = `RP-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    const callback_url = `${publicBaseUrl(req)}/paystack/callback`;
    const r = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: req.currentUser.email, amount: PAYSTACK_AMOUNT, currency: PAYSTACK_CURRENCY, reference, callback_url, metadata: { product: 'Ruby Parker 30-day membership', user_id: req.currentUser.id } })
    });
    const j = await r.json();
    if (!r.ok || !j.status) return res.status(400).json({ error: j.message || 'Paystack initialization failed' });
    const { error } = await supabase.from('payments').insert({ user_id: req.currentUser.id, provider: 'paystack', reference, amount: PAYSTACK_AMOUNT, currency: PAYSTACK_CURRENCY, status: 'initialized', created_at: new Date().toISOString() });
    if (error) throw error;
    res.json({ authorization_url: j.data.authorization_url });
  } catch (e) { console.error('Paystack init error:', e); res.status(500).json({ error: 'Payment service error' }); }
});

app.get('/paystack/callback', async (req, res, next) => {
  const ref = String(req.query.reference || '');
  if (!ref) return res.redirect('/join');
  if (!PAYSTACK_SECRET_KEY) return res.status(503).send(page('Payment', flash('Paystack is not configured on the server.'), req));
  try {
    const { data: payment, error: paymentError } = await supabase.from('payments').select('*').eq('reference', ref).maybeSingle();
    if (paymentError) throw paymentError;
    if (!payment) return res.status(400).send(page('Payment', flash('Payment reference was not found.'), req));
    if (payment.status === 'verified') return res.redirect('/account');
    const r = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`, { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } });
    const j = await r.json();
    const success = Boolean(j.status && j.data && j.data.status === 'success' && String(j.data.currency || '').toUpperCase() === PAYSTACK_CURRENCY && Number(j.data.amount) === PAYSTACK_AMOUNT);
    if (!success) return res.status(400).send(page('Payment', flash('Payment was not verified as successful.'), req));
    const exp = await extendMembership(payment.user_id, 30);
    const { error: updateError } = await supabase.from('payments').update({ status: 'verified' }).eq('id', payment.id);
    if (updateError) throw updateError;
    const user = await getUserById(payment.user_id);
    await sendEmail(user?.email, `${SITE_NAME} — membership active`, `<h2>Your membership is active 💗</h2><p>Your 30-day ${esc(SITE_NAME)} membership is active until ${esc(exp.toLocaleString())}.</p><p><a href="${esc(publicBaseUrl(req))}/feed">Open your private feed</a></p>`);
    req.session.userId = payment.user_id;
    res.redirect('/account');
  } catch (e) { next(e); }
});

app.get('/feed', requireMember, async (req, res, next) => {
  try {
    const { data: posts, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    const ids = (posts || []).map(p => p.id);
    const [{ data: likes }, { data: comments }] = ids.length ? await Promise.all([
      supabase.from('post_likes').select('post_id,user_id').in('post_id', ids),
      supabase.from('comments').select('id,post_id,user_id,body,created_at,users(email)').in('post_id', ids).order('created_at', { ascending: true })
    ]) : [{ data: [] }, { data: [] }];
    const likeCounts = {};
    const likedByMe = {};
    (likes || []).forEach(x => { likeCounts[x.post_id] = (likeCounts[x.post_id] || 0) + 1; if (x.user_id === req.currentUser.id) likedByMe[x.post_id] = true; });
    const commentMap = {};
    (comments || []).forEach(c => { (commentMap[c.post_id] ||= []).push(c); });
    const cards = posts.length ? posts.map(p => {
      const isVideo = String(p.mime_type || '').startsWith('video/');
      const media = p.storage_path ? (isVideo ? `<video controls preload="metadata" src="/media/${encodeURIComponent(p.id)}"></video>` : `<img class="lightbox-trigger" loading="lazy" src="/media/${encodeURIComponent(p.id)}" alt="Ruby Parker post">`) : '';
      const cs = commentMap[p.id] || [];
      const commentsHtml = cs.map(c => `<div class="comment"><strong>${esc((c.users?.email || 'Member').split('@')[0])}</strong><span>${esc(c.body)}</span><small>${formatDate(c.created_at)}</small></div>`).join('') || '<p class="small">Be the first to comment.</p>';
      return `<article class="post" id="post-${p.id}">${media}<div class="post-body"><p>${esc(p.caption)}</p><small>${formatDate(p.created_at)}</small><div class="post-actions"><form method="post" action="/posts/${p.id}/like">${csrfField(req)}<button class="like-button ${likedByMe[p.id] ? 'liked' : ''}">${likedByMe[p.id] ? '♥' : '♡'} ${likeCounts[p.id] || 0}</button></form><button type="button" class="comment-toggle" onclick="this.closest('.post').querySelector('.comments').classList.toggle('open')">💬 ${cs.length}</button></div><div class="comments open"><div class="comment-list">${commentsHtml}</div><form method="post" action="/posts/${p.id}/comments" class="comment-form">${csrfField(req)}<input name="body" maxlength="500" placeholder="Write a comment…" required><button class="button">Post</button></form></div></div></article>`;
    }).join('') : '<div class="card center"><h2>Your private feed is ready.</h2><p>No posts yet. New content will appear here when it is published.</p></div>';
    res.send(page('Private Feed', `<div class="feed-head"><div><span class="eyebrow">MEMBERS ONLY</span><h1>Private feed</h1><p>Welcome back, ${esc(req.currentUser.email.split('@')[0])} 💗</p></div><div class="status active">${esc(membershipLabel(req.currentUser))}</div></div><div class="posts">${cards}</div>`, req));
  } catch (e) { next(e); }
});

app.post('/posts/:id/like', requireMember, verifyCsrf, async (req, res, next) => {
  try {
    const postId = Number(req.params.id);
    const { data: existing } = await supabase.from('post_likes').select('post_id').eq('post_id', postId).eq('user_id', req.currentUser.id).maybeSingle();
    if (existing) await supabase.from('post_likes').delete().eq('post_id', postId).eq('user_id', req.currentUser.id);
    else { const { error } = await supabase.from('post_likes').insert({ post_id: postId, user_id: req.currentUser.id }); if (error) throw error; }
    res.redirect(req.get('referer') || '/feed');
  } catch (e) { next(e); }
});

app.post('/posts/:id/comments', requireMember, verifyCsrf, async (req, res, next) => {
  try {
    const body = String(req.body.body || '').trim().slice(0, 500);
    if (!body) return res.redirect('/feed');
    const { error } = await supabase.from('comments').insert({ post_id: Number(req.params.id), user_id: req.currentUser.id, body, created_at: new Date().toISOString() });
    if (error) throw error;
    res.redirect(req.get('referer') || '/feed');
  } catch (e) { next(e); }
});

app.get('/media/:id', requireMember, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { data: post, error } = await supabase.from('posts').select('storage_path,mime_type').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!post?.storage_path) return res.sendStatus(404);
    const { data, error: signedError } = await supabase.storage.from(SUPABASE_BUCKET).createSignedUrl(post.storage_path, 3600);
    if (signedError || !data?.signedUrl) return res.status(404).send('Media unavailable');
    res.redirect(data.signedUrl);
  } catch (e) { next(e); }
});

app.get('/admin', requireAdmin, async (req, res, next) => {
  try {
    const [{ data: users, error: usersError }, { data: btc, error: btcError }, { data: posts, error: postsError }, { data: payments, error: paymentsError }] = await Promise.all([
      supabase.from('users').select('id,email,is_admin,membership_expires_at,created_at').order('id', { ascending: false }),
      supabase.from('btc_submissions').select('*, users(email)').order('id', { ascending: false }),
      supabase.from('posts').select('id,caption,mime_type,created_at').order('created_at', { ascending: false }),
      supabase.from('payments').select('id,user_id,provider,amount,currency,status,created_at,users(email)').order('created_at', { ascending: false }).limit(50)
    ]);
    if (usersError) throw usersError; if (btcError) throw btcError; if (postsError) throw postsError; if (paymentsError) throw paymentsError;
    const activeUsers = (users || []).filter(activeMember).length;
    const verifiedPayments = (payments || []).filter(p => p.status === 'verified').length;
    const revenue = (payments || []).filter(p => p.status === 'verified').reduce((sum, p) => sum + Number(p.amount || 0), 0);
    const stats = `<div class="stats-grid"><div class="stat"><span>Members</span><strong>${users?.length || 0}</strong></div><div class="stat"><span>Active</span><strong>${activeUsers}</strong></div><div class="stat"><span>Posts</span><strong>${posts?.length || 0}</strong></div><div class="stat"><span>Verified payments</span><strong>${verifiedPayments}</strong><small>${esc(money(revenue, PAYSTACK_CURRENCY))}</small></div></div>`;
    const btcHtml = (btc || []).map(x => `<div class="row"><span><strong>${esc(x.users?.email || 'Unknown')}</strong><br><code>${esc(x.tx_hash)}</code><br><small>${esc(x.amount_note || '')} · ${formatDate(x.created_at)}</small></span>${x.status === 'pending' ? `<form method="post" action="/admin/btc/${x.id}/approve">${csrfField(req)}<button class="button">Approve 30 days</button></form>` : `<span class="status">${esc(x.status)}</span>`}</div>`).join('') || '<p>No BTC submissions.</p>';
    const postsHtml = (posts || []).map(x => `<div class="row"><span>${esc(x.caption || '(No caption)')}<br><small>${formatDate(x.created_at)}</small></span><form method="post" action="/admin/posts/${x.id}/delete">${csrfField(req)}<button class="danger-button" onclick="return confirm('Delete this post?')">Delete</button></form></div>`).join('') || '<p>No posts yet.</p>';
    const usersHtml = (users || []).map(x => `<div class="row"><span>${esc(x.email)}<br><small>Joined ${formatDate(x.created_at)}</small></span><span>${x.is_admin ? 'admin' : (x.membership_expires_at ? `expires ${new Date(x.membership_expires_at).toLocaleDateString()}` : 'not active')}</span></div>`).join('') || '<p>No members.</p>';
    const paymentHtml = (payments || []).map(x => `<div class="row"><span><strong>${esc(x.users?.email || 'Unknown')}</strong><br><small>${esc(x.provider)} · ${formatDate(x.created_at)}</small></span><span>${esc(money(x.amount, x.currency))}<br><small>${esc(x.status)}</small></span></div>`).join('') || '<p>No payments yet.</p>';
    const body = `<div class="admin-head"><div><span class="eyebrow">OWNER AREA</span><h1>Admin dashboard</h1><p>Manage content, memberships and payment requests.</p></div><div class="actions"><a class="button ghost" href="/admin/backup">Download data backup</a><a class="button ghost" href="/admin/expiry-reminders">Send expiry reminders</a></div></div>${stats}<div class="card"><h2>Publish new content</h2><form method="post" action="/admin/posts" enctype="multipart/form-data">${csrfField(req)}<label>Caption<textarea name="caption" rows="4" maxlength="2000" placeholder="Write a caption…"></textarea></label><label>Photo/video<input type="file" name="media" accept="image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm,video/quicktime" required><small>Maximum ${MAX_UPLOAD_MB} MB.</small></label><button class="button">Publish post</button></form></div><div class="card"><h2>Bitcoin submissions</h2>${btcHtml}</div><div class="card"><h2>Published posts</h2>${postsHtml}</div><div class="card"><h2>Members</h2>${usersHtml}</div><div class="card"><h2>Recent payments</h2>${paymentHtml}</div>`;
    res.send(page('Admin', body, req));
  } catch (e) { next(e); }
});

app.post('/admin/posts', requireAdmin, verifyCsrf, upload.single('media'), async (req, res, next) => {
  let uploadedPath = null;
  try {
    if (!req.file) return res.status(400).send(page('Admin', flash('Choose a photo or video first.'), req));
    const storagePath = makeObjectPath(req.file);
    const { data, error: uploadError } = await supabase.storage.from(SUPABASE_BUCKET).upload(storagePath, req.file.buffer, { contentType: req.file.mimetype, cacheControl: '3600', upsert: false });
    if (uploadError) throw uploadError;
    uploadedPath = data.path;
    const { error: insertError } = await supabase.from('posts').insert({ caption: String(req.body.caption || '').slice(0, 2000), storage_path: uploadedPath, mime_type: req.file.mimetype, created_at: new Date().toISOString() });
    if (insertError) throw insertError;
    res.redirect('/admin');
  } catch (e) {
    if (uploadedPath && supabase) { try { await supabase.storage.from(SUPABASE_BUCKET).remove([uploadedPath]); } catch (_) {} }
    next(e);
  }
});

app.post('/admin/posts/:id/delete', requireAdmin, verifyCsrf, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { data: post, error } = await supabase.from('posts').select('storage_path').eq('id', id).maybeSingle();
    if (error) throw error;
    if (post?.storage_path) await supabase.storage.from(SUPABASE_BUCKET).remove([post.storage_path]);
    const { error: deleteError } = await supabase.from('posts').delete().eq('id', id);
    if (deleteError) throw deleteError;
    res.redirect('/admin');
  } catch (e) { next(e); }
});

app.post('/admin/btc/:id/approve', requireAdmin, verifyCsrf, async (req, res, next) => {
  try {
    const { data: s, error } = await supabase.from('btc_submissions').select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (s && s.status === 'pending') {
      const exp = await extendMembership(s.user_id, 30);
      const { error: btcError } = await supabase.from('btc_submissions').update({ status: 'approved' }).eq('id', s.id);
      if (btcError) throw btcError;
      const user = await getUserById(s.user_id);
      await sendEmail(user?.email, `${SITE_NAME} — membership approved`, `<h2>Your membership is active 💗</h2><p>Your 30-day membership is active until ${esc(exp.toLocaleString())}.</p><p><a href="${esc(publicBaseUrl(req))}/feed">Open your private feed</a></p>`);
    }
    res.redirect('/admin');
  } catch (e) { next(e); }
});

app.get('/admin/backup', requireAdmin, async (req, res, next) => {
  try {
    const [{ data: users }, { data: posts }, { data: payments }, { data: btc }, { data: comments }, { data: likes }] = await Promise.all([
      supabase.from('users').select('id,email,is_admin,membership_expires_at,created_at'),
      supabase.from('posts').select('*'),
      supabase.from('payments').select('*'),
      supabase.from('btc_submissions').select('*'),
      supabase.from('comments').select('*'),
      supabase.from('post_likes').select('*')
    ]);
    const backup = { exported_at: new Date().toISOString(), site: SITE_NAME, users, posts, payments, btc_submissions: btc, comments, post_likes: likes };
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="ruby-parker-backup-${new Date().toISOString().slice(0,10)}.json"`);
    res.send(JSON.stringify(backup, null, 2));
  } catch (e) { next(e); }
});

app.get('/admin/expiry-reminders', requireAdmin, async (req, res, next) => {
  try {
    const until = new Date(); until.setDate(until.getDate() + 3);
    const { data: users, error } = await supabase.from('users').select('id,email,membership_expires_at').not('membership_expires_at', 'is', null).gte('membership_expires_at', new Date().toISOString()).lte('membership_expires_at', until.toISOString());
    if (error) throw error;
    let sent = 0;
    if (mailer) for (const u of users || []) { const ok = await sendEmail(u.email, `${SITE_NAME} — membership reminder`, `<h2>Your membership expires soon 💗</h2><p>Your membership expires on ${esc(new Date(u.membership_expires_at).toLocaleString())}.</p><p><a href="${esc(publicBaseUrl(req))}/join">Renew membership</a></p>`); if (ok) sent++; }
    const message = mailer ? `Expiry reminders sent: ${sent}.` : 'Email is not configured yet. Add SMTP settings in Render to enable reminders.';
    res.send(page('Expiry reminders', `<div class="card narrow center"><h1>Expiry reminders</h1><p>${esc(message)}</p><a class="button" href="/admin">Back to admin</a></div>`, req));
  } catch (e) { next(e); }
});

app.use((err, req, res, _next) => {
  console.error(err);
  const message = err.code === 'LIMIT_FILE_SIZE' ? `That file is too large. Maximum size is ${MAX_UPLOAD_MB} MB.` : (err.message || 'Something went wrong.');
  res.status(500).send(page('Error', flash(message) + '<a href="/">Back home</a>', req));
});

(async () => {
  try { if (supabase) await ensureAdmin(); }
  catch (error) { console.error('Startup error:', error); }
  app.listen(PORT, '0.0.0.0', () => console.log(`${SITE_NAME} running on port ${PORT}`));
})();
