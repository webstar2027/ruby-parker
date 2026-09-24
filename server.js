require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 10000);
const SITE_NAME = process.env.SITE_NAME || 'Ruby Parker';
const BTC_ADDRESS = process.env.BTC_ADDRESS || '';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || '';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_CURRENCY = String(process.env.PAYSTACK_CURRENCY || 'USD').toUpperCase();
const PAYSTACK_AMOUNT = Number(process.env.PAYSTACK_AMOUNT || 1000); // USD cents by default
const PAYSTACK_DISPLAY_PRICE = process.env.PAYSTACK_DISPLAY_PRICE || '$10';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || '';
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'ruby-content';
const BASE_URL = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || '';

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SECRET_KEY. Set them in Render Environment Variables.');
}

const supabase = (SUPABASE_URL && SUPABASE_SECRET_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  : null;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieSession({
  name: 'ruby_parker_session',
  keys: [process.env.SESSION_SECRET || 'dev-only-change-this-secret'],
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 1000 * 60 * 60 * 24 * 30
}));
app.use('/public', express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = /^(image|video)\/(jpeg|png|gif|webp|mp4|webm|quicktime)$/i.test(file.mimetype);
    cb(allowed ? null : new Error('Only image and video files are allowed.'), allowed);
  }
});

function esc(v = '') {
  return String(v).replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
}

function page(title, body, req) {
  const u = req?.currentUser || null;
  const nav = u
    ? `<a href="/feed">Feed</a>${u.is_admin ? '<a href="/admin">Admin</a>' : ''}<form method="post" action="/logout" class="inline"><button>Log out</button></form>`
    : `<a href="/login">Log in</a><a class="pill" href="/join">Join</a>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · ${esc(SITE_NAME)}</title><link rel="stylesheet" href="/public/style.css"></head><body><header><a class="brand" href="/">${esc(SITE_NAME)}</a><nav>${nav}</nav></header><main>${body}</main><footer>© ${new Date().getFullYear()} ${esc(SITE_NAME)}</footer></body></html>`;
}

function flash(msg) {
  return `<div class="notice">${esc(msg)}</div>`;
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

function activeMember(u) {
  return Boolean(u && (u.is_admin || (u.membership_expires_at && new Date(u.membership_expires_at) > new Date())));
}

async function attachCurrentUser(req) {
  if (!req.session?.userId) return null;
  try {
    req.currentUser = await getUserById(req.session.userId);
  } catch (error) {
    console.error('User lookup failed:', error);
    req.currentUser = null;
  }
  return req.currentUser;
}

async function requireLogin(req, res, next) {
  try {
    const u = await attachCurrentUser(req);
    if (!u) return res.redirect('/login');
    next();
  } catch (error) {
    next(error);
  }
}

async function requireMember(req, res, next) {
  try {
    const u = await attachCurrentUser(req);
    if (!activeMember(u)) return res.redirect('/join');
    next();
  } catch (error) {
    next(error);
  }
}

async function requireAdmin(req, res, next) {
  try {
    const u = await attachCurrentUser(req);
    if (!u || !u.is_admin) return res.status(403).send(page('Forbidden', '<div class="card"><h1>403</h1><p>Admin access only.</p></div>', req));
    next();
  } catch (error) {
    next(error);
  }
}

async function ensureAdmin() {
  if (!supabase) return;
  const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');
  if (!adminEmail || !adminPassword) return;

  const existing = await getUserByEmail(adminEmail);
  if (!existing) {
    const { error } = await supabase.from('users').insert({
      email: adminEmail,
      password_hash: bcrypt.hashSync(adminPassword, 12),
      is_admin: true,
      created_at: new Date().toISOString()
    });
    if (error) throw error;
  } else if (!existing.is_admin) {
    const { error } = await supabase.from('users').update({ is_admin: true }).eq('id', existing.id);
    if (error) throw error;
  }
}

function publicBaseUrl(req) {
  return BASE_URL || `${req.protocol}://${req.get('host')}`;
}

function makeObjectPath(file) {
  const ext = path.extname(file.originalname || '').toLowerCase() || '';
  return `posts/${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
}

app.get('/health', async (_req, res) => {
  if (!supabase) return res.status(503).json({ ok: false, error: 'Supabase is not configured' });
  const { error } = await supabase.from('users').select('id').limit(1);
  if (error) return res.status(503).json({ ok: false, error: error.message });
  res.json({ ok: true, database: 'supabase' });
});

app.get('/', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    res.send(page('Home', `<section class="hero"><div><span class="eyebrow">PRIVATE CREATOR MEMBERSHIP</span><h1>Welcome to ${esc(SITE_NAME)}.</h1><p>Exclusive photos, videos, updates and members-only posts in one private space.</p><div class="actions"><a class="button" href="/join">Join for ${esc(PAYSTACK_DISPLAY_PRICE)}</a><a class="button ghost" href="/login">Member login</a></div></div><div class="hero-card"><div class="orb">RP</div><p>30 days of private access</p><strong>${esc(PAYSTACK_DISPLAY_PRICE)}</strong></div></section>`, req));
  } catch (e) { next(e); }
});

app.get('/register', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    res.send(page('Register', `<div class="card narrow"><h1>Create your account</h1><form method="post"><label>Email<input name="email" type="email" required></label><label>Password<input name="password" type="password" minlength="8" required></label><button class="button">Create account</button></form></div>`, req));
  } catch (e) { next(e); }
});

app.post('/register', async (req, res, next) => {
  try {
    if (!supabase) return res.status(503).send(page('Register', flash('Database is not configured yet.'), req));
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || password.length < 8) return res.status(400).send(page('Register', flash('Use a valid email and a password of at least 8 characters.') + '<a href="/register">Try again</a>', req));
    const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
    if (existing) return res.status(409).send(page('Register', flash('That email is already registered.') + '<a href="/login">Log in</a>', req));
    const { data, error } = await supabase.from('users').insert({
      email,
      password_hash: bcrypt.hashSync(password, 12),
      is_admin: false,
      created_at: new Date().toISOString()
    }).select('id').single();
    if (error) throw error;
    req.session.userId = data.id;
    res.redirect('/join');
  } catch (e) { next(e); }
});

app.get('/login', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    res.send(page('Login', `<div class="card narrow"><h1>Member login</h1><form method="post"><label>Email<input name="email" type="email" required></label><label>Password<input name="password" type="password" required></label><button class="button">Log in</button></form><p>New here? <a href="/register">Create an account</a></p></div>`, req));
  } catch (e) { next(e); }
});

app.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const u = await getUserByEmail(email);
    if (!u || !bcrypt.compareSync(password, u.password_hash)) return res.status(401).send(page('Login', flash('Invalid email or password.') + '<a href="/login">Try again</a>', req));
    req.session.userId = u.id;
    res.redirect(u.is_admin ? '/admin' : '/join');
  } catch (e) { next(e); }
});

app.post('/logout', (req, res) => {
  req.session = null;
  res.redirect('/');
});

app.get('/join', async (req, res, next) => {
  try {
    await attachCurrentUser(req);
    const u = req.currentUser;
    res.send(page('Join', `<div class="card"><span class="eyebrow">MEMBERSHIP</span><h1>${esc(PAYSTACK_DISPLAY_PRICE)} for 30 days</h1><p>Choose Paystack for online payment, or submit a Bitcoin transaction for admin verification.</p><div class="pay-grid"><section><h2>Pay with Paystack</h2><p>Secure card/bank payment through Paystack.</p>${u ? `<button class="button" onclick="pay()">Pay ${esc(PAYSTACK_DISPLAY_PRICE)} with Paystack</button>` : '<a class="button" href="/login">Log in to pay</a>'}</section><section><h2>Pay with Bitcoin</h2><p>Send the $10 equivalent in BTC to:</p><code>${esc(BTC_ADDRESS)}</code><p class="small">After sending, submit the transaction hash for review. Membership is activated only after verification.</p>${u ? `<form method="post" action="/btc-submit"><input name="tx_hash" placeholder="Bitcoin transaction hash" required><input name="amount_note" placeholder="Amount sent (optional)"><button class="button">Submit BTC payment</button></form>` : '<a href="/login">Log in to submit payment</a>'}</section></div></div><script>async function pay(){const b=document.querySelector('.pay-grid .button');if(b){b.disabled=true;b.textContent='Connecting to Paystack...';}try{const r=await fetch('/api/paystack/init',{method:'POST'});const j=await r.json();if(j.authorization_url)location.href=j.authorization_url;else alert(j.error||'Paystack is not configured yet.');}catch(e){alert('Could not connect to the payment service.');}finally{if(b){b.disabled=false;b.textContent='Pay ${esc(PAYSTACK_DISPLAY_PRICE)} with Paystack';}}}</script>`, req));
  } catch (e) { next(e); }
});

app.post('/btc-submit', requireLogin, async (req, res, next) => {
  try {
    const tx = String(req.body.tx_hash || '').trim();
    if (tx.length < 20) return res.status(400).send(page('Bitcoin', flash('Please enter the transaction hash.'), req));
    const { error } = await supabase.from('btc_submissions').insert({
      user_id: req.currentUser.id,
      tx_hash: tx,
      amount_note: String(req.body.amount_note || ''),
      status: 'pending',
      created_at: new Date().toISOString()
    });
    if (error) throw error;
    res.send(page('Bitcoin submitted', `<div class="card"><h1>Payment submitted</h1><p>Your transaction was submitted for review. Membership will activate after the transaction is verified.</p><a class="button" href="/">Back home</a></div>`, req));
  } catch (e) { next(e); }
});

app.post('/api/paystack/init', requireLogin, async (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return res.status(503).json({ error: 'Paystack secret key has not been configured on the server yet.' });
  if (!supabase) return res.status(503).json({ error: 'Database is not configured yet.' });
  const reference = `RP-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    const callback_url = `${publicBaseUrl(req)}/paystack/callback`;
    const r = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: req.currentUser.email,
        amount: PAYSTACK_AMOUNT,
        currency: PAYSTACK_CURRENCY,
        reference,
        callback_url,
        metadata: { product: 'Ruby Parker 30-day membership', user_id: req.currentUser.id }
      })
    });
    const j = await r.json();
    if (!r.ok || !j.status) return res.status(400).json({ error: j.message || 'Paystack initialization failed' });
    const { error } = await supabase.from('payments').insert({
      user_id: req.currentUser.id,
      provider: 'paystack',
      reference,
      amount: PAYSTACK_AMOUNT,
      currency: PAYSTACK_CURRENCY,
      status: 'initialized',
      created_at: new Date().toISOString()
    });
    if (error) throw error;
    res.json({ authorization_url: j.data.authorization_url });
  } catch (e) {
    console.error('Paystack init error:', e);
    res.status(500).json({ error: 'Payment service error' });
  }
});

app.get('/paystack/callback', async (req, res, next) => {
  const ref = String(req.query.reference || '');
  if (!ref) return res.redirect('/join');
  if (!PAYSTACK_SECRET_KEY) return res.status(503).send(page('Payment', flash('Paystack is not configured on the server.'), req));
  try {
    const { data: payment, error: paymentError } = await supabase.from('payments').select('*').eq('reference', ref).maybeSingle();
    if (paymentError) throw paymentError;
    if (!payment) return res.status(400).send(page('Payment', flash('Payment reference was not found.'), req));

    const r = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
    });
    const j = await r.json();
    const success = Boolean(
      j.status &&
      j.data &&
      j.data.status === 'success' &&
      String(j.data.currency || '').toUpperCase() === PAYSTACK_CURRENCY &&
      Number(j.data.amount) === PAYSTACK_AMOUNT
    );

    if (!success) return res.status(400).send(page('Payment', flash('Payment was not verified as successful.'), req));

    const exp = new Date();
    exp.setDate(exp.getDate() + 30);
    const { error: userError } = await supabase.from('users').update({ membership_expires_at: exp.toISOString() }).eq('id', payment.user_id);
    if (userError) throw userError;
    const { error: updateError } = await supabase.from('payments').update({ status: 'verified' }).eq('id', payment.id);
    if (updateError) throw updateError;

    res.redirect('/login?paid=1');
  } catch (e) { next(e); }
});

app.get('/feed', requireMember, async (req, res, next) => {
  try {
    const { data: posts, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    const cards = posts.length
      ? posts.map(p => {
          const media = p.storage_path
            ? (String(p.mime_type || '').startsWith('video/')
              ? `<video controls preload="metadata" src="/media/${encodeURIComponent(p.id)}"></video>`
              : `<img loading="lazy" src="/media/${encodeURIComponent(p.id)}" alt="">`)
            : '';
          return `<article class="post">${media}<div class="post-body"><p>${esc(p.caption)}</p><small>${new Date(p.created_at).toLocaleString()}</small></div></article>`;
        }).join('')
      : '<div class="card"><h2>Your private feed is ready.</h2><p>No posts yet.</p></div>';
    const expiry = req.currentUser.membership_expires_at ? new Date(req.currentUser.membership_expires_at).toLocaleDateString() : 'unlimited';
    res.send(page('Feed', `<div class="feed-head"><div><span class="eyebrow">MEMBERS ONLY</span><h1>Private feed</h1></div><p>${req.currentUser.is_admin ? 'Admin access' : `Membership active until ${expiry}`}</p></div><div class="posts">${cards}</div>`, req));
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
    const [{ data: users, error: usersError }, { data: btc, error: btcError }, { data: posts, error: postsError }] = await Promise.all([
      supabase.from('users').select('id,email,is_admin,membership_expires_at,created_at').order('id', { ascending: false }),
      supabase.from('btc_submissions').select('*, users(email)').order('id', { ascending: false }),
      supabase.from('posts').select('id,caption,mime_type,created_at').order('created_at', { ascending: false })
    ]);
    if (usersError) throw usersError;
    if (btcError) throw btcError;
    if (postsError) throw postsError;

    const btcHtml = (btc || []).map(x => `<div class="row"><span><strong>${esc(x.users?.email || 'Unknown')}</strong><br><code>${esc(x.tx_hash)}</code><br><small>${esc(x.amount_note || '')}</small></span>${x.status === 'pending' ? `<form method="post" action="/admin/btc/${x.id}/approve"><button class="button">Approve 30 days</button></form>` : `<span>${esc(x.status)}</span>`}</div>`).join('') || '<p>No BTC submissions.</p>';
    const postsHtml = (posts || []).map(x => `<div class="row"><span>${esc(x.caption || '(No caption)')}<br><small>${new Date(x.created_at).toLocaleString()}</small></span><span>${esc(x.mime_type || '')}</span></div>`).join('') || '<p>No posts yet.</p>';
    const usersHtml = (users || []).map(x => `<div class="row"><span>${esc(x.email)}</span><span>${x.is_admin ? 'admin' : (x.membership_expires_at ? `expires ${new Date(x.membership_expires_at).toLocaleDateString()}` : 'not active')}</span></div>`).join('') || '<p>No members.</p>';

    res.send(page('Admin', `<div class="card"><h1>Admin dashboard</h1><p>Upload a photo or video and publish it to members.</p><form method="post" action="/admin/posts" enctype="multipart/form-data"><label>Caption<textarea name="caption" rows="4"></textarea></label><label>Photo/video<input type="file" name="media" accept="image/*,video/*"></label><button class="button">Publish post</button></form></div><div class="card"><h2>Bitcoin submissions</h2>${btcHtml}</div><div class="card"><h2>Published posts</h2>${postsHtml}</div><div class="card"><h2>Members</h2>${usersHtml}</div>`, req));
  } catch (e) { next(e); }
});

app.post('/admin/posts', requireAdmin, upload.single('media'), async (req, res, next) => {
  let uploadedPath = null;
  try {
    if (!req.file) return res.status(400).send(page('Admin', flash('Choose a photo or video first.'), req));
    const storagePath = makeObjectPath(req.file);
    const { data, error: uploadError } = await supabase.storage.from(SUPABASE_BUCKET).upload(storagePath, req.file.buffer, {
      contentType: req.file.mimetype,
      cacheControl: '3600',
      upsert: false
    });
    if (uploadError) throw uploadError;
    uploadedPath = data.path;

    const { error: insertError } = await supabase.from('posts').insert({
      caption: String(req.body.caption || ''),
      storage_path: uploadedPath,
      mime_type: req.file.mimetype,
      created_at: new Date().toISOString()
    });
    if (insertError) throw insertError;
    res.redirect('/admin');
  } catch (e) {
    if (uploadedPath && supabase) {
      try { await supabase.storage.from(SUPABASE_BUCKET).remove([uploadedPath]); } catch (_) {}
    }
    next(e);
  }
});

app.post('/admin/btc/:id/approve', requireAdmin, async (req, res, next) => {
  try {
    const { data: s, error } = await supabase.from('btc_submissions').select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (s) {
      const exp = new Date();
      exp.setDate(exp.getDate() + 30);
      const { error: userError } = await supabase.from('users').update({ membership_expires_at: exp.toISOString() }).eq('id', s.user_id);
      if (userError) throw userError;
      const { error: btcError } = await supabase.from('btc_submissions').update({ status: 'approved' }).eq('id', s.id);
      if (btcError) throw btcError;
    }
    res.redirect('/admin');
  } catch (e) { next(e); }
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).send(page('Error', flash(err.message || 'Something went wrong.') + '<a href="/">Back home</a>', req));
});

(async () => {
  try {
    if (supabase) await ensureAdmin();
  } catch (error) {
    console.error('Startup error:', error);
  }
  app.listen(PORT, '0.0.0.0', () => console.log(`${SITE_NAME} running on port ${PORT}`));
})();
