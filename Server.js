require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
// Render terminates HTTPS at its proxy. Trust the proxy so secure cookies work correctly.
app.set('trust proxy', true);
const PORT = Number(process.env.PORT || 10000);
const SITE_NAME = process.env.SITE_NAME || 'Ruby Parker';
const BTC_ADDRESS = process.env.BTC_ADDRESS || '';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || '';
const BASE_URL = process.env.BASE_URL || '';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'private', 'uploads');
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });
const db = new Database(path.join(dataDir, 'ruby-parker.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 is_admin INTEGER NOT NULL DEFAULT 0,
 membership_expires_at TEXT,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 caption TEXT NOT NULL DEFAULT '',
 filename TEXT,
 mime_type TEXT,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 provider TEXT NOT NULL,
 reference TEXT UNIQUE,
 amount INTEGER NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS btc_submissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 tx_hash TEXT NOT NULL,
 amount_note TEXT,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = String(process.env.ADMIN_PASSWORD || '');
if (adminEmail && adminPassword) {
  const passwordHash = bcrypt.hashSync(adminPassword, 12);
  const existing = db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail);
  if (!existing) {
    db.prepare('INSERT INTO users (email,password_hash,is_admin,created_at) VALUES (?,?,1,?)')
      .run(adminEmail, passwordHash, new Date().toISOString());
  } else {
    // If the admin email was previously registered as a normal member,
    // promote that account to admin and sync its password from Render.
    db.prepare('UPDATE users SET is_admin=1, password_hash=? WHERE id=?')
      .run(passwordHash, existing.id);
  }
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieSession({
  name: 'ruby_parker_session_v2',
  keys: [process.env.SESSION_SECRET || 'dev-only-change-this-secret'],
  httpOnly: true,
  sameSite: 'lax',
  secure: IS_PRODUCTION,
  path: '/',
  overwrite: true,
  maxAge: 1000 * 60 * 60 * 24 * 30
}));
app.use('/public', express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
    }
  }),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = /^(image|video)\/(jpeg|png|gif|webp|mp4|webm|quicktime)$/i.test(file.mimetype);
    cb(allowed ? null : new Error('Only image and video files are allowed.'), allowed);
  }
});

function user(req) { return req.session.userId ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId) : null; }
function activeMember(u) { return u && (u.is_admin || (u.membership_expires_at && new Date(u.membership_expires_at) > new Date())); }
function requireLogin(req,res,next){ const u=user(req); if(!u) return res.redirect('/login'); req.currentUser=u; next(); }
function requireMember(req,res,next){ const u=user(req); if(!activeMember(u)) return res.redirect('/join'); req.currentUser=u; next(); }
function requireAdmin(req,res,next){ const u=user(req); if(!u || !u.is_admin) return res.status(403).send(page('Forbidden','<div class="card"><h1>403</h1><p>Admin access only.</p></div>')); req.currentUser=u; next(); }
function esc(v=''){return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function page(title,body,req){
 const u=req ? user(req) : null;
 const nav = u ? `<a href="/feed">Feed</a>${u.is_admin?'<a href="/admin">Admin</a>':''}<form method="post" action="/logout" class="inline"><button>Log out</button></form>` : `<a href="/login">Log in</a><a class="pill" href="/join">Join</a>`;
 return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} Â· ${esc(SITE_NAME)}</title><link rel="stylesheet" href="/public/style.css"></head><body><header><a class="brand" href="/">${esc(SITE_NAME)}</a><nav>${nav}</nav></header><main>${body}</main><footer>Â© ${new Date().getFullYear()} ${esc(SITE_NAME)}</footer></body></html>`;
}
function flash(msg){return `<div class="notice">${esc(msg)}</div>`;}

app.get('/health', (_req,res)=>res.json({ok:true}));
app.get('/', (req,res)=>res.send(page('Home',`<section class="hero"><div><span class="eyebrow">PRIVATE CREATOR MEMBERSHIP</span><h1>Welcome to ${esc(SITE_NAME)}.</h1><p>Exclusive photos, videos, updates and members-only posts in one private space.</p><div class="actions"><a class="button" href="/join">Join for $10</a><a class="button ghost" href="/login">Member login</a></div></div><div class="hero-card"><div class="orb">RP</div><p>30 days of private access</p><strong>$10</strong></div></section>`,req)));

app.get('/register',(req,res)=>res.send(page('Register',`<div class="card narrow"><h1>Create your account</h1><form method="post"><label>Email<input name="email" type="email" required></label><label>Password<input name="password" type="password" minlength="8" required></label><button class="button">Create account</button></form></div>`,req)));
app.post('/register',(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
 if(!email || password.length<8) return res.status(400).send(page('Register',flash('Use a valid email and a password of at least 8 characters.')+'<a href="/register">Try again</a>',req));
 try { const info=db.prepare('INSERT INTO users (email,password_hash,created_at) VALUES (?,?,?)').run(email,bcrypt.hashSync(password,12),new Date().toISOString()); req.session.userId=info.lastInsertRowid; res.redirect('/join'); } catch { res.status(409).send(page('Register',flash('That email is already registered.')+'<a href="/login">Log in</a>',req)); }
});
app.get('/login',(req,res)=>{
 const next=typeof req.query.next==='string' && req.query.next.startsWith('/') ? req.query.next : '';
 const paid=req.query.paid==='1';
 const html=`<div class="card narrow">${paid?'<div class="notice">Payment was successful. Log in to continue.</div>':''}<h1>Member login</h1><form method="post"><input type="hidden" name="next" value="${esc(next)}"><label>Email<input name="email" type="email" autocomplete="email" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="button">Log in</button></form><p>New here? <a href="/register">Create an account</a></p></div>`;
 res.set('Cache-Control','no-store');
 res.send(page('Login',html,req));
});
app.post('/login',(req,res)=>{
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(req.body.email||'').trim().toLowerCase());
 if(!u||!bcrypt.compareSync(String(req.body.password||''),u.password_hash)) return res.status(401).send(page('Login',flash('Invalid email or password.')+'<a href="/login">Try again</a>',req));
 req.session.userId=u.id;
 const next=typeof req.body.next==='string' && req.body.next.startsWith('/') ? req.body.next : '';
 res.set('Cache-Control','no-store');
 res.redirect(u.is_admin?'/admin':(next||'/join'));
});
app.post('/logout',(req,res)=>{req.session=null;res.redirect('/')});

app.get('/join',(req,res)=>{
 const currentUser=user(req);
 const payUi=currentUser ? `<button class="button" id="paystack-btn" onclick="pay()">Pay $10 with Paystack</button>` : '<a class="button" href="/login?next=/join">Log in to pay</a>';
 const btcUi=currentUser ? `<form method="post" action="/btc-submit"><input name="tx_hash" placeholder="Bitcoin transaction hash" required><input name="amount_note" placeholder="Amount sent (optional)"><button class="button">Submit BTC payment</button></form>` : '<a href="/login?next=/join">Log in to submit payment</a>';
 const paidMessage=req.query.paid==='1' ? '<div class="notice">Payment verified. Your 30-day membership is active.</div>' : '';
 const html=`<div class="card">${paidMessage}<span class="eyebrow">MEMBERSHIP</span><h1>$10 for 30 days</h1><p>Choose Paystack for online payment, or submit a Bitcoin transaction for admin verification.</p><div class="pay-grid"><section><h2>Pay with Paystack</h2><p>Secure card/bank payment through Paystack.</p>${payUi}</section><section><h2>Pay with Bitcoin</h2><p>Send the $10 equivalent in BTC to:</p><code>${esc(BTC_ADDRESS)}</code><p class="small">After sending, submit the transaction hash for review. Membership is activated only after verification.</p>${btcUi}</section></div></div><script>async function pay(){const b=document.getElementById('paystack-btn');if(b){b.disabled=true;b.textContent='Connecting to Paystackâ¦';}try{const r=await fetch('/api/paystack/init',{method:'POST',headers:{'Accept':'application/json'}});const j=await r.json();if(j.authorization_url){window.location.assign(j.authorization_url);}else{alert(j.error||'Paystack could not start the payment.');if(b){b.disabled=false;b.textContent='Pay $10 with Paystack';}}}catch(e){alert('Could not connect to the payment service.');if(b){b.disabled=false;b.textContent='Pay $10 with Paystack';}}}</script>`;
 res.set('Cache-Control','no-store');
 res.send(page('Join',html,req));
});
app.post('/btc-submit',requireLogin,(req,res)=>{const tx=String(req.body.tx_hash||'').trim();if(tx.length<20)return res.status(400).send(page('Bitcoin',flash('Please enter the transaction hash.'),req));db.prepare('INSERT INTO btc_submissions (user_id,tx_hash,amount_note,created_at) VALUES (?,?,?,?)').run(req.currentUser.id,tx,String(req.body.amount_note||''),new Date().toISOString());res.send(page('Bitcoin submitted',`<div class="card"><h1>Payment submitted</h1><p>Your transaction was submitted for review. Membership will activate after the transaction is verified.</p><a class="button" href="/">Back home</a></div>`,req));});

app.post('/api/paystack/init',requireLogin,async(req,res)=>{
 if(!process.env.PAYSTACK_SECRET_KEY)return res.status(503).json({error:'Paystack secret key has not been configured on the server yet.'});
 const reference=`RP-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
 const currency=String(process.env.PAYSTACK_CURRENCY||'USD').toUpperCase();
 const amount=currency==='USD' ? 1000 : Number(process.env.PAYSTACK_AMOUNT||0);
 if(!amount) return res.status(500).json({error:'PAYSTACK_AMOUNT is not configured for the selected currency.'});
 const callbackBase = BASE_URL || (IS_PRODUCTION ? `https://${req.get('host')}` : `${req.protocol}://${req.get('host')}`);
 const callbackUrl=`${callbackBase.replace(/\/$/,'')}/paystack/callback`;
 try {
   const r=await fetch('https://api.paystack.co/transaction/initialize',{
     method:'POST',
     headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET_KEY}`,'Content-Type':'application/json'},
     body:JSON.stringify({email:req.currentUser.email,amount,currency,reference,callback_url:callbackUrl,metadata:{user_id:req.currentUser.id,site:SITE_NAME}})
   });
   const j=await r.json();
   if(!r.ok||!j.status) return res.status(400).json({error:j.message||'Paystack initialization failed'});
   db.prepare('INSERT INTO payments (user_id,provider,reference,amount,status,created_at) VALUES (?,?,?,?,?,?)').run(req.currentUser.id,'paystack',reference,amount,'initialized',new Date().toISOString());
   res.json({authorization_url:j.data.authorization_url,reference});
 } catch(e){
   console.error('Paystack initialization error:',e);
   res.status(500).json({error:'Payment service error'});
 }
});
app.get('/paystack/callback',async(req,res)=>{
 const ref=String(req.query.reference||'').trim();
 if(!ref)return res.redirect('/join');
 if(!process.env.PAYSTACK_SECRET_KEY)return res.status(503).send(page('Payment',flash('Paystack is not configured on the server.'),req));
 try {
   const r=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`,{headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET_KEY}`}});
   const j=await r.json();
   const p=db.prepare('SELECT * FROM payments WHERE reference=?').get(ref);
   const expectedAmount=p ? Number(p.amount) : 1000;
   const expectedCurrency=String(process.env.PAYSTACK_CURRENCY||'USD').toUpperCase();
   if(p && j.status&&j.data&&j.data.status==='success'&&Number(j.data.amount)>=expectedAmount&&String(j.data.currency||'').toUpperCase()===expectedCurrency){
     if(p.status!=='verified'){
       const exp=new Date();
       exp.setDate(exp.getDate()+30);
       db.prepare('UPDATE users SET membership_expires_at=? WHERE id=?').run(exp.toISOString(),p.user_id);
       db.prepare('UPDATE payments SET status=? WHERE id=?').run('verified',p.id);
     }
     const loggedInUser=user(req);
     if(loggedInUser && Number(loggedInUser.id)===Number(p.user_id)) return res.redirect('/feed');
     return res.redirect('/login?next=/join&paid=1');
   }
   console.error('Paystack verification failed:', j.message || j.data);
   res.status(400).send(page('Payment',flash('Payment was not verified as successful. Please contact support if you were charged.'),req));
 } catch(e){
   console.error('Paystack verification error:',e);
   res.status(500).send(page('Payment',flash('Could not verify the payment.'),req));
 }
});

app.get('/feed',requireMember,(req,res)=>{const posts=db.prepare('SELECT * FROM posts ORDER BY created_at DESC').all();const cards=posts.length?posts.map(p=>`<article class="post">${p.filename?`<${p.mime_type.startsWith('video/')?'video controls':'img src="/media/'+encodeURIComponent(p.filename)+'"'} ${p.mime_type.startsWith('video/')?'src="/media/'+encodeURIComponent(p.filename)+'"':''}></${p.mime_type.startsWith('video/')?'video':'img'}>`:''}<div class="post-body"><p>${esc(p.caption)}</p><small>${new Date(p.created_at).toLocaleString()}</small></div></article>`).join(''):'<div class="card"><h2>Your private feed is ready.</h2><p>No posts yet.</p></div>';res.send(page('Feed',`<div class="feed-head"><div><span class="eyebrow">MEMBERS ONLY</span><h1>Private feed</h1></div><p>Membership active until ${new Date(req.currentUser.membership_expires_at).toLocaleDateString()}</p></div><div class="posts">${cards}</div>`,req));});
app.get('/media/:name',requireMember,(req,res)=>{const name=path.basename(req.params.name);const file=path.join(uploadDir,name);if(!fs.existsSync(file))return res.sendStatus(404);res.sendFile(file);});

app.get('/admin',requireAdmin,(req,res)=>{const users=db.prepare('SELECT id,email,is_admin,membership_expires_at,created_at FROM users ORDER BY id DESC').all();const btc=db.prepare(`SELECT b.*,u.email FROM btc_submissions b JOIN users u ON u.id=b.user_id ORDER BY b.id DESC`).all();res.send(page('Admin',`<div class="card"><h1>Admin dashboard</h1><p>Upload a photo or video and publish it to members.</p><form method="post" action="/admin/posts" enctype="multipart/form-data"><label>Caption<textarea name="caption" rows="4"></textarea></label><label>Photo/video<input type="file" name="media" accept="image/*,video/*"></label><button class="button">Publish post</button></form></div><div class="card"><h2>Bitcoin submissions</h2>${btc.map(x=>`<div class="row"><span><strong>${esc(x.email)}</strong><br><code>${esc(x.tx_hash)}</code><br><small>${esc(x.amount_note||'')}</small></span>${x.status==='pending'?`<form method="post" action="/admin/btc/${x.id}/approve"><button class="button">Approve 30 days</button></form>`:`<span>${esc(x.status)}</span>`}</div>`).join('')||'<p>No BTC submissions.</p>'}</div><div class="card"><h2>Members</h2>${users.map(x=>`<div class="row"><span>${esc(x.email)}</span><span>${x.membership_expires_at?`expires ${new Date(x.membership_expires_at).toLocaleDateString()}`:'not active'}</span></div>`).join('')}</div>`,req))});
app.post('/admin/posts',requireAdmin,upload.single('media'),(req,res)=>{db.prepare('INSERT INTO posts (caption,filename,mime_type,created_at) VALUES (?,?,?,?)').run(String(req.body.caption||''),req.file?req.file.filename:null,req.file?req.file.mimetype:null,new Date().toISOString());res.redirect('/admin');});
app.post('/admin/btc/:id/approve',requireAdmin,(req,res)=>{const s=db.prepare('SELECT * FROM btc_submissions WHERE id=?').get(req.params.id);if(s){const exp=new Date();exp.setDate(exp.getDate()+30);db.prepare('UPDATE users SET membership_expires_at=? WHERE id=?').run(exp.toISOString(),s.user_id);db.prepare('UPDATE btc_submissions SET status=? WHERE id=?').run('approved',s.id);}res.redirect('/admin');});

app.use((err,req,res,next)=>{console.error(err);res.status(500).send(page('Error',flash(err.message||'Something went wrong.')+'<a href="/">Back home</a>',req));});
app.listen(PORT,'0.0.0.0',()=>console.log(`${SITE_NAME} running on port ${PORT}`));
