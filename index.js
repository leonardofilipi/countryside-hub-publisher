// index.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import { randomUUID as uuid } from 'crypto';
import pkg from 'pg';
import fs from 'fs';

const { Pool } = pkg;

// ====== ENV ======
const {
  PORT = 10000,
  JWT_SECRET = 'change-me',
  CORS_ORIGIN = '',
  PUBLIC_URL = '',
  SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS, MAIL_FROM,
  DATABASE_URL,
  SHOPIFY_STORE,
  SHOPIFY_ADMIN_TOKEN
} = process.env;

// ====== APP & MIDDLEWARE ======
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN ? CORS_ORIGIN.split(',').map(s => s.trim()) : true,
  credentials: true
}));
app.use(express.urlencoded({ extended: true }));

// ====== DB (Postgres) ======
const pool = DATABASE_URL
  ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

async function ensureSchema(){
  if (!pool) return;
  await pool.query(`
    create extension if not exists pgcrypto;

    create table if not exists users (
      id uuid primary key default gen_random_uuid(),
      email text unique not null,
      password_hash text not null,
      name text,
      phone text,
      verified boolean default false,
      created_at timestamptz default now()
    );

    create table if not exists verify_tokens (
      token uuid primary key,
      user_email text not null,
      created_at timestamptz default now()
    );

    create table if not exists reset_tokens (
      token uuid primary key,
      user_email text not null,
      created_at timestamptz default now()
    );

    create table if not exists reviews (
      id uuid primary key default gen_random_uuid(),
      seller_email text not null,
      reviewer_email text not null,
      rating int check(rating between 1 and 5) not null,
      title text,
      body text,
      created_at timestamptz default now(),
      approved boolean default true
    );
  `);
}
ensureSchema().catch(console.error);

// ====== Mailer (Zoho) ======
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 465),
  secure: String(SMTP_SECURE).toLowerCase() === 'true',
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

// ====== Helpers ======
function setSession(res, payload){
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('csh_sid', token, { httpOnly: true, sameSite: 'lax', secure: true, path: '/' });
}
function clearSession(res){ res.clearCookie('csh_sid', { path: '/' }); }
function auth(req, res, next){
  const t = req.cookies.csh_sid;
  if (!t) return res.status(401).json({ error: 'not_auth' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'bad_token' }); }
}

// ====== AUTH ROUTES ======
app.post('/auth/register', async (req, res) => {
  const { email, password, name, phone } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });

  const hash = await bcrypt.hash(password, 10);

  if (pool){
    const q = `
      insert into users (email, password_hash, name, phone)
      values ($1,$2,$3,$4)
      on conflict (email) do update set password_hash = excluded.password_hash
      returning email, verified, name, phone`;
    await pool.query(q, [email, hash, name || null, phone || null]);
  }

  const token = uuid();
  if (pool){
    await pool.query('insert into verify_tokens(token, user_email) values($1,$2)', [token, email]);
  }

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: 'Confirme seu e-mail – Countryside Hub',
    html: `
      <p>Olá${name ? ' ' + name.split(' ')[0] : ''}!</p>
      <p>Confirme seu e-mail clicando no link abaixo:</p>
      <p><a href="${PUBLIC_URL}/auth/verify?token=${token}">Confirmar e-mail</a></p>
    `
  });

  setSession(res, { email });
  res.json({ ok: true, pendingVerification: true });
});

app.get('/auth/verify', async (req, res) => {
  const { token } = req.query;
  if (!token || !pool) return res.status(400).send('Invalid');

  const { rows } = await pool.query('select user_email from verify_tokens where token=$1', [token]);
  if (!rows.length) return res.status(400).send('Token inválido ou expirado');

  const email = rows[0].user_email;
  await pool.query('update users set verified=true where email=$1', [email]);
  await pool.query('delete from verify_tokens where token=$1', [token]);

  res.send('E-mail verificado com sucesso. Você já pode fechar esta aba.');
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });

  if (!pool) return res.status(500).json({ error: 'db_unavailable' });
  const { rows } = await pool.query('select email, password_hash, verified, name from users where email=$1', [email]);
  if (!rows.length) return res.status(401).json({ error: 'invalid_credentials' });

  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  setSession(res, { email });
  res.json({ ok: true, verified: rows[0].verified, name: rows[0].name });
});

app.get('/auth/me', auth, async (req, res) => {
  if (!pool) return res.json({ email: req.user.email, verified: false });
  const { rows } = await pool.query('select email, verified, name, phone from users where email=$1', [req.user.email]);
  res.json(rows[0] || { email: req.user.email, verified: false });
});

app.post('/auth/logout', (req, res) => { clearSession(res); res.json({ ok: true }); });

app.post('/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });

  const token = uuid();
  if (pool){
    await pool.query('insert into reset_tokens(token, user_email) values($1,$2)', [token, email]);
  }

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: 'Redefinição de senha – Countryside Hub',
    html: `<p><a href="${PUBLIC_URL}/auth/reset?token=${token}">Redefinir senha</a></p>`
  });

  res.json({ ok: true });
});

app.get('/auth/reset', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Token inválido');
  res.send(`
    <form method="POST" action="/auth/reset">
      <input type="hidden" name="token" value="${token}" />
      <label>Nova senha</label><br/>
      <input type="password" name="password" required/>
      <button type="submit">Salvar</button>
    </form>
  `);
});

app.post('/auth/reset', async (req, res) => {
  const { token, password } = req.body;
  if (!pool) return res.status(500).send('DB indisponível');

  const { rows } = await pool.query('select user_email from reset_tokens where token=$1', [token]);
  if (!rows.length) return res.status(400).send('Token inválido');

  const hash = await bcrypt.hash(password, 10);
  await pool.query('update users set password_hash=$1 where email=$2', [hash, rows[0].user_email]);
  await pool.query('delete from reset_tokens where token=$1', [token]);

  res.send('Senha alterada. Você já pode fechar esta aba e entrar novamente.');
});

// ====== REVIEWS ======
app.post('/reviews', auth, async (req, res) => {
  const { sellerEmail, rating, title, body } = req.body || {};
  if (!sellerEmail || !rating) return res.status(400).json({ error: 'missing_fields' });
  if (!pool) return res.status(500).json({ error: 'db_unavailable' });

  await pool.query(
    'insert into reviews (seller_email, reviewer_email, rating, title, body) values ($1,$2,$3,$4,$5)',
    [sellerEmail, req.user.email, Number(rating), title || null, body || null]
  );

  res.json({ ok: true });

  // trigger recompute (non-blocking)
  try {
    await fetch(`${PUBLIC_URL}/seller/recompute`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ sellerEmail })
    });
  } catch(e) { console.warn('recompute failed (silent):', e?.message); }
});

app.get('/reviews/:sellerEmail', async (req, res) => {
  if (!pool) return res.json([]);
  const { rows } = await pool.query(
    'select rating, title, body, reviewer_email, created_at from reviews where seller_email=$1 and approved=true order by created_at desc limit 50',
    [req.params.sellerEmail]
  );
  res.json(rows);
});

// ====== SELLER AGGREGATION + SHOPIFY METAOBJECT UPDATE ======
async function shopifyGraphQL(query, variables = {}){
  if (!SHOPIFY_STORE || !SHOPIFY_ADMIN_TOKEN) {
    throw new Error('Shopify Admin API não configurada');
  }
  const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-07/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN
    },
    body: JSON.stringify({ query, variables })
  });
  const j = await r.json();
  if (j.errors || j.data?.metaobjectUpdate?.userErrors?.length) {
    console.error('Shopify GraphQL error', JSON.stringify(j));
    throw new Error('Shopify GraphQL error');
  }
  return j.data;
}

app.get('/seller/aggregate/:email', async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'db_unavailable' });
  const { rows } = await pool.query(
    'select coalesce(avg(rating),0)::float as avg, count(*)::int as cnt from reviews where seller_email=$1 and approved=true',
    [req.params.email]
  );
  res.json(rows[0]);
});

app.post('/seller/recompute', async (req, res) => {
  try {
    const { sellerEmail } = req.body || {};
    if (!sellerEmail) return res.status(400).json({ error: 'sellerEmail_required' });
    if (!pool) return res.status(500).json({ error: 'db_unavailable' });

    const { rows } = await pool.query(
      'select coalesce(avg(rating),0)::float as avg, count(*)::int as cnt from reviews where seller_email=$1 and approved=true',
      [sellerEmail]
    );
    const avg = Number(rows[0].avg || 0);
    const cnt = Number(rows[0].cnt || 0);

    const Q_FIND = `
      query($q: String!){
        metaobjects(type: "perfil_do_vendedor", first: 1, query: $q){
          nodes { id handle }
        }
      }`;
    const findQ = `contact_email_e_mail_de_contato:"${sellerEmail.replace(/"/g,'\\"')}"`;
    const found = await shopifyGraphQL(Q_FIND, { q: findQ });
    const node = found.metaobjects.nodes[0];
    if (!node) return res.status(404).json({ error: 'metaobject_not_found' });

    const M_UPDATE = `
      mutation($id: ID!, $fields: [MetaobjectFieldInput!]!){
        metaobjectUpdate(id: $id, metaobject: { fields: $fields }){
          metaobject { id }
          userErrors { field message }
        }
      }`;
    const fields = [
      { key: "rating_nota_media", value: avg.toFixed(2) },
      { key: "numero_de_avaliacoes", value: String(cnt) }
    ];
    await shopifyGraphQL(M_UPDATE, { id: node.id, fields });

    res.json({ ok: true, avg, cnt, handle: node.handle });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'update_failed' });
  }
});

// ====== CatFinder JSON endpoint (arquivo estático) ======
app.get('/catfinder.json', (req, res) => {
  try {
    const j = fs.readFileSync('./data/catfinder.json', 'utf8');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.send(j);
  } catch (e) {
    console.error('Erro lendo data/catfinder.json:', e?.message);
    res.status(500).json({ error: 'catfinder_read_failed' });
  }
});

// ====== START ======
app.listen(PORT, () => {
  console.log(`CSH service running on :${PORT}`);
});
