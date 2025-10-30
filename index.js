// index.js (ESM)
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
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== ENV =====
const {
  NODE_ENV = 'production',
  PORT = 10000,
  JWT_SECRET = 'change-me',
  CORS_ORIGIN = '',                  // "https://countrysidehub.com,https://www.countrysidehub.com,https://admin.shopify.com,https://<store>.myshopify.com"
  COOKIE_DOMAIN,                     // e.g. countrysidehub.com
  PUBLIC_URL = '',                   // e.g. "https://csh-auth-2.onrender.com"

  SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS, MAIL_FROM,

  DATABASE_URL,

  // Shopify Admin (use the myshopify.com domain here)
  SHOPIFY_ADMIN_DOMAIN,              // e.g. "<store>.myshopify.com"
  SHOPIFY_ADMIN_TOKEN
} = process.env;

// ===== App =====
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: CORS_ORIGIN ? CORS_ORIGIN.split(',').map(s => s.trim()) : true,
  credentials: true,
}));

// ===== DB (Postgres) =====
const pool = DATABASE_URL
  ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

async function ensureSchema() {
  if (!pool) return;
  try {
    await pool.query(`
      do $$ begin
        begin
          create extension if not exists pgcrypto;
        exception when others then
          -- ignore extension errors
          null;
        end;
      end $$;

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
        rating int check (rating between 1 and 5) not null,
        title text,
        body text,
        approved boolean default true,
        created_at timestamptz default now()
      );
            create table if not exists products (
        id uuid primary key default gen_random_uuid(),
        owner_email text not null,
        title text not null,
        description text,
        price_cents int not null,
        currency text not null default 'BRL',
        status text not null default 'DRAFT',            -- DRAFT, ACTIVE, ARCHIVED
        shopify_product_id text,                         -- e.g. gid://shopify/Product/123...
        shopify_handle text,
        created_at timestamptz default now(),
        updated_at timestamptz default now()
      );

      create index if not exists idx_products_owner on products(owner_email);

    `);
  } catch (e) {
    console.error('ensureSchema failed', e);
  }
}
ensureSchema().catch(console.error);

// ===== Mailer =====
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 465),
  secure: String(SMTP_SECURE).toLowerCase() === 'true',
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

// ===== Session helpers =====
function setSession(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('csh_sid', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: NODE_ENV === 'production',
    path: '/',
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {})
  });
}
function clearSession(res) {
  res.clearCookie('csh_sid', {
    path: '/',
    ...(COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {})
  });
}
function auth(req, res, next) {
  const t = req.cookies.csh_sid;
  if (!t) return res.status(401).json({ error: 'not_auth' });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'bad_token' });
  }
}

// ===== AUTH =====
app.post('/auth/register', async (req, res) => {
  const { email, password, name, phone } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email_password_required' });
  if (String(password).length < 8) return res.status(400).json({ error: 'weak_password' });

  const hash = await bcrypt.hash(password, 10);

  if (pool) {
    await pool.query(
      `insert into users (email, password_hash, name, phone)
       values ($1,$2,$3,$4)
       on conflict (email) do update set password_hash = excluded.password_hash`,
      [email, hash, name || null, phone || null]
    );
  }

  const token = uuid();
  if (pool) {
    await pool.query('insert into verify_tokens (token, user_email) values ($1,$2)', [token, email]);
  }

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: 'Confirme seu e-mail – Countryside Hub',
    html: `
      <p>Olá${name ? ' ' + name.split(' ')[0] : ''}!</p>
      <p>Confirme seu e-mail clicando no link abaixo:</p>
      <p><a href="${PUBLIC_URL}/auth/verify?token=${token}">Confirmar e-mail</a></p>
    `,
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

app.post('/auth/logout', (_req, res) => { clearSession(res); res.json({ ok: true }); });

app.post('/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });

  const token = uuid();
  if (pool) {
    await pool.query('insert into reset_tokens(token, user_email) values ($1,$2)', [token, email]);
  }

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: 'Redefinição de senha – Countryside Hub',
    html: `<p><a href="${PUBLIC_URL}/auth/reset?token=${token}">Redefinir senha</a></p>`,
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
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).send('Dados inválidos');
  if (!pool) return res.status(500).send('DB indisponível');

  const { rows } = await pool.query('select user_email from reset_tokens where token=$1', [token]);
  if (!rows.length) return res.status(400).send('Token inválido');

  const hash = await bcrypt.hash(password, 10);
  await pool.query('update users set password_hash=$1 where email=$2', [hash, rows[0].user_email]);
  await pool.query('delete from reset_tokens where token=$1', [token]);

  res.send('Senha alterada. Você já pode fechar esta aba e entrar novamente.');
});
function toCents(v) {
  if (v == null) return 0;
  // accepts "123.45", "123,45", number, etc.
  const n = String(v).replace(',', '.');
  return Math.round(parseFloat(n) * 100);
}

// Set vendor metafield on a Shopify product (stores the vendor email)
async function setVendorMetafield(productGid, vendorEmail) {
  const M_SET = `
    mutation metafieldsSet($ownerId: ID!, $metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(ownerId: $ownerId, metafields: $metafields) {
        metafields { id key namespace type value }
        userErrors { field message }
      }
    }`;
  const metafields = [{
    namespace: "csh",
    key: "vendor_email",
    type: "single_line_text_field",
    value: vendorEmail
  }];
  await shopifyGraphQL(M_SET, { ownerId: productGid, metafields });
}

// ===== Reviews =====
app.post('/reviews', auth, async (req, res) => {
  const { sellerEmail, rating, title, body } = req.body || {};
  if (!sellerEmail || !rating) return res.status(400).json({ error: 'missing_fields' });
  if (!pool) return res.status(500).json({ error: 'db_unavailable' });

  await pool.query(
    'insert into reviews (seller_email, reviewer_email, rating, title, body) values ($1,$2,$3,$4,$5)',
    [sellerEmail, req.user.email, Number(rating), title || null, body || null]
  );

  res.json({ ok: true });

  // fire-and-forget recompute in Shopify metaobject
  try {
    await fetch(`${PUBLIC_URL}/seller/recompute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sellerEmail }),
    });
  } catch (e) { console.warn('recompute failed (silent):', e?.message); }
});

app.get('/reviews/:sellerEmail', async (req, res) => {
  if (!pool) return res.json([]);
  const { rows } = await pool.query(
    'select rating, title, body, reviewer_email, created_at from reviews where seller_email=$1 and approved=true order by created_at desc limit 50',
    [req.params.sellerEmail]
  );
  res.json(rows);
});
// ========== Vendor Products API ==========
// All routes require login; they only operate on the authenticated vendor's products.

app.get('/vendor/products', auth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: 'db_unavailable' });
    const { rows } = await pool.query(
      'select * from products where owner_email=$1 order by created_at desc limit 200',
      [req.user.email]
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'list_failed' });
  }
});

// Create local product; optionally publish to Shopify immediately
app.post('/vendor/products', auth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: 'db_unavailable' });
    const { title, description, price, currency = 'BRL', publishToShopify = false, tags = [] } = req.body || {};
    if (!title || !price) return res.status(400).json({ error: 'missing_fields' });

    const price_cents = toCents(price);
    const { rows } = await pool.query(
      `insert into products (owner_email, title, description, price_cents, currency, status)
       values ($1,$2,$3,$4,$5,$6)
       returning *`,
      [req.user.email, title, description || null, price_cents, currency, 'DRAFT']
    );
    const product = rows[0];

    // Optionally create on Shopify
    if (publishToShopify) {
      const M_CREATE = `
        mutation productCreate($input: ProductInput!) {
          productCreate(input: $input) {
            product { id handle }
            userErrors { field message }
          }
        }`;
      const input = {
        title,
        descriptionHtml: description || '',
        vendor: "Countryside Hub",
        tags: Array.isArray(tags) ? tags : [],
        variants: [{ price: (price_cents / 100).toFixed(2) }] // single variant
      };
      const resp = await shopifyGraphQL(M_CREATE, { input });
      const gid = resp.productCreate?.product?.id;
      const handle = resp.productCreate?.product?.handle;
      if (!gid) return res.status(502).json({ error: 'shopify_create_failed' });

      await setVendorMetafield(gid, req.user.email);

      await pool.query(
        'update products set shopify_product_id=$1, shopify_handle=$2, status=$3, updated_at=now() where id=$4',
        [gid, handle || null, 'ACTIVE', product.id]
      );
      product.shopify_product_id = gid;
      product.shopify_handle = handle || null;
      product.status = 'ACTIVE';
    }

    res.status(201).json(product);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'create_failed' });
  }
});

// Update local product; if linked, update Shopify too
app.put('/vendor/products/:id', auth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: 'db_unavailable' });
    const { id } = req.params;
    const { title, description, price, currency, status } = req.body || {};

    // ensure ownership
    const { rows: chk } = await pool.query(
      'select * from products where id=$1 and owner_email=$2',
      [id, req.user.email]
    );
    if (!chk.length) return res.status(404).json({ error: 'not_found' });

    const p = chk[0];
    const price_cents = price != null ? toCents(price) : p.price_cents;

    const { rows } = await pool.query(
      `update products
       set title=coalesce($1,title),
           description=coalesce($2,description),
           price_cents=$3,
           currency=coalesce($4,currency),
           status=coalesce($5,status),
           updated_at=now()
       where id=$6
       returning *`,
       [title, description, price_cents, currency, status, id]
    );
    const updated = rows[0];

    // If linked to Shopify, push updates (title/description/price)
    if (updated.shopify_product_id) {
      const M_UPDATE = `
        mutation productUpdate($input: ProductInput!) {
          productUpdate(input: $input) {
            product { id handle }
            userErrors { field message }
          }
        }`;
      const input = {
        id: updated.shopify_product_id,
        title: updated.title,
        descriptionHtml: updated.description || '',
        variants: [{ price: (updated.price_cents / 100).toFixed(2) }]
      };
      await shopifyGraphQL(M_UPDATE, { input });
      await setVendorMetafield(updated.shopify_product_id, req.user.email);
    }

    res.json(updated);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'update_failed' });
  }
});

// Archive locally; optional: delete on Shopify
app.delete('/vendor/products/:id', auth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: 'db_unavailable' });
    const { id } = req.params;

    const { rows: chk } = await pool.query(
      'select * from products where id=$1 and owner_email=$2',
      [id, req.user.email]
    );
    if (!chk.length) return res.status(404).json({ error: 'not_found' });

    await pool.query(
      'update products set status=$1, updated_at=now() where id=$2',
      ['ARCHIVED', id]
    );

    // If you want to actually delete from Shopify, uncomment below:
    // if (chk[0].shopify_product_id) {
    //   const M_DEL = `
    //     mutation productDelete($id: ID!) {
    //       productDelete(input: { id: $id }) {
    //         deletedProductId
    //         userErrors { field message }
    //       }
    //     }`;
    //   await shopifyGraphQL(M_DEL, { id: chk[0].shopify_product_id });
    // }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'delete_failed' });
  }
});

// Link an existing Shopify product to this vendor (adds metafield + saves GID locally)
app.post('/vendor/products/:id/link-shopify', auth, async (req, res) => {
  try {
    if (!pool) return res.status(500).json({ error: 'db_unavailable' });
    const { id } = req.params;
    const { shopifyProductGid } = req.body || {};
    if (!shopifyProductGid) return res.status(400).json({ error: 'gid_required' });

    const { rows: chk } = await pool.query(
      'select * from products where id=$1 and owner_email=$2',
      [id, req.user.email]
    );
    if (!chk.length) return res.status(404).json({ error: 'not_found' });

    // ensure the product exists and get handle
    const Q = `
      query ($id: ID!) { product(id: $id) { id handle } }
    `;
    const found = await shopifyGraphQL(Q, { id: shopifyProductGid });
    const node = found.product;
    if (!node?.id) return res.status(404).json({ error: 'shopify_not_found' });

    await setVendorMetafield(node.id, req.user.email);

    const { rows } = await pool.query(
      'update products set shopify_product_id=$1, shopify_handle=$2, status=$3, updated_at=now() where id=$4 returning *',
      [node.id, node.handle || null, 'ACTIVE', id]
    );

    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'link_failed' });
  }
});

// ===== Shopify Admin helper =====
async function shopifyGraphQL(query, variables = {}) {
  if (!SHOPIFY_ADMIN_DOMAIN || !SHOPIFY_ADMIN_TOKEN) {
    throw new Error('Shopify Admin API não configurada');
  }
  const r = await fetch(`https://${SHOPIFY_ADMIN_DOMAIN}/admin/api/2024-07/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
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
    const findQ = `contact_email_e_mail_de_contato:"${sellerEmail.replace(/"/g, '\\"')}"`;
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
      { key: 'rating_nota_media', value: avg.toFixed(2) },
      { key: 'numero_de_avaliacoes', value: String(cnt) },
    ];
    await shopifyGraphQL(M_UPDATE, { id: node.id, fields });

    res.json({ ok: true, avg, cnt, handle: node.handle });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'update_failed' });
  }
});

// ===== Categories from CSV =====
const CSV_PATH = path.join(__dirname, 'data', 'csh_categories.csv');

function slugify(txt) {
  return String(txt || '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function loadCSVRows() {
  const raw = fs.readFileSync(CSV_PATH, 'utf8');
  const lines = raw.split(/\r?\n/).filter(Boolean);
  const header = lines.shift().split(',').map(h => h.trim().toLowerCase());
  const idxCat = header.findIndex(h => h === 'categoria');
  const idxSub = header.findIndex(h => h === 'subcategoria');
  const idxItem = header.findIndex(h => h === 'item');

  const rows = [];
  for (const line of lines) {
    const cols = line.split(',').map(c => c.trim());
    rows.push({
      categoria: idxCat >= 0 ? cols[idxCat] : '',
      subcategoria: idxSub >= 0 ? cols[idxSub] : '',
      item: idxItem >= 0 ? cols[idxItem] : '',
    });
  }
  return rows;
}

function buildCatfinderAndVendor() {
  const rows = loadCSVRows();

  const cfItems = [];
  const seen = new Set();
  const byCat = new Map();

  for (const r of rows) {
    if (!r.categoria) continue;

    const cName = r.categoria;
    const cSlug = slugify(cName);
    const cUrl = `/collections/${cSlug}`;

    if (!seen.has(`cat:${cSlug}`)) {
      cfItems.push({ name: cName, slug: cSlug, url: cUrl });
      seen.add(`cat:${cSlug}`);
    }
    if (!byCat.has(cSlug)) {
      byCat.set(cSlug, { name: cName, slug: cSlug, url: cUrl, children: [] });
    }

    if (!r.subcategoria) continue;

    const sName = r.subcategoria;
    const sSlug = slugify(sName);
    const sUrl = `/collections/${sSlug}`;

    if (!seen.has(`sub:${sSlug}`)) {
      cfItems.push({ name: sName, slug: sSlug, url: sUrl, parent: cSlug });
      seen.add(`sub:${sSlug}`);
    }

    const catEntry = byCat.get(cSlug);
    let subRef = catEntry.children.find(x => x.slug === sSlug);
    if (!subRef) {
      subRef = { name: sName, slug: sSlug, url: sUrl, items: [] };
      catEntry.children.push(subRef);
    }

    if (!r.item) continue;

    const iName = r.item;
    const iSlug = slugify(iName);
    const iUrl = `/collections/${sSlug}?filter.p.tag=${iSlug}`;

    if (!seen.has(`item:${sSlug}:${iSlug}`)) {
      cfItems.push({ name: iName, slug: iSlug, url: iUrl, parent: sSlug });
      seen.add(`item:${sSlug}:${iSlug}`);
    }

    if (!subRef.items.find(it => it.slug === iSlug)) {
      subRef.items.push({ name: iName, slug: iSlug, url: iUrl });
    }
  }

  const catfinder = {
    rootAll: { slug: 'todas-as-categorias', name: 'Todas as Categorias', url: '/collections/all' },
    items: cfItems,
  };

  const vendor = { categories: Array.from(byCat.values()) };

  return { catfinder, vendor };
}

// start with safe empty cache if CSV missing
let CAT_CACHE = {
  catfinder: { rootAll: { slug: 'todas-as-categorias', name: 'Todas as Categorias', url: '/collections/all' }, items: [] },
  vendor: { categories: [] }
};
try { CAT_CACHE = buildCatfinderAndVendor(); }
catch { console.warn('CSV not found at startup; serving empty categories'); }

// rebuild every 60s
setInterval(() => {
  try { CAT_CACHE = buildCatfinderAndVendor(); }
  catch (e) { console.error('rebuild CSV failed', e); }
}, 60_000);

function setPublicCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
}

// public endpoints for Shopify
app.get('/catfinder.json', (req, res) => {
  try {
    setPublicCors(res);
    res.setHeader('Cache-Control', 'no-cache');
    res.json(CAT_CACHE.catfinder);
  } catch (e) {
    console.error('catfinder endpoint error', e);
    res.status(500).json({ error: 'catfinder_failed' });
  }
});

app.get('/vendor/categories.json', (req, res) => {
  try {
    setPublicCors(res);
    res.setHeader('Cache-Control', 'no-cache');
    res.json(CAT_CACHE.vendor);
  } catch (e) {
    console.error('vendor categories endpoint error', e);
    res.status(500).json({ error: 'vendor_categories_failed' });
  }
});

// receive ad from storefront
app.options('/vendor/listing', (_req, res) => {
  setPublicCors(res);
  res.sendStatus(204);
});

app.post('/vendor/listing', async (req, res) => {
  try {
    setPublicCors(res);

    const {
      category,
      subcategory,
      item,         // optional
      title,
      price,
      city,
      email,        // contact
      description
    } = req.body || {};

    if (!category || !subcategory || !title || !price || !email) {
      return res.status(400).json({ ok: false, error: 'missing_fields' });
    }

    // TODO: persist in DB or forward to Zoho here
    console.log('NEW LISTING', { category, subcategory, item, title, price, city, email, description });

    return res.json({ ok: true, message: 'listing_received' });
  } catch (e) {
    console.error('vendor/listing error:', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// health
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, () => {
  console.log(`CSH service running on :${PORT}`);
});
