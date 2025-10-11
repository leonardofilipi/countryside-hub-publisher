// index.js
// Countryside Hub Publisher — envio por Zoho Mail API (HTTPS, OAuth2)

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');

// =========================
// Configurações / Ambiente
// =========================
const {
  PORT = 3000,
  SITE_NAME = 'Countryside Hub',

  // Identidade do remetente
  ADMIN_EMAIL,

  // CORS (opcional)
  ALLOWED_ORIGIN,

  // Credenciais Zoho OAuth (US data center)
  ZOHO_CLIENT_ID,
  ZOHO_CLIENT_SECRET,
  ZOHO_REFRESH_TOKEN,
  ZOHO_ACCOUNT_ID,
} = process.env;

if (!ADMIN_EMAIL) {
  console.error('[ERRO] Defina ADMIN_EMAIL (ex.: adm@countrysidehub.com).');
  process.exit(1);
}
for (const v of ['ZOHO_CLIENT_ID','ZOHO_CLIENT_SECRET','ZOHO_REFRESH_TOKEN','ZOHO_ACCOUNT_ID']) {
  if (!process.env[v]) {
    console.error(`[ERRO] Variável ausente: ${v}. Configure o Zoho OAuth para usar a API HTTPS.`);
    process.exit(1);
  }
}

// ================
// App & Segurança
// ================
const app = express();

app.use(helmet({ crossOriginResourcePolicy: false }));

// CSP para permitir embed no Admin do Shopify
app.use((req, res, next) => {
  const csp = [
    'frame-ancestors',
    'https://admin.shopify.com',
    'https://*.myshopify.com'
  ].join(' ');
  res.setHeader('Content-Security-Policy', csp);
  res.removeHeader('X-Frame-Options');
  next();
});

// CORS
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // health checks e ferramentas
      if (!ALLOWED_ORIGIN) return cb(null, true);
      const ok = origin === ALLOWED_ORIGIN || origin === ALLOWED_ORIGIN.replace(/\/$/, '');
      cb(ok ? null : new Error('Origin not allowed by CORS'), ok);
    },
    credentials: false,
  })
);

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Anti-abuso
app.use(
  '/api/',
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Upload em memória
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
});

// ===================================
// Helpers — Sanitização e Formatação
// ===================================
const sanitize = (s = '') => String(s ?? '').toString().trim();
const money = (v) => {
  const n = Number(String(v).replace(/[^\d.,-]/g, '').replace(',', '.'));
  return Number.isFinite(n) ? n.toFixed(2) : '';
};

// ================================
// Zoho OAuth — Access Token cache
// ================================
let cachedToken = null;         // string
let cachedTokenExp = 0;         // epoch ms

async function getZohoAccessToken() {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExp - 30_000) {
    return cachedToken;
  }

  const url = 'https://accounts.zoho.com/oauth/v2/token';
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: ZOHO_REFRESH_TOKEN,
    client_id: ZOHO_CLIENT_ID,
    client_secret: ZOHO_CLIENT_SECRET,
  });

  const { data } = await axios.post(url, params, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 20_000,
  });

  if (!data.access_token) {
    throw new Error('Zoho: access_token não retornado.');
  }

  cachedToken = data.access_token;
  // Zoho retorna expires_in (segundos). Padrão ~3600s
  cachedTokenExp = Date.now() + (Number(data.expires_in || 3600) * 1000);
  return cachedToken;
}

// ==================================
// Zoho Mail API — Envio de mensagens
// ==================================
/**
 * Envia e-mail via Zoho Mail API.
 * @param {Object} opts
 *  - to: string (um ou mais separados por vírgula)
 *  - subject: string
 *  - html: string
 *  - attachments: [{ filename, buffer, contentType }]
 */
async function sendMailZoho({ to, subject, html, attachments = [] }) {
  const token = await getZohoAccessToken();

  // Endpoint para criar mensagem
  const url = `https://mail.zoho.com/api/accounts/${encodeURIComponent(ZOHO_ACCOUNT_ID)}/messages`;

  // Para enviar HTML e anexos, precisamos multipart/form-data.
  const fd = new FormData();
  fd.append('fromAddress', ADMIN_EMAIL);
  fd.append('toAddress', sanitize(to));
  fd.append('subject', sanitize(subject));
  fd.append('content', html);       // HTML
  fd.append('mailFormat', 'html');  // indicar HTML

  // anexos
  for (const f of attachments) {
    fd.append('attachments', f.buffer, {
      filename: f.filename,
      contentType: f.contentType || 'application/octet-stream'
    });
  }

  const { data } = await axios.post(url, fd, {
    headers: {
      Authorization: `Zoho-oauthtoken ${token}`,
      ...fd.getHeaders(),
    },
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    timeout: 30_000,
  });

  // data.status.code === 200 normalmente
  if (data?.status?.code !== 200) {
    throw new Error(`Zoho Mail API erro: ${JSON.stringify(data)}`);
  }

  return data;
}

// =====================
// Templates de e-mail
// =====================
function buildAdminHtml(payload, filesInfo) {
  const {
    nome_empresa, nome_completo, cpf_cnpj, email, telefone,
    cidade, estado, categoria, subcategoria, produto, preco,
    aceita_propostas, entrega, local, descricao, termos_aceitos, propostas,
  } = payload;

  const linhas = [
    `<p><b>Nome completo:</b> ${sanitize(nome_completo)}</p>`,
    `<p><b>Nome da empresa:</b> ${sanitize(nome_empresa || '(não informado)')}</p>`,
    `<p><b>CPF/CNPJ:</b> ${sanitize(cpf_cnpj)}</p>`,
    `<p><b>E-mail:</b> ${sanitize(email)}</p>`,
    `<p><b>Telefone:</b> ${sanitize(telefone)}</p>`,
    `<p><b>Cidade/UF:</b> ${sanitize(cidade)} / ${sanitize(estado)}</p>`,
    `<p><b>Categoria:</b> ${sanitize(categoria)}</p>`,
    `<p><b>Subcategoria:</b> ${sanitize(subcategoria || '(não informado)')}</p>`,
    `<p><b>Produto/Animal:</b> ${sanitize(produto || '(não informado)')}</p>`,
    `<p><b>Preço (R$):</b> ${money(preco)}</p>`,
    `<p><b>Aceita propostas:</b> ${sanitize(aceita_propostas || propostas || '(não informado)')}</p>`,
    `<p><b>Entrega/Coleta:</b> ${sanitize(entrega || '(não informado)')}</p>`,
    `<p><b>Local:</b> ${sanitize(local || '(não informado)')}</p>`,
    `<p><b>Descrição:</b><br>${(sanitize(descricao) || '(sem descrição)').replace(/\n/g, '<br>')}</p>`,
    `<p><b>Termos & Condições:</b> ${termos_aceitos ? 'Aceitos' : 'Não aceitos'}</p>`,
  ];

  if (filesInfo?.length) {
    linhas.push(
      `<p><b>Anexos:</b> ${filesInfo
        .map(f => `${f.originalname} (${(f.size / 1024).toFixed(1)} KB)`)
        .join(', ')}</p>`
    );
  }

  return `
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222">
      <h2>NOVO ANÚNCIO PUBLICADO (auto)</h2>
      ${linhas.join('\n')}
      <hr>
      <p style="font-size:12px;color:#666">
        E-mail gerado automaticamente pelo formulário do ${SITE_NAME}.
      </p>
    </div>`;
}

function buildWelcomeHtml(payload) {
  const { nome_completo, produto, preco } = payload;

  return `
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#222;line-height:1.5">
      <h2>Bem-vindo(a) ao ${SITE_NAME}!</h2>
      <p>Olá ${sanitize(nome_completo) || 'vendedor(a)'} 👋</p>
      <p>Seu anúncio <b>${sanitize(produto || 'seu produto')}</b> foi publicado com sucesso${preco ? ` por <b>R$ ${money(preco)}</b>` : ''}.</p>
      <ul>
        <li>Responda rápido os interessados;</li>
        <li>Negocie com transparência (preço, entrega/coleta, prazos);</li>
        <li>Mantenha seu anúncio atualizado para ter mais visibilidade.</li>
      </ul>
      <p>Bons negócios! 🚀</p>
      <p>Equipe ${SITE_NAME}</p>
    </div>`;
}

// =====================
// Rotas de saúde
// =====================
app.get('/', (_req, res) => res.status(200).send('OK'));
app.get('/healthz', (_req, res) => res.status(200).json({ status: 'ok', time: new Date().toISOString() }));

// =========================================
// Rota de publicação (suporta multipart)
// =========================================
const publishHandler = async (req, res) => {
  try {
    const payload = {
      nome_empresa: sanitize(req.body.nome_empresa),
      nome_completo: sanitize(req.body.nome_completo),
      cpf_cnpj: sanitize(req.body.cpf_cnpj),
      email: sanitize(req.body.email),
      telefone: sanitize(req.body.telefone),
      cidade: sanitize(req.body.cidade),
      estado: sanitize(req.body.estado),

      categoria: sanitize(req.body.categoria),
      subcategoria: sanitize(req.body.subcategoria),
      produto: sanitize(req.body.produto),
      preco: sanitize(req.body.preco),
      aceita_propostas: sanitize(req.body.aceita_propostas),
      propostas: sanitize(req.body.propostas),
      entrega: sanitize(req.body.entrega),
      local: sanitize(req.body.local),
      descricao: sanitize(req.body.descricao),
      termos_aceitos: String(req.body.termos_aceitos) === 'true' || req.body.termos_aceitos === 'on',
    };

    // Validação mínima
    const missing = [];
    if (!payload.email) missing.push('email');
    if (!payload.nome_completo) missing.push('nome_completo');
    if (!payload.cpf_cnpj) missing.push('cpf_cnpj');
    if (!payload.preco) missing.push('preco');
    if (!payload.entrega) missing.push('entrega');
    if (!payload.termos_aceitos) missing.push('termos_aceitos');
    if (missing.length) {
      return res.status(400).json({ ok: false, error: `Campos obrigatórios: ${missing.join(', ')}` });
    }

    // Anexos (para e-mail do admin)
    const attachments = (req.files || []).map(f => ({
      filename: f.originalname,
      buffer: f.buffer,
      contentType: f.mimetype,
    }));

    // 1) e-mail administrador (fiscalização)
    await sendMailZoho({
      to: ADMIN_EMAIL,
      subject: `Novo anúncio publicado - ${sanitize(payload.produto || 'Produto')}`,
      html: buildAdminHtml(payload, req.files),
      attachments,
    });

    // 2) e-mail de boas-vindas ao vendedor
    await sendMailZoho({
      to: payload.email,
      subject: `Bem-vindo(a) ao ${SITE_NAME}! Seu anúncio está no ar`,
      html: buildWelcomeHtml(payload),
    });

    return res.status(200).json({ ok: true, message: 'Anúncio publicado e e-mails enviados via Zoho API.' });
  } catch (err) {
    console.error('[ERRO /publish]', err?.message || err, err?.response?.data);
    return res.status(500).json({
      ok: false,
      error: 'Falha interna ao processar/enviar e-mails. Tente novamente.',
    });
  }
};

app.post('/publish', upload.array('docs[]', 5), publishHandler);
app.post('/api/publish', upload.array('docs[]', 5), publishHandler);

// =====================
// 404 handler
// =====================
app.use((_req, res) => res.status(404).json({ ok: false, error: 'Rota não encontrada.' }));

// =====================
// Start
// =====================
app.listen(PORT, () => {
  console.log(`[OK] ${SITE_NAME} publisher on port ${PORT} (Zoho API HTTPS)`);
});
