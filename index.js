// index.js
// Countryside Hub Publisher - Node + Express
// SMTP: Zoho (US Datacenter) - STARTTLS (porta 587)

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const multer = require('multer');
const net = require('net');

// =========================
// Configurações / Ambiente
// =========================
const {
  PORT = 3000,
  SITE_NAME = 'Countryside Hub',

  // Zoho - remetente e App Password (obrigatórios)
  ADMIN_EMAIL,
  ADMIN_EMAIL_PASSWORD,

  // Opcional: cópia de fiscalização (se vazio, cai no ADMIN_EMAIL)
  REVIEW_EMAIL,

  // CORS: defina seu domínio, ex.: https://countrysidehub.com
  ALLOWED_ORIGIN,

  // SMTP avançado (com defaults para Zoho US/STARTTLS):
  ZOHO_SMTP_HOST = 'smtp.zoho.com',
  ZOHO_SMTP_PORT = '587',
  ZOHO_SMTP_SECURE = 'false', // false = STARTTLS (porta 587); true = SSL direto (porta 465)
} = process.env;

if (!ADMIN_EMAIL || !ADMIN_EMAIL_PASSWORD) {
  console.error('[ERRO] Defina ADMIN_EMAIL e ADMIN_EMAIL_PASSWORD (Zoho App Password).');
  process.exit(1);
}

const SMTP_HOST = String(ZOHO_SMTP_HOST).trim();
const SMTP_PORT = parseInt(String(ZOHO_SMTP_PORT).trim(), 10) || 587;
const SMTP_SECURE = String(ZOHO_SMTP_SECURE).toLowerCase() === 'true'; // false para STARTTLS

// ================
// App & Segurança
// ================
const app = express();

// Segurança de headers (sem bloquear frames para admin Shopify)
app.use(
  helmet({
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: false, // vamos setar CSP manualmente abaixo
  })
);

// CSP permitindo embed no Admin do Shopify
app.use((req, res, next) => {
  const csp = [
    'frame-ancestors',
    'https://admin.shopify.com',
    'https://*.myshopify.com',
  ].join(' ');
  res.setHeader('Content-Security-Policy', csp);
  res.removeHeader('X-Frame-Options');
  next();
});

// CORS
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // health checks / curl
      if (!ALLOWED_ORIGIN) return cb(null, true); // sem restrição
      const ok = origin === ALLOWED_ORIGIN || origin === ALLOWED_ORIGIN.replace(/\/$/, '');
      cb(ok ? null : new Error('Origin not allowed by CORS'), ok);
    },
    credentials: false,
  })
);

// Body parsers
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Rate limit básico
app.use(
  '/api/',
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// =====================
// Upload (anexos)
// =====================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
});

// =====================
// Nodemailer (Zoho)
// =====================
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE, // false -> STARTTLS; true -> SSL direto
  auth: { user: ADMIN_EMAIL, pass: ADMIN_EMAIL_PASSWORD },
  pool: true,
  connectionTimeout: 20000,
  socketTimeout: 20000,
  tls: {
    minVersion: 'TLSv1.2',
    // Para Zoho US + Render normalmente não precisa mexer nisso:
    rejectUnauthorized: true,
  },
});

// Teste inicial de conexão SMTP (assíncrono, não derruba o app)
transporter
  .verify()
  .then(() => console.log('[OK] SMTP verificado:', SMTP_HOST, 'porta', SMTP_PORT, 'secure:', SMTP_SECURE))
  .catch((err) => console.error('[ERRO] Falha ao verificar SMTP Zoho:', err?.message || err));

// =====================
// Utilidades
// =====================
const sanitize = (s = '') => String(s).trim();
const money = (v) => {
  const n = Number(String(v).replace(/[^\d.,-]/g, '').replace(',', '.'));
  return Number.isFinite(n) ? n.toFixed(2) : '';
};

function buildAdminHtml(payload, filesInfo) {
  const {
    nome_empresa,
    nome_completo,
    cpf_cnpj,
    email,
    telefone,
    cidade,
    estado,
    categoria,
    subcategoria,
    produto,
    preco,
    aceita_propostas,
    entrega,
    local,
    descricao,
    termos_aceitos,
    propostas,
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
        .map((f) => `${f.originalname} (${(f.size / 1024).toFixed(1)} KB)`)
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
    </div>
  `;
}

function buildWelcomeHtml(payload) {
  const { nome_completo, produto, preco } = payload;
  return `
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#222;line-height:1.5">
      <h2>Bem-vindo(a) ao ${SITE_NAME}!</h2>
      <p>Olá ${sanitize(nome_completo) || 'vendedor(a)'} 👋</p>
      <p>Seu anúncio <b>${sanitize(produto || 'seu produto')}</b> foi publicado com sucesso${
        preco ? ` por <b>R$ ${money(preco)}</b>` : ''
      }.</p>
      <ul>
        <li>Responda rápido os interessados;</li>
        <li>Negocie com transparência (preço, entrega/coleta, prazos);</li>
        <li>Evite pagamentos fora dos canais combinados com o comprador.</li>
      </ul>
      <p>Estamos juntos para te ajudar a vender mais e melhor. Bons negócios! 🚀</p>
      <p>Equipe ${SITE_NAME}</p>
    </div>
  `;
}

// =====================
// Rotas básicas
// =====================
app.get('/', (_req, res) => {
  res.status(200).send('OK');
});

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok', time: new Date().toISOString() });
});

// Diagnóstico SMTP (usa transporter.verify na hora)
app.get('/smtp-check', async (_req, res) => {
  try {
    await transporter.verify();
    res.status(200).send('SMTP OK');
  } catch (err) {
    res
      .status(500)
      .send(`SMTP FAIL: ${err?.code || ''} ${err?.message || String(err)}`);
  }
});

// Diagnóstico TCP (verifica rota/porta de saída da Render)
app.get('/tcp-check', (req, res) => {
  const host = req.query.host || SMTP_HOST;
  const port = parseInt(req.query.port || SMTP_PORT, 10);

  const started = Date.now();
  const socket = net.createConnection({ host, port, timeout: 8000 }, () => {
    const ms = Date.now() - started;
    socket.end();
    res.status(200).send(`TCP OK: ${host}:${port} em ${ms}ms`);
  });
  socket.on('timeout', () => {
    socket.destroy();
    res.status(504).send('TCP TIMEOUT');
  });
  socket.on('error', (e) => {
    res.status(500).send(`TCP ERROR: ${e.code || ''} ${e.message}`);
  });
});

// =====================================================
// Rota de publicação (aceita multipart com documentos)
// =====================================================
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

    const files = (req.files || []).map((f) => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype,
    }));

    // Envia para fiscalização
    const adminTo = sanitize(REVIEW_EMAIL || ADMIN_EMAIL);
    const adminHtml = buildAdminHtml(payload, req.files);

    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: adminTo,
      subject: `Novo anúncio publicado - ${sanitize(payload.produto || 'Produto')}`,
      html: adminHtml,
      attachments: files,
    });

    // Boas-vindas
    const welcomeHtml = buildWelcomeHtml(payload);
    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: payload.email,
      subject: `Bem-vindo(a) ao ${SITE_NAME}! Seu anúncio está no ar`,
      html: welcomeHtml,
    });

    res.status(200).json({ ok: true, message: 'Anúncio publicado e e-mails enviados.' });
  } catch (err) {
    console.error('[ERRO /publish]', err?.message || err, err?.stack);
    res.status(500).json({ ok: false, error: 'Falha interna ao processar o anúncio.' });
  }
};

app.post('/publish', upload.array('docs[]', 5), publishHandler);
app.post('/api/publish', upload.array('docs[]', 5), publishHandler);

// 404
app.use((_req, res) => {
  res.status(404).json({ ok: false, error: 'Rota não encontrada.' });
});

// =====================
// Sobe o servidor
// =====================
app.listen(PORT, () => {
  console.log(`[OK] ${SITE_NAME} publisher rodando na porta ${PORT}`);
  console.log(`[SMTP] host=${SMTP_HOST} port=${SMTP_PORT} secure=${SMTP_SECURE}`);
});
