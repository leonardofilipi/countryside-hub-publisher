// index.js
// Servidor de publicação do Countryside Hub (Node + Express)
// Envia e-mail para o administrador (fiscalização) e boas-vindas ao vendedor
// SMTP: Zoho (SSL 465)

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const multer = require('multer');

// =========================
// Configurações / Ambiente
// =========================
const {
  PORT = 3000,
  SITE_NAME = 'Countryside Hub',
  // E-mail do remetente (Zoho) e App Password do Zoho
  ADMIN_EMAIL,
  ADMIN_EMAIL_PASSWORD,
  // Para onde receber a cópia (pode ser o mesmo do ADMIN_EMAIL)
  REVIEW_EMAIL,
  // (opcional) origem permitida no CORS. Ex.: https://countrysidehub.com
  ALLOWED_ORIGIN,
  // (opcional) SMTP avançado (só mude se souber o que está fazendo)
  ZOHO_SMTP_HOST = 'smtppro.zoho.com',
  ZOHO_SMTP_PORT = '465',
  ZOHO_SMTP_SECURE = 'true', // SSL
} = process.env;

if (!ADMIN_EMAIL || !ADMIN_EMAIL_PASSWORD) {
  console.error(
    '[ERRO] Defina as variáveis ADMIN_EMAIL e ADMIN_EMAIL_PASSWORD (App Password do Zoho).'
  );
  process.exit(1);
}

// ================
// App & Segurança
// ================
const app = express();

// Segurança básica de headers
app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

// CORS (permite seu domínio do Shopify/site)
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // permite ferramentas internas e health checks
      if (!ALLOWED_ORIGIN) return cb(null, true); // sem restrição definida
      const ok =
        origin === ALLOWED_ORIGIN ||
        origin === ALLOWED_ORIGIN.replace(/\/$/, '');
      cb(ok ? null : new Error('Origin not allowed by CORS'), ok);
    },
    credentials: false,
  })
);

// Aceita JSON (para submits sem arquivo)
app.use(express.json({ limit: '2mb' }));
// Aceita forms application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Limite de requisições (anti-abuso)
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
// Usamos memória (não escreve em disco do Render)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB por arquivo
    files: 5, // até 5 documentos
  },
});

// =====================
// Nodemailer (Zoho)
// =====================
const transporter = nodemailer.createTransport({
  host: "smtppro.zoho.com",
  port: 465,
  secure: true,                         // SSL direto
  auth: {
    user: process.env.ADMIN_EMAIL,      // adm@countrysidehub.com
    pass: process.env.ADMIN_EMAIL_PASSWORD
  },
  pool: true,
  connectionTimeout: 20000,             // 20s
  socketTimeout: 20000,
  tls: {
    minVersion: "TLSv1.2",
    rejectUnauthorized: true
  }
});


// Tenta validar a conexão SMTP na subida
transporter
  .verify()
  .then(() => console.log('[OK] SMTP Zoho verificado com sucesso.'))
  .catch((err) => {
    console.error('[ERRO] Falha ao verificar SMTP Zoho:', err?.message || err);
  });

// =====================
// Utilidades
// =====================
function sanitize(str = '') {
  return String(str).trim();
}

function money(v) {
  const n = Number(String(v).replace(/[^\d.,-]/g, '').replace(',', '.'));
  if (Number.isFinite(n)) return n.toFixed(2);
  return '';
}

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
    `<p><b>Local para retirada/entrega:</b> ${sanitize(local || '(não informado)')}</p>`,
    `<p><b>Descrição detalhada:</b><br>${(sanitize(descricao) || '(sem descrição)').replace(/\n/g, '<br>')}</p>`,
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
        Este e-mail foi gerado automaticamente pelo formulário de cadastro de anúncio do ${SITE_NAME}.
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
      <p>Seu anúncio <b>${sanitize(produto || 'seu produto')}</b> foi publicado com sucesso${preco ? ` por <b>R$ ${money(preco)}</b>` : ''}.</p>
      <p>Nossa plataforma foi criada para dar <b>visibilidade</b> e <b>segurança</b> aos negócios do agro e pecuária. 
      Mantenha seu anúncio completo e atualizado — isso aumenta muito suas chances de venda.</p>
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
// Rotas de saúde/ok
// =====================
app.get('/', (_req, res) => {
  res.status(200).send('OK');
});

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok', time: new Date().toISOString() });
});

// =====================================================
// Rotas de publicação (suporta multipart com documentos)
// =====================================================
const handler = async (req, res) => {
  try {
    // Fields podem vir de JSON ou multipart (multer popula req.body)
    const payload = {
      // Identidade / contato
      nome_empresa: sanitize(req.body.nome_empresa),
      nome_completo: sanitize(req.body.nome_completo),
      cpf_cnpj: sanitize(req.body.cpf_cnpj),
      email: sanitize(req.body.email),
      telefone: sanitize(req.body.telefone),
      cidade: sanitize(req.body.cidade),
      estado: sanitize(req.body.estado),
      // Anúncio
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

    // Validações essenciais
    const missing = [];
    if (!payload.email) missing.push('email');
    if (!payload.nome_completo) missing.push('nome_completo');
    if (!payload.cpf_cnpj) missing.push('cpf_cnpj');
    if (!payload.preco) missing.push('preco');
    if (!payload.entrega) missing.push('entrega');
    if (!payload.termos_aceitos) missing.push('termos_aceitos');

    if (missing.length) {
      return res.status(400).json({
        ok: false,
        error: `Campos obrigatórios ausentes: ${missing.join(', ')}`,
      });
    }

    // Monta anexos (se houver)
    const files = (req.files || []).map((f) => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype,
    }));

    // ========= Envia e-mail para o ADMIN/REVIEW (fiscalização)
    const adminTo = sanitize(REVIEW_EMAIL || ADMIN_EMAIL);
    const adminHtml = buildAdminHtml(payload, req.files);

    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: adminTo,
      subject: `Novo anúncio publicado - ${sanitize(payload.produto || 'Produto')}`,
      html: adminHtml,
      attachments: files,
    });

    // ========= Envia e-mail de boas-vindas para o vendedor
    const welcomeHtml = buildWelcomeHtml(payload);

    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: payload.email,
      subject: `Bem-vindo(a) ao ${SITE_NAME}! Seu anúncio está no ar`,
      html: welcomeHtml,
    });

    // Sucesso
    return res.status(200).json({
      ok: true,
      message: 'Anúncio publicado e e-mails enviados.',
    });
  } catch (err) {
    console.error('[ERRO /publish]', err?.message || err, err?.stack);
    return res.status(500).json({
      ok: false,
      error: 'Falha interna ao processar o anúncio. Tente novamente.',
    });
  }
};

// Ambas as rotas aceitam multipart (docs[] como campo de arquivo)
app.post('/publish', upload.array('docs[]', 5), handler);
app.post('/api/publish', upload.array('docs[]', 5), handler);

// ===================================
// Tratamento global de rota inexistente
// ===================================
app.use((_req, res) => {
  res.status(404).json({ ok: false, error: 'Rota não encontrada.' });
});

// =====================
// Sobe o servidor
// =====================
app.listen(PORT, () => {
  console.log(`[OK] ${SITE_NAME} publisher rodando na porta ${PORT}`);
});
// --- Permitir embed no Admin do Shopify ---
app.use((req, res, next) => {
  // Qualquer domínio do admin do Shopify + sua loja (subdomínio myshopify)
  const csp = [
    "frame-ancestors",
    "https://admin.shopify.com",
    "https://*.myshopify.com"
  ].join(" ");

  res.setHeader("Content-Security-Policy", csp);
  // NÃO envie X-Frame-Options: DENY. Se algo enviar, sobrescreva:
  res.removeHeader("X-Frame-Options");
  next();
});
app.get("/", (_req, res) => {
  res.status(200).send(`
    <!doctype html>
    <html lang="pt-br">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Countryside Hub Publisher</title>
        <style>
          body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu, sans-serif;
               margin:0;padding:32px;background:#f6f7f8;color:#0d1b0f}
          .card{max-width:760px;margin:0 auto;background:#fff;border:1px solid #e6e8eb;border-radius:16px;padding:28px;
                box-shadow:0 6px 24px rgba(0,0,0,.06)}
          h1{margin:0 0 8px}
          p{margin:8px 0 0;line-height:1.5}
          a.button{display:inline-block;margin-top:16px;padding:10px 16px;border-radius:10px;border:1px solid #d4dfd6;text-decoration:none}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>🎉 App instalado</h1>
          <p>Seu app “Countryside Hub Publisher” está rodando. <br/>
             Use os endpoints já criados (ex.: <code>/health</code> e <code>/submit</code>) e as páginas do tema para o fluxo de cadastro/anúncio.</p>
          <a class="button" href="/health" target="_blank">Ver /health</a>
        </div>
      </body>
    </html>
  `);
});

